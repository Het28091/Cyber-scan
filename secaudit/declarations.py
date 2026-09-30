"""Bounded declaration checks; no reference resolution or application execution."""
from .models import Finding


def inspect_document(name,document,modules):
    findings=[];inventory=[];events=[]
    if not isinstance(document,dict):return findings,inventory,events

    def add(rule,title,pointer,description,remediation,severity='MEDIUM'):
        findings.append(Finding(rule,title,name,description+' Declaration: '+pointer,
            remediation,severity=severity,confidence='MEDIUM',
            evidence=[name+' JSON pointer '+pointer+'; values omitted'],
            reproduction='Inspect the referenced JSON pointer and verify the deployed policy.',
            retest='Update the declaration, repeat the assessment and verify the deployed behavior.'))

    def segment(value):return str(value).replace('~','~0').replace('/','~1')

    if 'openapi' in modules and 'openapi' in document:
        events.append('OpenAPI declaration checks are partial: JSON only, no reference resolution, schema validation or runtime authorization verification: '+name)
        components=document.get('components',{})
        schemes=components.get('securitySchemes',{}) if isinstance(components,dict) else {}
        schemes=schemes if isinstance(schemes,dict) else {}
        paths=document.get('paths',{})
        if not isinstance(paths,dict):
            events.append('OpenAPI paths could not be inspected: '+name)
            paths={}
        servers=[('/servers',document.get('servers',[]))]
        external_refs=False
        # References are deliberately not fetched or read from neighboring files.
        stack=[document];visited=0
        while stack and visited<20000:
            value=stack.pop();visited+=1
            if isinstance(value,dict):
                if '$ref' in value:external_refs=True
                stack.extend(v for v in value.values() if isinstance(v,(dict,list)))
            elif isinstance(value,list):stack.extend(v for v in value if isinstance(v,(dict,list)))
        if external_refs:events.append('OpenAPI references are not resolved; referenced declarations remain uninspected: '+name)
        if stack:events.append('OpenAPI reference inventory reached its 20000-node limit: '+name)
        for path,methods in paths.items():
            if not isinstance(methods,dict):continue
            pointer='/paths/'+segment(path)
            servers.append((pointer+'/servers',methods.get('servers',[])))
            for method,operation in methods.items():
                if method not in ('get','post','put','delete','patch','head','options','trace') or not isinstance(operation,dict):continue
                location=pointer+'/'+method
                inventory.append({'asset':str(path),'method':method,'type':'declared-api'})
                if '$ref' in operation:continue
                security=operation.get('security',document.get('security'))
                if security is None or security==[] or isinstance(security,list) and any(item=={} for item in security):
                    add('API-SECURITY','API operation permits anonymous access in its declaration',location+'/security',
                        'The operation has no security requirement or includes an anonymous alternative. Public endpoints may be intentional.',
                        'Verify the intended access policy; declare and enforce required authentication where appropriate.')
                elif not isinstance(security,list) or any(not isinstance(item,dict) for item in security):
                    events.append('OpenAPI security declaration has an unsupported shape: '+name+' '+location)
                else:
                    missing=any(key not in schemes for item in security for key in item)
                    if missing:add('API-SECURITY-REFERENCE','API operation references an undeclared security scheme',location+'/security',
                        'At least one referenced security scheme is absent from the local components object. References are not resolved.',
                        'Define the required security scheme and verify runtime enforcement; reconcile unresolved references.')
                servers.append((location+'/servers',operation.get('servers',[])))
        for pointer,values in servers:
            if not isinstance(values,list):continue
            for index,server in enumerate(values):
                if isinstance(server,dict) and isinstance(server.get('url'),str) and server['url'].lower().startswith('http://'):
                    add('API-CLEARTEXT-SERVER','API server declares cleartext HTTP',pointer+'/'+str(index)+'/url',
                        'An explicit server URL uses HTTP. Local development endpoints may be intentional; deployed transport is not verified.',
                        'Use HTTPS for deployed endpoints carrying sensitive information and document local-only exceptions.')
        for key,scheme in schemes.items():
            if not isinstance(scheme,dict) or '$ref' in scheme:continue
            pointer='/components/securitySchemes/'+segment(key)
            if scheme.get('type')=='apiKey' and scheme.get('in')=='query':
                add('API-QUERY-CREDENTIAL','API key is declared in a query parameter',pointer,
                    'URL query credentials can enter request logs and copied URLs. No credential value was inspected.',
                    'Use an appropriate authorization header and prevent sensitive values from entering logs.')
            flows=scheme.get('flows',{})
            if scheme.get('type')=='oauth2' and isinstance(flows,dict):
                for flow in ('implicit','password'):
                    if flow in flows:add('API-OAUTH-FLOW','OAuth flow requires security review',pointer+'/flows/'+flow,
                        'The declaration includes an implicit or password grant flow. Actual provider behavior and client constraints are unknown.',
                        'Review migration to an authorization-code flow with PKCE and the provider’s supported client policy.')

    if 'config' in modules:
        objects=document.get('items',[]) if document.get('kind')=='List' else [document]
        if not isinstance(objects,list):objects=[]
        for index,obj in enumerate(objects[:1000]):
            if not isinstance(obj,dict) or not isinstance(obj.get('apiVersion'),str):continue
            kind=obj.get('kind');prefix='/items/'+str(index) if document.get('kind')=='List' else ''
            if kind=='Pod':parts=['spec']
            elif kind in ('Deployment','DaemonSet','StatefulSet','ReplicaSet','Job','ReplicationController'):parts=['spec','template','spec']
            elif kind=='CronJob':parts=['spec','jobTemplate','spec','template','spec']
            else:continue
            pod=obj
            for part in parts:pod=pod.get(part,{}) if isinstance(pod,dict) else {}
            if not isinstance(pod,dict):continue
            pointer=prefix+'/'+('/'.join(parts))
            inventory.append({'asset':name,'type':'declared-kubernetes-workload','kind':kind,'pointer':pointer})
            if not any(e.startswith('Kubernetes declaration checks are partial:') for e in events):
                events.append('Kubernetes declaration checks are partial: explicit JSON settings only; no image, admission, cluster, Helm or YAML evaluation: '+name)
            for field in ('hostNetwork','hostPID','hostIPC'):
                if pod.get(field) is True:add('K8S-HOST-NAMESPACE','Workload shares a host namespace',pointer+'/'+field,
                    'The workload explicitly enables a host namespace, reducing isolation.',
                    'Disable host namespace sharing unless it is necessary and explicitly reviewed.','HIGH')
            if pod.get('automountServiceAccountToken') is True:
                add('K8S-TOKEN-MOUNT','Workload explicitly mounts service-account credentials',pointer+'/automountServiceAccountToken',
                    'Automatic service-account token mounting is explicitly enabled. Required permissions and token use are unknown.',
                    'Disable automatic token mounting for workloads that do not call the Kubernetes API and minimize service-account permissions.')
            volumes=pod.get('volumes',[])
            if isinstance(volumes,list):
                for i,volume in enumerate(volumes):
                    if isinstance(volume,dict) and isinstance(volume.get('hostPath'),dict):
                        add('K8S-HOST-PATH','Workload declares a host filesystem volume',pointer+'/volumes/'+str(i)+'/hostPath',
                            'A hostPath volume exposes part of the node filesystem. Mount permissions and admission policy are not evaluated.',
                            'Prefer managed storage; narrowly constrain and review unavoidable host mounts.','HIGH')
            pod_context=pod.get('securityContext',{})
            if not isinstance(pod_context,dict):pod_context={}
            for group in ('containers','initContainers','ephemeralContainers'):
                containers=pod.get(group,[])
                if not isinstance(containers,list):continue
                for i,container in enumerate(containers):
                    if not isinstance(container,dict):continue
                    context=container.get('securityContext',{})
                    if not isinstance(context,dict):continue
                    location=pointer+'/'+group+'/'+str(i)+'/securityContext'
                    for field,rule,title in [('privileged','K8S-PRIVILEGED','Container explicitly enables privileged mode'),('allowPrivilegeEscalation','K8S-ESCALATION','Container permits privilege escalation')]:
                        if context.get(field) is True:add(rule,title,location+'/'+field,
                            'The container explicitly enables this security-sensitive setting. Runtime admission controls are unknown.',
                            'Disable the setting and use only the permissions required by the workload.','HIGH')
                    user=context.get('runAsUser',pod_context.get('runAsUser'))
                    if type(user) is int and user==0:add('K8S-ROOT','Container explicitly selects the root user',location+'/runAsUser' if 'runAsUser' in context else pointer+'/securityContext/runAsUser',
                        'The effective declared user ID is zero. Image defaults and runtime overrides are not evaluated.',
                        'Select a non-root user and enable runAsNonRoot after confirming application compatibility.')
                    capabilities=context.get('capabilities',{})
                    additions=capabilities.get('add',[]) if isinstance(capabilities,dict) else []
                    if isinstance(additions,list) and any(c in ('ALL','SYS_ADMIN','SYS_PTRACE','NET_ADMIN') for c in additions):
                        add('K8S-CAPABILITIES','Container adds broad Linux capabilities',location+'/capabilities/add',
                            'The declaration adds at least one broad administration or tracing capability.',
                            'Drop unnecessary capabilities and explicitly justify each retained capability.','HIGH')
        if len(objects)>1000:events.append('Kubernetes List inspection limited to 1000 objects: '+name)
    return findings,inventory,events
