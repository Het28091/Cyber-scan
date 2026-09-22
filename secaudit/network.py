"""No ambient proxies, automatic redirects, cookies, or credential forwarding."""
import http.client, socket, ssl, time
from urllib.parse import urlsplit,urljoin
from html.parser import HTMLParser
from .security import canonical,PolicyError
from .models import Finding

class PinnedHTTP(http.client.HTTPConnection):
    def __init__(self,host,port,ip,timeout,secure=False):
        super().__init__(host,port,timeout=timeout);self.ip=ip;self.secure=secure
    def connect(self):
        family=socket.AF_INET6 if ':' in self.ip else socket.AF_INET
        sock=socket.socket(family,socket.SOCK_STREAM);sock.settimeout(self.timeout)
        try:
            sock.connect((self.ip,self.port))
            if self.secure: sock=ssl.create_default_context().wrap_socket(sock,server_hostname=self.host)
            self.sock=sock
        except BaseException:
            sock.close();raise

def request(url,scope,method='GET',body=None,headers=None,timeout=5,max_bytes=1_000_000):
    ip=scope.check(url)
    _,_,host,port=canonical(url)
    u=urlsplit(url)
    conn=PinnedHTTP(host,port,ip,timeout,u.scheme=='https')
    try:
        conn.request(method,(u.path or '/')+('?' +u.query if u.query else ''),body=body,headers=headers or {'User-Agent':'Secaudit/0.1 authorized-assessment'})
        response=conn.getresponse(); payload=response.read(max_bytes+1)
        if len(payload)>max_bytes: raise PolicyError('response exceeds size limit')
        return response.status,response.getheaders(),payload
    finally: conn.close()

class Links(HTMLParser):
    def __init__(self): super().__init__();self.urls=[]
    def handle_starttag(self,tag,attrs):
        if tag=='a': self.urls.extend(v for k,v in attrs if k=='href' and v)

def scan_web(url,scope,checkpoint):
    start=time.monotonic();queue=[url];seen=set();inventory=[];findings=[];events=[]
    while queue and len(seen)<scope.data['max_requests']:
        remaining=scope.data['max_seconds']-(time.monotonic()-start)
        if remaining<=0: events.append('Time budget reached');break
        current=queue.pop(0)
        if current in seen: continue
        seen.add(current)
        try:
            status,hs,body=request(current,scope,timeout=min(5,remaining))
        except (OSError,ValueError,http.client.HTTPException) as e:
            events.append(f'{type(e).__name__}: request blocked or failed')
            continue
        # Paths are evidence metadata, not full captures or query values.
        u=urlsplit(current); asset=u.scheme+'://'+u.netloc+u.path
        inventory.append({'asset':asset,'status':status})
        if status>=500: events.append('Stopped after server error (possible instability)');break
        hd={k.lower():v for k,v in hs}
        if status in (301,302,303,307,308) and 'location' in hd:
            nxt=urljoin(current,hd['location'])
            try: scope.check(nxt);queue.append(nxt)
            except (ValueError,OSError): events.append('Out-of-scope redirect blocked')
            continue
        for header,why in [('content-security-policy','Define a restrictive Content-Security-Policy.'),('x-content-type-options','Set X-Content-Type-Options: nosniff.')]:
            if header not in hd:
                findings.append(Finding('HTTP-'+header,'Missing '+header,asset,'Header absent on this response.',why,severity='LOW',confidence='HIGH',evidence=['Observed header names: '+', '.join(sorted(hd))]))
        if u.scheme=='https' and 'strict-transport-security' not in hd:
            findings.append(Finding('HTTP-HSTS','Missing HSTS',asset,'HTTPS response lacks HSTS.','Review deployment and enable HSTS.',severity='LOW',confidence='HIGH',evidence=['HSTS header absent']))
        for k,v in hs:
            if k.lower()=='set-cookie':
                attrs={x.strip().split('=')[0].lower() for x in v.split(';')[1:]}
                missing={'secure','httponly','samesite'}-attrs
                if missing: findings.append(Finding('COOKIE-FLAGS','Cookie flags need review',asset,'Cookie lacks '+', '.join(sorted(missing)), 'Set flags appropriate for the cookie purpose.',confidence='HIGH',evidence=['Cookie values omitted; missing flags: '+', '.join(sorted(missing))]))
        checkpoint(findings,inventory)
        if 'text/html' in hd.get('content-type',''):
            parser=Links();parser.feed(body.decode('utf-8','replace'))
            for link in parser.urls[:100]:
                nxt=urljoin(current,link)
                # Avoid arbitrary query workflows; never submit forms or execute scripts.
                if urlsplit(nxt).query or urlsplit(nxt).fragment: continue
                try: scope.check(nxt)
                except (ValueError,OSError): continue
                if nxt not in seen and len(queue)<100: queue.append(nxt)
        time.sleep(0.1)
    if queue: events.append('Crawl incomplete: request or time budget')
    return findings,inventory,events
