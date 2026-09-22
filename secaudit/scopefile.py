"""Explicit scope preparation: DNS lookup only; never implies ownership verification."""
import ipaddress,json,os,socket
from pathlib import Path
from urllib.parse import urlsplit
from .security import Scope,canonical,PolicyError

def create(origin,authorization,exclusions,output):
    _,_,host,port=canonical(origin)
    if urlsplit(origin).query:raise PolicyError('scope origin cannot include a query')
    ips=sorted({str(ipaddress.ip_address(r[4][0])) for r in socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)})
    data={'authorization':authorization,'origins':[origin],'exclusions':exclusions,'environment':'operator-authorized','profiles':['passive'],'max_requests':10,'max_seconds':30,'allowed_ips':ips}
    Scope(data)
    # No overwrite of an existing authorization record, including symlinks.
    with Path(output).open('x',encoding='utf-8') as f:
        os.chmod(output,0o600);json.dump(data,f,indent=2);f.write('\n')
    return data
