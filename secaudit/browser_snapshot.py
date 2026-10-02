"""Offline CDP-pipe snapshot helper, run only inside both resource/OS boundaries.

Disable page scripts before navigation; retrieve DOM through CDP, not JavaScript.
Chrome's --dump-dom depends on script execution on some builds, so it is unsuitable
for this contract. No listening debugging port or third-party Python library.
"""
import json
import os
import select
import subprocess
import sys
import time


def snapshot(executable):
    send_read,send_write=os.pipe();receive_read,receive_write=os.pipe()
    def pipes():
        os.dup2(send_read,3);os.dup2(receive_write,4)
    args=[executable,'--headless','--disable-gpu','--disable-background-networking',
        '--disable-extensions','--no-first-run','--no-startup-window',
        '--user-data-dir=/tmp/profile','--remote-debugging-pipe']
    process=subprocess.Popen(args,pass_fds=tuple(sorted({3,4,send_read,receive_write})),
        preexec_fn=pipes,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    os.close(send_read);os.close(receive_write)
    buffer=b'';ident=0;deadline=time.monotonic()+120
    def message():
        nonlocal buffer
        while b'\0' not in buffer:
            remaining=deadline-time.monotonic()
            if remaining<=0 or not select.select([receive_read],[],[],remaining)[0]:raise ValueError('browser protocol timed out')
            data=os.read(receive_read,65536)
            if not data:raise ValueError('browser protocol closed')
            buffer+=data
            if len(buffer)>1_000_000:raise ValueError('browser protocol size limit')
        raw,buffer=buffer.split(b'\0',1)
        return json.loads(raw)
    def call(method,params=None,session=None):
        nonlocal ident
        ident+=1;request={'id':ident,'method':method,'params':params or {}}
        if session:request['sessionId']=session
        data=json.dumps(request).encode()+b'\0'
        while data:data=data[os.write(send_write,data):]
        while True:
            response=message()
            if response.get('id')!=ident:continue
            if 'error' in response:raise ValueError('browser protocol command rejected')
            return response['result']
    try:
        target=call('Target.createTarget',{'url':'about:blank'})['targetId']
        session=call('Target.attachToTarget',{'targetId':target,'flatten':True})['sessionId']
        call('Page.enable',session=session)
        call('Emulation.setScriptExecutionDisabled',{'value':True},session)
        result=call('Page.navigate',{'url':'file:///input/page.html'},session)
        if result.get('errorText'):raise ValueError('snapshot navigation failed')
        # DOM.getDocument after the load event avoids reporting the initial blank page.
        while True:
            event=message()
            if event.get('sessionId')==session and event.get('method')=='Page.loadEventFired':break
        node=call('DOM.getDocument',{'depth':0},session)['root']['nodeId']
        html=call('DOM.getOuterHTML',{'nodeId':node},session)['outerHTML']
        if len(html.encode())>1_000_000:raise ValueError('snapshot size limit')
        return html
    finally:
        os.close(send_write);os.close(receive_read)
        process.terminate()
        try:process.wait(timeout=2)
        except subprocess.TimeoutExpired:process.kill();process.wait()


if __name__=='__main__':
    try:print(snapshot(sys.argv[1]))
    except (ValueError,OSError,KeyError,IndexError):
        print('Offline browser snapshot unavailable.',file=sys.stderr);raise SystemExit(2)
