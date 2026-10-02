from pathlib import Path
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform=='linux','real pipe descriptors require POSIX')
class SnapshotProtocolTests(unittest.TestCase):
    def test_scripts_disabled_before_navigation_and_early_load_event_retained(self):
        from secaudit.browser_snapshot import snapshot
        with tempfile.TemporaryDirectory() as temp:
            fixture=Path(temp)/'owned-protocol-fixture'
            fixture.write_text('#!'+sys.executable+'\n'+'''
import json,os
stream=os.fdopen(3,'rb',buffering=0)
disabled=False
def send(value):os.write(4,json.dumps(value).encode()+b'\\0')
while True:
 raw=b''
 while not raw.endswith(b'\\0'):
  data=stream.read(1)
  if not data:raise SystemExit(0)
  raw+=data
 request=json.loads(raw[:-1]);method=request['method'];result={}
 if method=='Target.createTarget':result={'targetId':'fixture'}
 if method=='Target.attachToTarget':result={'sessionId':'session'}
 if method=='Emulation.setScriptExecutionDisabled':disabled=request['params']['value'] is True
 if method=='Page.navigate':
  assert disabled,'untrusted navigation before script disable'
  result={'loaderId':'correct'}
  for loader in ('old','correct'):
   send({'sessionId':'session','method':'Page.lifecycleEvent','params':{'name':'load','loaderId':loader}})
 if method=='DOM.getDocument':result={'root':{'nodeId':1}}
 if method=='DOM.getOuterHTML':result={'outerHTML':'<html><form></form></html>'}
 send({'id':request['id'],'result':result})
''')
            fixture.chmod(0o700)
            self.assertEqual(snapshot(str(fixture)),'<html><form></form></html>')
