"""Synthetic gate records test the validator; they are not acceptance evidence."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from secaudit import __version__
from secaudit.bundle import ALLOWED,SOURCE_PATHS
from secaudit.release_gate import GATES,verify
from secaudit.security import PolicyError

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('release_collector',ROOT/'scripts/collect-release.py')
collector=importlib.util.module_from_spec(spec);spec.loader.exec_module(collector)
package_spec=importlib.util.spec_from_file_location('release_packager',ROOT/'scripts/package-release.py')
packager=importlib.util.module_from_spec(package_spec);package_spec.loader.exec_module(packager)


class ReleaseGateTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.commit='a'*40;self.path=self.root/'manifest.json'
        self.manifest={'schema':1,'source_commit':self.commit,'app_version':__version__,'gates':{}}
        for gate,kind in GATES.items():
            self.evidence(gate,{'gate':gate,'kind':kind,'status':'PASS','source_commit':self.commit,'app_version':__version__,
                'checks':['Synthetic validator control only'],'unresolved_requirements':[],'reviewer':'test-fixture',
                'mode':'local-ai' if gate=='local_ai' else 'connected-ai','real_provider_verified':True,
                'provider_identity':'synthetic validator record, not a real model run','modes_verified':['offline','internet'],
                'platform':'Linux','conclusion':'success','run_url':'https://github.com/example/test/actions/runs/1'})
        self.save()

    def save(self):self.path.write_text(json.dumps(self.manifest),encoding='utf-8')

    def evidence(self,gate,data):
        name=gate+'.json';raw=json.dumps(data).encode();(self.root/name).write_bytes(raw)
        self.manifest['gates'][gate]={'status':'PASS','evidence':name,'sha256':hashlib.sha256(raw).hexdigest()}

    def check(self):return verify(self.path,self.commit,__version__)

    def test_complete_manifest_and_cli(self):
        self.assertEqual(set(self.check()['gates']),set(GATES))
        result=subprocess.run([sys.executable,'-m','secaudit','release-check','--manifest',str(self.path),'--commit',self.commit],cwd=ROOT,capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(json.loads(result.stdout)['status'],'PASS')

    def test_missing_gate_and_nonpass_block(self):
        for status in ('NOT TESTED','FAIL','SKIP',True):
            self.manifest['gates']['local_ai']['status']=status;self.save()
            with self.assertRaises(PolicyError):self.check()
        del self.manifest['gates']['local_ai'];self.save()
        with self.assertRaises(PolicyError):self.check()

    def test_commit_version_digest_and_fixture_provenance_block(self):
        original=json.loads((self.root/'local_ai.json').read_text())
        for change in ({'kind':'protocol-fixture'},{'source_commit':'b'*40},{'app_version':'0.0.0'},
                       {'unresolved_requirements':['real model not run']},{'unresolved_requirements':None},
                       {'real_provider_verified':False},{'provider_identity':''},{'mode':'connected-ai'},{'checks':[]}):
            self.evidence('local_ai',dict(original,**change));self.save()
            with self.subTest(change=change),self.assertRaises(PolicyError):self.check()
        self.evidence('local_ai',original);self.save();(self.root/'local_ai.json').write_text('{}')
        with self.assertRaisesRegex(PolicyError,'checksum'):self.check()

    def test_paths_cannot_escape(self):
        for path in ('../secret.json','/secret.json','C:/secret.json','folder\\secret.json','folder/../local_ai.json','folder//local_ai.json'):
            self.manifest['gates']['local_ai']['evidence']=path;self.save()
            with self.subTest(path=path),self.assertRaises(PolicyError):self.check()

    def test_linux_and_both_non_ai_modes_required(self):
        for gate,change in (('non_ai',{'modes_verified':['offline']}),('dashboard',{'platform':'Windows'}),('owner_machine',{'reviewer':''}),('linux_ci',{'conclusion':'failure'})):
            original=json.loads((self.root/(gate+'.json')).read_text())
            self.evidence(gate,dict(original,**change));self.save()
            with self.assertRaises(PolicyError):self.check()
            self.evidence(gate,original)

    def test_collection_failure_leaves_no_output(self):
        previous=Path.cwd()
        try:
            os.chdir(self.root)
            with patch.dict(os.environ,{'GITHUB_SHA':self.commit,'SECAUDIT_ACCEPTANCE_MANIFEST':str(self.path)}):
                with self.assertRaisesRegex(ValueError,'four'):collector.main()
            self.assertFalse((self.root/'release-assets').exists())
            self.assertEqual(list(self.root.glob('secaudit-release-*')),[])
        finally:os.chdir(previous)


class ReleaseIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)

    def checksums(self):
        return '\n'.join(hashlib.sha256((self.root/n).read_bytes()).hexdigest()+'  '+n for n in ('release.json','bundle.tar.gz'))+'\n'

    def test_checksums_require_all_unique_artifacts(self):
        (self.root/'release.json').write_text('{}');(self.root/'bundle.tar.gz').write_bytes(b'fixture')
        valid=self.checksums()
        for listing in ('',valid.splitlines()[0]+'\n',valid+valid,valid.replace('bundle.tar.gz','../bundle.tar.gz'),valid.replace('bundle.tar.gz','not-delivered.tar.gz')):
            (self.root/'SHA256SUMS').write_text(listing)
            with self.subTest(listing=listing),self.assertRaises(ValueError):collector.verify_checksums(self.root)
        (self.root/'SHA256SUMS').write_text(valid);collector.verify_checksums(self.root)
        (self.root/'bundle.tar.gz').write_bytes(b'changed')
        with self.assertRaises(ValueError):collector.verify_checksums(self.root)

    def archive(self,extra=None):
        path=self.root/'bundle.tar.gz';files={name:b'fixture' for name in ALLOWED}
        manifest={'app_version':__version__,'files':{name:hashlib.sha256(raw).hexdigest() for name,raw in files.items()}}
        files['manifest.json']=json.dumps(manifest).encode()
        with tarfile.open(path,'w:gz') as tar:
            for name,raw in files.items():
                member=tarfile.TarInfo('bundle/'+name);member.size=len(raw);tar.addfile(member,io.BytesIO(raw))
            if extra is not None:
                member=tarfile.TarInfo(extra);member.size=0;tar.addfile(member,io.BytesIO())
        return path

    def test_archive_rejects_unmanifested_duplicate_and_traversal(self):
        collector.verify_archive(self.archive())
        for name in ('bundle/extra','bundle/LICENSE','../escape','/absolute'):
            with self.subTest(name=name),self.assertRaises(ValueError):collector.verify_archive(self.archive(name))

    def test_source_bundle_contains_acceptance_tools(self):
        for name in ('integration','requirements-dev.txt','.github'):
            self.assertIn(name,SOURCE_PATHS);self.assertTrue((ROOT/name).exists())

    def test_package_requires_exact_clean_source_commit(self):
        def git(*args):return subprocess.check_output(['git',*args],cwd=self.root,text=True,stderr=subprocess.STDOUT).strip()
        git('init');(self.root/'README.md').write_text('Owned test repository')
        git('add','README.md');git('-c','user.name=Secaudit fixture','-c','user.email=fixture@example.invalid','commit','-m','fixture')
        commit=git('rev-parse','HEAD');packager.verify_source(self.root,commit)
        with self.assertRaisesRegex(ValueError,'commit'):packager.verify_source(self.root,'a'*40)
        (self.root/'README.md').write_text('Changed source')
        with self.assertRaisesRegex(ValueError,'uncommitted'):packager.verify_source(self.root,commit)
        (self.root/'README.md').write_text('Owned test repository')
        (self.root/'.gitignore').write_text('.env\n__pycache__/\n*.pyc\n')
        (self.root/'secaudit').mkdir();(self.root/'secaudit/.env').write_text('synthetic fixture, not a credential')
        with self.assertRaisesRegex(ValueError,'ignored'):packager.verify_source(self.root,commit)
        (self.root/'secaudit/.env').unlink()
        (self.root/'secaudit/__pycache__').mkdir();(self.root/'secaudit/__pycache__/cache.pyc').write_bytes(b'fixture')
        packager.verify_source(self.root,commit)
        (self.root/'tests').mkdir();(self.root/'tests/untracked.py').write_text('untracked input')
        with self.assertRaisesRegex(ValueError,'untracked'):packager.verify_source(self.root,commit)


if __name__=='__main__':unittest.main()
