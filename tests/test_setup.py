import importlib.util,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def module(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'scripts'/f'{name}.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
class SetupTests(unittest.TestCase):
    def test_native_linux_environment(self):
        bootstrap=module('bootstrap');env,out=bootstrap.environment_paths(Path('/tmp/project'))
        self.assertEqual(env,Path('/tmp/project/.venv'));self.assertEqual(out,Path('/tmp/project/runs'))
    def test_linux_shell_syntax(self):
        for path in ('setup.sh','run.sh','scripts/setup-linux.sh'):
            p=subprocess.run(['bash','-n',str(ROOT/path)],capture_output=True,text=True);self.assertEqual(p.returncode,0,p.stderr)
    def test_runtime_does_not_install(self):
        source=(ROOT/'scripts/launch.py').read_text()
        self.assertNotIn('pip',source);self.assertNotIn('apt-get',source);self.assertNotIn('shell=True',source)
