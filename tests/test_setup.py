import importlib.util,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def module(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'scripts'/f'{name}.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
class SetupTests(unittest.TestCase):
    def test_windows_paths_are_data(self):
        launch=module('launch');seen=[]
        def convert(v): seen.append(v);return '/mnt/c/source with spaces'
        result=launch.convert_paths(['scan','--source',r'C:\source with spaces','--target','http://127.0.0.1:3000','--output='+r'C:\reports'],convert)
        self.assertEqual(result[2],'/mnt/c/source with spaces');self.assertEqual(len(seen),2);self.assertEqual(result[4],'http://127.0.0.1:3000')
    def test_wsl_environment_stays_in_linux_home(self):
        bootstrap=module('bootstrap');env,out=bootstrap.environment_paths(Path('/mnt/c/project with spaces'),True)
        self.assertTrue(env.is_relative_to(Path.home()/'.local/share/secaudit'));self.assertEqual(env.parent,out.parent)
        other,_=bootstrap.environment_paths(Path('/mnt/c/other'),True);self.assertNotEqual(env,other)
    def test_native_linux_environment(self):
        bootstrap=module('bootstrap');env,out=bootstrap.environment_paths(Path('/tmp/project'),False)
        self.assertEqual(env,Path('/tmp/project/.venv'));self.assertEqual(out,Path('/tmp/project/runs'))
    def test_linux_shell_syntax(self):
        for path in ('setup.sh','run.sh','scripts/setup-linux.sh'):
            p=subprocess.run(['bash','-n',str(ROOT/path)],capture_output=True,text=True);self.assertEqual(p.returncode,0,p.stderr)
    def test_runtime_does_not_install(self):
        source=(ROOT/'scripts/launch.py').read_text()
        self.assertNotIn('pip',source);self.assertNotIn('apt-get',source);self.assertNotIn('shell=True',source)
