"""Real Chromium acceptance against the production loopback dashboard; no mocks."""
import io
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import zipfile

from playwright.sync_api import sync_playwright, expect
from secaudit import __version__

ROOT = Path(__file__).resolve().parents[1]


def main():
    artifacts = Path(os.environ.get('BROWSER_ARTIFACTS', 'artifacts/browser')).resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temp:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        process = subprocess.Popen(
            [sys.executable, '-m', 'secaudit', 'dashboard', '--port', str(port), '--output', temp],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            env=dict(os.environ,SECAUDIT_EXPERIMENTAL_AI='1'))
        lines = queue.Queue()
        def read_startup():
            for _ in range(3):
                lines.put(process.stdout.readline())
        threading.Thread(target=read_startup, daemon=True).start()
        try:
            startup = [lines.get(timeout=20).strip() for _ in range(3)]
            assert startup[2].startswith('Session password: '), 'Dashboard startup failed'
            password = startup[2].split(': ', 1)[1]
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch()
                context = browser.new_context(http_credentials={'username': 'operator', 'password': password},
                                              viewport={'width': 1440, 'height': 1000})
                page = context.new_page()
                errors = []
                accessibility = []
                axe_script = Path(os.environ['AXE_SCRIPT']).read_text()
                def audit(label):
                    page.evaluate(axe_script)
                    result = page.evaluate("async () => await axe.run(document, {runOnly: {type: 'tag', values: ['wcag2a','wcag2aa','wcag21aa']}})")
                    accessibility.append({'view': label, 'violations': result['violations'], 'incomplete': result['incomplete']})
                    (artifacts / 'accessibility.json').write_text(json.dumps(accessibility, indent=2))
                    # Gather every view before failing so the evidence is actionable.

                page.on('pageerror', lambda error: errors.append(str(error)))
                page.goto(f'http://127.0.0.1:{port}')
                expect(page.locator('#version')).to_have_text('v'+__version__)
                expect(page.locator('#recent-runs')).to_contain_text('No runs yet')
                page.locator('#new-scan').focus()
                page.keyboard.press('Enter')
                expect(page.get_by_role('dialog', name='Start with a defined scope.')).to_be_visible()
                audit('assessment-dialog')
                page.keyboard.press('Escape')
                expect(page.locator('#new-scan')).to_be_focused()
                page.locator('#new-scan').click()
                page.locator('#scan-preset').select_option('offline')
                page.locator('#scan-source').fill(str(ROOT/'demo/source'))
                page.get_by_label('Profile name',exact=True).fill('Owned offline fixture')
                page.get_by_role('button',name='Save as new',exact=True).click()
                expect(page.get_by_role('combobox',name='Saved profile',exact=True)).to_contain_text('revision 1')
                page.locator('#scan-source').fill(str(Path(temp)/'changed-draft'))
                page.locator('#scan-authorized').check()
                page.get_by_role('button',name='Load selected',exact=True).click()
                expect(page.locator('#scan-source')).to_have_value(str(ROOT/'demo/source'))
                expect(page.locator('#scan-authorized')).not_to_be_checked()
                page.get_by_role('button',name='Review configuration',exact=True).click()
                expect(page.locator('.configuration-summary')).to_contain_text('Mode: offline')
                expect(page.locator('#recent-runs')).to_contain_text('No runs yet')
                page.locator('#scan-authorized').check()
                # The browser must display malformed-upload errors without losing the form.
                page.locator('#scan-archive').set_input_files({'name': 'bad.zip', 'mimeType': 'application/zip', 'buffer': b'invalid'})
                page.locator('#submit-scan').click()
                expect(page.locator('#scan-error')).not_to_be_empty()
                expect(page.locator('#scan-dialog')).to_be_visible()
                archive = io.BytesIO()
                with zipfile.ZipFile(archive, 'w') as z:
                    z.writestr('app.py', 'eval(input())\n')
                page.locator('#scan-archive').set_input_files({'name': 'owned-fixture.zip', 'mimeType': 'application/zip', 'buffer': archive.getvalue()})
                page.locator('#submit-scan').click()
                expect(page.locator('#scan-dialog')).not_to_be_visible()
                expect(page.locator('#all-runs .run-name')).to_have_count(1, timeout=90000)
                expect(page.locator('#notice')).to_contain_text('completed', timeout=30000)
                page.locator('#all-runs .run-name').click()
                expect(page.locator('.finding-button').first).to_be_visible()
                page.locator('#finding-search').fill('no-such-rule-acceptance')
                expect(page.locator('#findings-list')).to_contain_text('No matching findings')
                page.locator('#finding-search').fill('')
                page.locator('.finding-button').first.click()
                expect(page.locator('#finding-dialog')).to_be_visible()
                expect(page.locator('#finding-detail')).to_contain_text('Remediation')
                expect(page.get_by_role('combobox',name='Review status',exact=True)).to_be_visible()
                page.get_by_role('combobox',name='Review status',exact=True).select_option('CONFIRMED')
                page.get_by_label('Rationale',exact=True).fill('Reviewed the owned eval fixture.')
                page.get_by_label('Remediation owner',exact=True).fill('Fixture maintainer')
                page.get_by_label('Due date (optional; overdue evaluated in UTC)',exact=True).fill('2026-10-14')
                page.get_by_label('Evidence or verification reference',exact=True).fill('Fixture app.py:1')
                page.get_by_role('button',name='Save review',exact=True).click()
                expect(page.locator('#finding-detail')).to_contain_text('Revision 1')
                expect(page.get_by_label('Remediation owner',exact=True)).to_have_value('Fixture maintainer')
                expect(page.get_by_label('Due date (optional; overdue evaluated in UTC)',exact=True)).to_have_value('2026-10-14')
                audit('finding-dialog')
                page.keyboard.press('Escape')
                page.locator('.nav[data-view="reports"]').click()
                page.get_by_role('button',name='Refresh report snapshots',exact=True).click()
                page.wait_for_function("async () => (await (await fetch('/api/jobs')).json()).some(j => j.kind === 'report refresh' && j.status === 'COMPLETED')",timeout=30000)
                runs=page.evaluate("async () => await (await fetch('/api/runs')).json()")
                assert len(runs)==1, 'Refreshing reports must not create another assessment'
                snapshot=json.loads((Path(temp)/runs[0]['id']/'run.json').read_text())
                assert snapshot['report_snapshot']['includes_operator_reviews']
                assert '2026-10-14' in (Path(temp)/runs[0]['id']/'technical.md').read_text()
                for view in ('overview', 'assessments', 'findings', 'coverage', 'reports'):
                    page.locator(f'.nav[data-view="{view}"]').click()
                    expect(page.locator(f'#view-{view}')).to_be_visible()
                    audit(view)
                card = page.locator('.report-card').filter(has=page.get_by_role('heading', name='Normalized findings'))
                with page.expect_download() as downloaded:
                    card.locator('a').click()
                download = downloaded.value
                assert download.failure() is None, 'Browser download failed: '+str(download.failure())
                assert json.loads(Path(download.path()).read_text()), 'Empty findings download'
                page.screenshot(path=str(artifacts / 'desktop.png'), full_page=True)
                page.set_viewport_size({'width': 390, 'height': 844})
                page.locator('.nav[data-view="overview"]').click()
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'Mobile horizontal overflow'
                audit('mobile-overview')
                page.screenshot(path=str(artifacts / 'mobile.png'), full_page=True)
                page.set_viewport_size({'width': 1440, 'height': 1000})
                page.locator('#new-scan').click()
                page.locator('#scan-archive').set_input_files([])
                page.locator('#scan-source').fill(str(Path(temp) / 'missing-source'))
                page.locator('#submit-scan').click()
                expect(page.locator('#scan-dialog')).not_to_be_visible()
                expect(page.locator('#jobs-list')).to_contain_text('Failed', timeout=30000)
                expect(page.locator('#jobs-list')).to_contain_text('blocked the scan')
                # Hold a real owned HTTP response so cancellation exercises a running worker.
                entered, release = threading.Event(), threading.Event()
                class SlowTarget(BaseHTTPRequestHandler):
                    def log_message(self, *args):
                        pass
                    def do_HEAD(self):
                        self.send_response(200)
                        self.send_header('Content-Length', '0')
                        self.end_headers()
                    def do_GET(self):
                        entered.set()
                        release.wait(30)
                        try:
                            self.do_HEAD()
                        except (BrokenPipeError, ConnectionResetError):
                            pass
                target = ThreadingHTTPServer(('127.0.0.1', 0), SlowTarget)
                target.daemon_threads = True
                threading.Thread(target=target.serve_forever, daemon=True).start()
                try:
                    origin = f'http://127.0.0.1:{target.server_port}/'
                    page.locator('#new-scan').click()
                    page.locator('#scan-source').fill('')
                    page.locator('#scan-target').fill(origin)
                    page.get_by_role('combobox',name='Configuration editor',exact=True).select_option('json')
                    page.locator('#scan-scope').fill(json.dumps({
                        'authorization': 'Owned browser acceptance fixture', 'origins': [origin],
                        'exclusions': [], 'environment': 'local-lab', 'profiles': ['passive'],
                        'max_requests': 2, 'max_seconds': 60, 'allowed_ips': ['127.0.0.1']}))
                    page.locator('#submit-scan').click()
                    expect(page.locator('#scan-dialog')).not_to_be_visible()
                    assert entered.wait(20), 'Crawler never reached owned target'
                    page.locator('#refresh').click()
                    page.locator('#jobs-list button', has_text='Cancel').click()
                    page.wait_for_function("async () => (await (await fetch('/api/jobs')).json()).some(j => j.status === 'CANCELLED')")
                    expect(page.locator('#jobs-list button', has_text='Cancel')).to_have_count(0)
                finally:
                    release.set()
                    target.shutdown()
                    target.server_close()
                # Protocol fixture only: exercise the real dashboard/provider/report
                # path, but never label this real-model acceptance.
                class AIEndpoint(BaseHTTPRequestHandler):
                    def log_message(self,*args):pass
                    def do_GET(self):
                        self.send_response(200);self.end_headers()
                        self.wfile.write(b'{"models":[{"name":"dashboard-fixture"}]}')
                    def do_POST(self):
                        body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                        metadata=json.loads(body['messages'][1]['content'])
                        if any(set(item)!={'id','rule','severity'} for item in metadata):
                            self.send_response(400);self.end_headers();return
                        self.send_response(200);self.end_headers()
                        self.wfile.write(json.dumps({'message':{'content':json.dumps({'suggestions':[{'id':metadata[0]['id'],'text':'Review the referenced deterministic finding.'}]})}}).encode())
                provider=ThreadingHTTPServer(('127.0.0.1',0),AIEndpoint)
                threading.Thread(target=provider.serve_forever,daemon=True).start()
                try:
                    page.locator('#new-scan').click()
                    page.locator('#scan-target').fill('')
                    page.locator('#scan-source').fill(str(ROOT/'demo/source'))
                    page.locator('#scan-preset').select_option('local-ai')
                    expect(page.locator('#ai-controls')).to_be_visible()
                    page.locator('#submit-scan').click()
                    expect(page.locator('#scan-dialog')).to_be_visible()
                    expect(page.locator('#ai-consent')).not_to_be_checked()
                    config={'enabled':True,'provider':'ollama','endpoint':f'http://127.0.0.1:{provider.server_port}',
                            'model':'dashboard-fixture','approved_ips':['127.0.0.1'],'failure_policy':'required'}
                    page.locator('#scan-ai').fill(json.dumps(config))
                    page.locator('#ai-consent').check()
                    page.locator('#scan-scanners').fill('{"shell":{}}')
                    page.locator('#submit-scan').click()
                    expect(page.locator('#scan-error')).not_to_be_empty()
                    page.locator('#scan-scanners').fill('{}')
                    audit('ai-configuration')
                    page.locator('#submit-scan').click()
                    expect(page.locator('#scan-dialog')).not_to_be_visible()
                    page.wait_for_function("async () => (await (await fetch('/api/jobs')).json()).some(j => j.mode === 'local-ai' && j.status === 'COMPLETED')",timeout=90000)
                    rows=page.evaluate("async () => await (await fetch('/api/runs')).json()")
                    ai_run=next(row['id'] for row in rows if row['mode']=='local-ai')
                    saved=page.evaluate("async id => await (await fetch('/api/runs/'+id)).json()",ai_run)
                    assert saved['ai_usage']['verified']=='inference response validated'
                    assert saved['ai_suggestions']['suggestions']
                    assert 'ai-suggestions.json' in saved['available_reports']
                    page.locator('#new-scan').click()
                    config['model']='not-installed'
                    page.locator('#scan-ai').fill(json.dumps(config))
                    page.locator('#submit-scan').click()
                    page.wait_for_function("async () => (await (await fetch('/api/jobs')).json()).some(j => j.mode === 'local-ai' && j.status === 'FAILED')",timeout=30000)
                finally:
                    provider.shutdown();provider.server_close()
                failures = [{'view': a['view'], 'violations': a['violations']} for a in accessibility if a['violations']]
                assert not failures, json.dumps(failures)
                assert not errors, errors
                browser.close()
            result = {'status': 'passed', 'engine': 'Chromium', 'checks': ['keyboard dialog', 'malformed ZIP recovery', 'real offline ZIP scan', 'finding search/detail','saved operator review', 'all navigation views', 'JSON download', 'mobile overflow', 'no uncaught JavaScript errors', 'failed worker diagnostic', 'running crawler cancellation','AI disclosure consent','invalid scanner configuration','AI protocol fixture through reports','missing model failure'], 'limitations': ['Not a full accessibility audit','AI protocol fixture is not real-model acceptance']}
            (artifacts / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
            print(json.dumps(result))
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == '__main__':
    main()
