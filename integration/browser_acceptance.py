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
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
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
                    assert not result['violations'], json.dumps({'view': label, 'violations': result['violations']})

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
                audit('finding-dialog')
                page.keyboard.press('Escape')
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
                assert not errors, errors
                browser.close()
            result = {'status': 'passed', 'engine': 'Chromium', 'checks': ['keyboard dialog', 'malformed ZIP recovery', 'real offline ZIP scan', 'finding search/detail', 'all navigation views', 'JSON download', 'mobile overflow', 'no uncaught JavaScript errors', 'failed worker diagnostic', 'running crawler cancellation'], 'limitations': ['Not a full accessibility audit']}
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
