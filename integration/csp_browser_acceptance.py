"""Owned loopback CSP fixtures in real Chromium; not an external-site scan."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading

from secaudit.web_csp import csp_findings


def verify_csp_browser(browser, artifacts):
    cases = [
        ('unrelated', [('Content-Security-Policy', 'img-src *')], True, True, True),
        ('default', [('Content-Security-Policy', "default-src 'none'")], False, False, False),
        ('element', [('Content-Security-Policy', "script-src-elem 'none'")], False, True, True),
        ('attribute', [('Content-Security-Policy', "script-src-attr 'none'")], True, False, True),
        ('split', [('Content-Security-Policy', "script-src-elem 'none'"),
                   ('Content-Security-Policy', "script-src-attr 'none'")], False, False, False),
        ('combined', [('Content-Security-Policy', "img-src *, script-src 'none'")], False, False, False),
        ('report-only', [('Content-Security-Policy', 'img-src *'),
                         ('Content-Security-Policy-Report-Only', "default-src 'none'")], True, True, True),
    ]
    document = b'<html><body><script>window.elementRan=true</script><button id="probe" onclick="window.attributeRan=true">Owned fixture</button></body></html>'
    headers_by_path = {'/' + name: headers for name, headers, *_ in cases}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path not in headers_by_path:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            for name, value in headers_by_path[self.path]:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(document)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f'http://127.0.0.1:{server.server_port}'
    context = browser.new_context(service_workers='block')
    # Only the owned server receives traffic, even if the fixture changes later.
    context.route('**/*', lambda route: route.continue_() if route.request.url.startswith(base + '/') else route.abort())
    records = []
    try:
        for name, headers, element, attribute, expected_gap in cases:
            page = context.new_page()
            try:
                page.goto(base + '/' + name)
                page.locator('#probe').click()
                observed = page.evaluate('({element: window.elementRan === true, attribute: window.attributeRan === true})')
                assert observed == {'element': element, 'attribute': attribute}, (name, observed)
                findings = csp_findings(base + '/' + name, 200, [('Content-Type', 'text/html')] + headers, document)
                gap = any(f.rule == 'HTTP-CSP-SCRIPT-COVERAGE' for f in findings)
                assert gap == expected_gap, (name, gap)
                records.append({'case': name, 'browser': observed, 'declaration_gap': gap, 'result': 'PASS'})
            finally:
                page.close()
    finally:
        context.close()
        server.shutdown()
        server.server_close()
        thread.join()
    (artifacts / 'csp-directives.json').write_text(json.dumps({
        'engine': 'Chromium', 'fixture': 'owned loopback', 'cases': records,
        'limitation': 'Declaration coverage fixtures only; no general CSP strength or independent accuracy claim.'
    }, indent=2) + '\n')
