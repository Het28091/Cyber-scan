"""Synthetic local fixture; no destructive endpoints or real records."""
from http.server import HTTPServer,BaseHTTPRequestHandler
class Handler(BaseHTTPRequestHandler):
    def do_HEAD(self): self.send_response(200);self.end_headers()
    def do_GET(self):
        self.send_response(200);self.send_header('Content-Type','text/html');self.send_header('Set-Cookie','demo=synthetic; Path=/');self.end_headers()
        self.wfile.write(b'<h1>Synthetic fixture</h1><a href="/public">Public demo record</a>')
HTTPServer(('127.0.0.1',3000),Handler).serve_forever()
