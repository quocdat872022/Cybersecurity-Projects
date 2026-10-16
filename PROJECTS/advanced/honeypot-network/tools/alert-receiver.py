#!/usr/bin/env python3
import hashlib, hmac, json, os
from http.server import BaseHTTPRequestHandler, HTTPServer

SECRET = os.environ.get("SECRET", "test").encode()
FAIL_FIRST = int(os.environ.get("FAIL_FIRST", "0"))
seen = {}

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        want = "sha256=" + hmac.new(SECRET, body, hashlib.sha256).hexdigest()
        ok = hmac.compare_digest(self.headers.get("X-Hive-Signature", ""), want)
        did = self.headers.get("X-Hive-Delivery")
        seen[did] = seen.get(did, 0) + 1
        a = json.loads(body)
        print(f"try#{seen[did]} {a['rule']:14} {a['severity']:8} sig={'OK' if ok else 'BAD'} | {a['summary']}", flush=True)
        self.send_response(500 if seen[did] <= FAIL_FIRST else 200)
        self.end_headers()
    def log_message(self, *a): pass

HTTPServer(("0.0.0.0", 9000), H).serve_forever()