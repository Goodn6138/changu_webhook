from http.server import BaseHTTPRequestHandler
import json, hmac, hashlib, os

WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        signature = self.headers.get("Signature", "")

        # Verify HMAC signature
        if WEBHOOK_SECRET and not self._verify(body, signature):
            self._json(400, {"error": "Invalid signature"})
            return

        data = json.loads(body)
        tx_ref = data.get("tx_ref")
        status = data.get("status")

        if status == "success":
            # TODO: give value, update DB, send email, etc.
            print(f"[PAID] {tx_ref}")
        else:
            print(f"[FAILED] {tx_ref}")

        # Always return 200 so PayChangu stops retrying
        self._json(200, {"received": True})

    def _verify(self, payload, signature):
        expected = hmac.new(WEBHOOK_SECRET.encode(), payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)

    def _json(self, code, data):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
