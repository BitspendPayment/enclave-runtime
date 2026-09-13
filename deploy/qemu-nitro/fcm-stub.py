#!/usr/bin/env python3
"""A stand-in for Firebase, so the e2e can prove what the enclave sends.

Google is not reachable from this harness and would not accept a made-up
registration token if it were. What matters is not that FCM delivered anything
— it is that the *runtime* built the right request: a data-only message, with
no `notification` object, carrying nothing but the labels the guest chose.

So this answers the two endpoints the runtime calls and writes every message it
receives to a file the harness reads back:

    POST /token                                  -> an access token
    POST /v1/projects/<project>/messages:send    -> recorded, then accepted

Plaintext HTTP, which the runtime allows only because `--fcm-endpoint` was
pointed here; PCR0 records that the emulator image was built that way. A
production image has no such setting and talks to Google over TLS it validates
against roots compiled into the binary.
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

RECORD = sys.argv[1] if len(sys.argv) > 1 else "/tmp/fcm-messages.jsonl"


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 - the base class names it
        length = int(self.headers.get("content-length", 0))
        body = self.rfile.read(length)

        if self.path.endswith("/token"):
            # The runtime signs a real RS256 assertion to get here. Checking it
            # would mean holding the public key and reimplementing Google; the
            # signing itself is covered by a unit test that verifies against the
            # key that produced it.
            return self.reply(200, {"access_token": "stub-token", "expires_in": 3600})

        if self.path.endswith("messages:send"):
            try:
                message = json.loads(body)
            except json.JSONDecodeError:
                return self.reply(400, {"error": {"status": "INVALID_ARGUMENT"}})
            with open(RECORD, "a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "authorization": self.headers.get("authorization", ""),
                    "path": self.path,
                    "message": message.get("message", {}),
                }) + "\n")
                f.flush()
            return self.reply(200, {"name": "projects/e2e/messages/stub"})

        self.reply(404, {"error": {"status": "NOT_FOUND"}})

    def reply(self, status, payload):
        encoded = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_args):
        # The harness reads the record file; per-request noise on the console
        # would bury the legs it is actually asserting.
        pass


if __name__ == "__main__":
    open(RECORD, "w", encoding="utf-8").close()
    print(f"fcm-stub: listening on 9101, recording to {RECORD}", flush=True)
    HTTPServer(("0.0.0.0", 9101), Handler).serve_forever()
