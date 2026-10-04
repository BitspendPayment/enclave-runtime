#!/usr/bin/env python3
"""A stand-in for AWS End User Messaging Push, so the e2e can prove what the enclave sends.

AWS would not accept a made-up registration token, and the harness has no instance role to sign
with. What matters is not that anything was delivered — it is that the *runtime* built the right
request: a signed `SendMessages` call whose only payload is `RawContent`, holding a data-only FCM
message with no `notification` object and nothing but the labels the guest chose.

So this answers the two calls the runtime makes and writes one line per address to a file the
harness reads back:

    GET  /v1/apps/<app>/channels/gcm   -> an enabled channel, on token auth (the boot probe)
    POST /v1/apps/<app>/messages       -> recorded, then each address reported delivered

Plaintext HTTP, which the runtime allows only because `--push-endpoint` was pointed here — a
setting only a `testing` build has; PCR0 records that the emulator image was built that way. A
production image talks to AWS over TLS it validates against roots compiled into the binary.
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

RECORD = sys.argv[1] if len(sys.argv) > 1 else "/tmp/push-messages.jsonl"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - the base class names it
        if self.path.endswith("/channels/gcm"):
            return self.reply(200, {
                "Platform": "GCM",
                "Enabled": True,
                "HasFcmServiceCredentials": True,
                "DefaultAuthenticationMethod": "TOKEN",
            })
        self.reply(404, {"Message": "not found"})

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("content-length", 0))
        body = self.rfile.read(length)
        if not self.path.endswith("/messages"):
            return self.reply(404, {"Message": "not found"})
        try:
            request = json.loads(body)
            gcm = request["MessageConfiguration"]["GCMMessage"]
            message = json.loads(gcm["RawContent"])["fcmV1Message"]["message"]
        except (json.JSONDecodeError, KeyError, TypeError):
            return self.reply(400, {"Message": "not a RawContent GCM message"})

        result = {}
        with open(RECORD, "a", encoding="utf-8") as f:
            for token, address in request.get("Addresses", {}).items():
                # The signature is not checked — that would mean reimplementing SigV4, and the
                # runtime's unit tests pin it — but who it was signed for is recorded, so a leg can
                # see the request was made for this service.
                f.write(json.dumps({
                    "authorization": self.headers.get("authorization", ""),
                    "path": self.path,
                    "request_keys": sorted(request),
                    "configuration": sorted(gcm),
                    "token": token,
                    "channel": address.get("ChannelType"),
                    "message": message,
                }) + "\n")
                result[token] = {"DeliveryStatus": "SUCCESSFUL", "StatusCode": 200}
            f.flush()
        self.reply(200, {"ApplicationId": "e2e", "Result": result})

    def reply(self, status, payload):
        encoded = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_args):
        # The harness reads the record file; per-request noise on the console would bury the legs
        # it is actually asserting.
        pass


if __name__ == "__main__":
    open(RECORD, "w", encoding="utf-8").close()
    print(f"push-stub: listening on 9101, recording to {RECORD}", flush=True)
    HTTPServer(("0.0.0.0", 9101), Handler).serve_forever()
