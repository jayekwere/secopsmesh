"""A separate pod probes the victim's real Cilium-governed network path."""

import json
import os
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer


class Probe(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/probe":
            self.send_error(404)
            return
        try:
            with urllib.request.urlopen(os.environ["TARGET_URL"], timeout=2) as response:  # nosec B310 -- fixed lab service URL injected by operator
                reachable = response.status == 200
        except (urllib.error.URLError, TimeoutError):
            reachable = False
        body = json.dumps(
            {
                "reachable": reachable,
                "measurement": "separate-pod HTTP packet path",
                "target": "lab-workload",
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


HTTPServer(("0.0.0.0", 8080), Probe).serve_forever()  # nosec B104 -- isolated pod service, not published externally
