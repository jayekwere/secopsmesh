"""A separate pod probes the victim's real Cilium-governed network path."""

import json
import os
import socket
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer


def measure(url):
    try:
        with urllib.request.urlopen(url, timeout=2) as response:  # noqa: S310 -- operator-owned fixed lab HTTP services
            return response.status == 200, "http_200"
    except urllib.error.HTTPError:
        return True, "http_error"
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            return False, "timeout"
        if isinstance(exc.reason, socket.gaierror):
            return False, "dns_error"
        if isinstance(exc.reason, ConnectionRefusedError):
            return False, "connection_refused"
        return False, "network_error"
    except TimeoutError:
        return False, "timeout"


class Probe(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/probe":
            self.send_error(404)
            return
        reachable, reason = measure(os.environ["TARGET_URL"])
        control, control_reason = measure(os.environ["CONTROL_URL"])
        body = json.dumps(
            {
                "schema_version": "1.0",
                "reachable": reachable,
                "reason": reason,
                "control_reachable": control and control_reason == "http_200",
                "measurement": "separate-pod HTTP packet path",
                "target": "lab-workload",
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Probe).serve_forever()  # noqa: S104 -- isolated pod service, not a host publication
