"""Wazuh custom integration entry point; URL and credential come only from operator environment."""

import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

import httpx

if len(sys.argv) < 2:
    raise SystemExit("usage: wazuh-forwarder.py <manager-generated-alert-file>")
api = os.environ["SECMESH_API_URL"].rstrip("/")
origin = urlparse(api)
if origin.scheme != "https" and not (
    origin.scheme == "http" and origin.hostname in {"127.0.0.1", "localhost"}
):
    raise SystemExit("collector requires HTTPS except on loopback")
path = Path(sys.argv[1])
with path.open("rb") as handle:
    content = handle.read(262145)
if len(content) > 262144:
    raise SystemExit("alert exceeds 256 KiB")
payload = json.loads(content)
with httpx.Client(timeout=15, follow_redirects=False, trust_env=False) as client:
    for attempt in range(3):
        try:
            response = client.post(
                api + "/api/ingest/wazuh",
                json=payload,
                headers={"Authorization": "Bearer " + os.environ["SECMESH_COLLECTOR_TOKEN"]},
            )
            response.raise_for_status()
            break
        except (httpx.TimeoutException, httpx.NetworkError):
            if attempt == 2:
                raise SystemExit(
                    "delivery failed after three attempts; retain manager alert for replay"
                ) from None
