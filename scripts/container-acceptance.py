"""Exercise the built Compose stack through its published authenticated API."""

import json
from pathlib import Path

import httpx

tokens = json.loads(Path(".runtime/compose/tokens.json").read_text())
with httpx.Client(base_url="http://127.0.0.1:8080", timeout=120, trust_env=False) as client:

    def call(path, role="analyst", body=None):
        response = client.request(
            "POST" if body is not None else "GET",
            path,
            json=body,
            headers={"Authorization": "Bearer " + tokens[role]},
        )
        response.raise_for_status()
        return response.json()

    incidents = call("/api/incidents")
    incident = next(i for i in incidents if "hybrid-identity" in i["entity"])
    report = call("/api/incidents/" + incident["id"] + "/investigate", body={})
    plan = call("/api/actions", body={"incident_id": incident["id"], "target": "lab-host"})
    call(
        "/api/actions/" + plan["id"] + "/approve", "approver", {"fingerprint": plan["fingerprint"]}
    )
    contained = call("/api/actions/" + plan["id"] + "/execute", "executor", {})
    assert contained["state"] == "verified", contained
    rollback = call(
        "/api/actions",
        body={
            "incident_id": incident["id"],
            "target": "lab-host",
            "action": "rollback",
            "original_action_id": plan["id"],
        },
    )
    call(
        "/api/actions/" + rollback["id"] + "/approve",
        "approver",
        {"fingerprint": rollback["fingerprint"]},
    )
    restored = call("/api/actions/" + rollback["id"] + "/execute", "executor", {})
    assert restored["state"] == "verified", restored
    output = {
        "synthetic": True,
        "transport": "Docker Compose / PostgreSQL / separate API and executor / isolated response network",
        "containment": contained,
        "rollback": restored,
        "investigation": report,
        "checkpoint": call("/api/audit/checkpoint"),
    }
    Path("reports").mkdir(exist_ok=True)
    Path("reports/container-acceptance.json").write_text(json.dumps(output, indent=2))
print("Container containment, readback, rollback and audit acceptance passed.")
