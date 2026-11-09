"""Real scoped Kubernetes API and packet-path acceptance in the disposable kind lab."""

import base64
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

from secopsmesh.cli import initialize
from secopsmesh.domain import canonical, stamp

sys.path.insert(0, str(Path(__file__).resolve().parent))
from demo import port, wait_ready  # noqa: E402

if os.environ.get("SECMESH_DISPOSABLE_KUBERNETES_LAB") != "yes":
    raise SystemExit("requires explicitly disposable Kubernetes lab")
connection = json.loads(Path(".runtime/kube-connection.json").read_text())
cluster = connection["clusters"][0]["cluster"]
ca_file = Path(".runtime/kube-ca.crt").resolve()
ca_file.write_bytes(base64.b64decode(cluster["certificate-authority-data"]))
token_file = Path(".runtime/kube-token").resolve()
audit_events = [
    json.loads(line) for line in Path(".runtime/kube-audit.jsonl").read_text().splitlines() if line
]
event = next(
    e
    for e in reversed(audit_events)
    if e.get("verb") in {"create", "get"}
    and e.get("objectRef", {}).get("subresource") == "exec"
    and e["objectRef"].get("namespace") == "secopsmesh-lab"
    and e.get("stage") in {"ResponseStarted", "ResponseComplete"}
)
target = {
    "kind": "kubernetes",
    "tenant": "lab",
    "enabled": True,
    "asset": event["objectRef"].get("uid") or event["objectRef"]["name"],
    "source_family": "kubernetes",
    "environment": "kubernetes",
    "collector_instance": "kind-lab",
    "namespace": "secopsmesh-lab",
    "url": cluster["server"],
    "label": "lab-workload",
    "ca_file": str(ca_file),
    "token_file": str(token_file),
    "probe_url": "http://127.0.0.1:18091/probe",
}
with httpx.Client(
    verify=str(ca_file),
    headers={"Authorization": "Bearer " + token_file.read_text().strip()},
    timeout=10,
    trust_env=False,
) as kube:
    denied = kube.get(cluster["server"] + "/api/v1/namespaces")
    assert denied.status_code == 403, (
        "response service account unexpectedly has cluster namespace access"
    )
    from secopsmesh.response import KubernetesResponse

    adapter = KubernetesResponse(target)
    wrong = adapter.policy({"id": "a" * 32})
    wrong["spec"]["endpointSelector"]["matchLabels"]["secopsmesh.io/target"] = (
        "not-the-approved-target"
    )
    scoped = kube.post(adapter.collection, json=wrong)
    assert scoped.status_code in {403, 422} and "Responder may select only" in scoped.text, (
        f"scope admission denied incorrectly: {scoped.status_code} {scoped.text}"
    )
    assert kube.get(adapter.collection + "/" + adapter.name).status_code == 404, (
        "denied policy unexpectedly persisted"
    )
    adapter.close()
baseline = None
for _ in range(30):
    try:
        baseline = httpx.get(target["probe_url"], timeout=3, trust_env=False).json()
        if baseline.get("reachable") is True and baseline.get("control_reachable") is True:
            break
    except httpx.HTTPError:
        pass
    time.sleep(1)
assert baseline and baseline["reachable"] is True and baseline["control_reachable"] is True, (
    "baseline and control traffic must work before containment"
)
processes = []
with tempfile.TemporaryDirectory(prefix="mesh-kube-acceptance-") as temporary:
    directory = Path(temporary)
    api_port, executor_port = port(), port()
    initialize(directory, api_port=api_port, executor_port=executor_port)
    for file_name in ["config.json", "executor-config.json"]:
        path = directory / file_name
        configuration = json.loads(path.read_text())
        configuration["SECMESH_TARGETS"] = canonical({"lab-kubernetes": target})
        principals = json.loads(configuration["SECMESH_CREDENTIALS"])
        for identity in principals.values():
            if "collector" in identity["roles"]:
                identity["instance"] = "kind-lab"
        configuration["SECMESH_CREDENTIALS"] = canonical(principals)
        path.write_text(canonical(configuration))
    tokens = json.loads((directory / "tokens.json").read_text())
    try:
        for command, bind_port, config in [
            ("executor", executor_port, "executor-config.json"),
            ("serve", api_port, "config.json"),
        ]:
            processes.append(
                subprocess.Popen(  # noqa: S603 -- fixed application entry point, owned temporary configuration
                    [
                        sys.executable,
                        "-m",
                        "secopsmesh.cli",
                        command,
                        "--port",
                        str(bind_port),
                        "--config",
                        str(directory / config),
                    ]
                )
            )  # noqa: S603 -- fixed application entry point and owned temporary configuration
            wait_ready(f"http://127.0.0.1:{bind_port}")
        with httpx.Client(
            base_url=f"http://127.0.0.1:{api_port}", timeout=120, trust_env=False
        ) as client:

            def call(path, role="analyst", body=None):
                response = client.request(
                    "POST" if body is not None else "GET",
                    path,
                    json=body,
                    headers={"Authorization": "Bearer " + tokens[role]},
                )
                response.raise_for_status()
                return response.json()

            iid = call("/api/ingest/kubernetes.audit", "collector", event)["incident_ids"][0]
            investigation = call("/api/incidents/" + iid + "/investigate", body={})
            plan = call("/api/actions", body={"incident_id": iid, "target": "lab-kubernetes"})

            def execute_approved(plan):
                call(
                    "/api/actions/" + plan["id"] + "/approve",
                    "approver",
                    {"fingerprint": plan["fingerprint"]},
                )
                result = call("/api/actions/" + plan["id"] + "/execute", "executor", {})
                for _ in range(15):
                    if result["state"] == "verified":
                        return result
                    assert result["state"] in {"verification_failed", "ambiguous"}, result
                    time.sleep(1)
                    result = call("/api/actions/" + plan["id"] + "/execute", "executor", {})
                raise AssertionError("packet path did not converge: " + canonical(result))

            contained = execute_approved(plan)
            blocked = httpx.get(target["probe_url"], timeout=4, trust_env=False).json()
            assert blocked["reachable"] is False and blocked["control_reachable"] is True
            assert blocked["reason"] == "timeout"
            repeated = call("/api/actions/" + plan["id"] + "/execute", "executor", {})
            assert repeated == contained
            rollback = call(
                "/api/actions",
                body={
                    "incident_id": iid,
                    "target": "lab-kubernetes",
                    "action": "rollback",
                    "original_action_id": plan["id"],
                },
            )
            restored = execute_approved(rollback)
            after = httpx.get(target["probe_url"], timeout=4, trust_env=False).json()
            assert after["reachable"] is True and after["control_reachable"] is True
            assert after["reason"] == "http_200"
            output = {
                "generated_at": stamp(),
                "synthetic_lab": True,
                "real_kubernetes_audit": True,
                "real_cilium_packet_enforcement": True,
                "live_cloud_provider": False,
                "audit_event": event,
                "baseline": baseline,
                "blocked": blocked,
                "restored": after,
                "rbac_cluster_access_status": denied.status_code,
                "admission_wrong_selector_status": scoped.status_code,
                "containment": contained,
                "rollback": restored,
                "investigation": investigation,
                "checkpoint": call("/api/audit/checkpoint"),
            }
            Path("reports").mkdir(exist_ok=True)
            Path("reports/kubernetes-acceptance.json").write_text(
                json.dumps(output, indent=2) + "\n"
            )
            print(
                "Real Kubernetes audit -> detection -> approval -> Cilium deny -> blocked packets -> approved rollback -> restored packets: passed"
            )
    finally:
        for process in processes:
            process.terminate()
        for process in processes:
            process.wait(timeout=5)
