import httpx
import pytest
from conftest import auth

from secopsmesh.response import KubernetesResponse, ResponseError


@pytest.mark.parametrize(
    "reason,control",
    [("dns_error", True), ("connection_refused", True), ("http_error", True), ("timeout", False)],
)
def test_packet_failure_is_not_automatically_verified(reason, control):
    target = {
        "namespace": "secopsmesh-lab",
        "url": "https://synthetic.invalid",
        "label": "lab-workload",
        "probe_url": "https://synthetic.invalid/probe",
    }
    plan = {"id": "a" * 32, "action": "contain", "original_action_id": None}
    adapter = None

    def handler(request):
        if request.url.path == "/probe":
            return httpx.Response(
                200,
                json={
                    "schema_version": "1.0",
                    "target": "lab-workload",
                    "reachable": False,
                    "control_reachable": control,
                    "reason": reason,
                },
            )
        return httpx.Response(200, json=adapter.policy(plan))

    adapter = KubernetesResponse(target, httpx.Client(transport=httpx.MockTransport(handler)))
    adapter.baseline = {"target": "lab-workload", "reachable": True, "control_reachable": True}
    assert adapter.verify(plan)["verified"] is False
    adapter.close()


def test_kubernetes_mutation_requires_positive_preflight():
    adapter = KubernetesResponse(
        {
            "namespace": "secopsmesh-lab",
            "url": "https://synthetic.invalid",
            "label": "lab-workload",
        },
        httpx.Client(),
    )
    with pytest.raises(ResponseError, match="preflight"):
        adapter.apply({"id": "a" * 32, "action": "contain"})
    adapter.close()


def test_durable_preflight_survives_ambiguous_execution(app, client, approved):
    calls = []

    class Adapter:
        baseline = None

        def preflight(self, plan):
            return {"reachable": True, "control_reachable": True, "target": "test-lab"}

        def apply(self, plan):
            calls.append(plan["id"])
            raise httpx.ReadTimeout("synthetic ambiguous write")

        def verify(self, plan):
            return {"verified": bool(self.baseline and self.baseline["reachable"])}

        def close(self):
            pass

    app.state.workflow.factory = lambda _: Adapter()
    path = f"/api/actions/{approved['id']}/execute"
    first = client.post(path, headers=auth("executor")).json()
    assert first["state"] == "ambiguous" and first["result"]["baseline"]["reachable"]
    second = client.post(path, headers=auth("executor")).json()
    assert second["state"] == "verified" and second["result"]["reconcile"]
    assert calls == [approved["id"]]


def test_approval_plan_exposes_scope_but_never_response_secret(client, proposed):
    assert proposed["plan"]["target_scope"]["asset"] == "lab-host-01"
    assert "key" not in proposed["plan"]["target_scope"]
    assert "synthetic-lab-key" not in str(proposed)


@pytest.mark.parametrize(
    "body",
    [
        {"jsonrpc": "2.0", "method": []},
        {"jsonrpc": "2.0", "method": "tools/call", "params": []},
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": [], "arguments": {"incident_id": "test"}},
        },
        {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "execute", "arguments": []}},
    ],
)
def test_malformed_or_privileged_tools_fail_closed_and_are_audited(client, body):
    assert client.post("/api/mcp", json=body, headers=auth()).status_code == 403
    rows = client.get("/api/audit", headers=auth()).json()
    assert rows[0]["kind"] == "authorization.denied"
    assert client.get("/api/audit/checkpoint", headers=auth()).json()["valid"]
