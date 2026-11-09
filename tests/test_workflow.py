import threading
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from conftest import auth
from fastapi.testclient import TestClient
from sqlalchemy import select

from secopsmesh.api import create_app
from secopsmesh.config import Principal, token_hash
from secopsmesh.domain import now
from secopsmesh.lab_service import create_lab
from secopsmesh.response import LabResponse
from secopsmesh.store import Action, Audit, Incident


@pytest.fixture
def lab_factory(app, tmp_path):
    lab = create_lab("synthetic-lab-key-at-least-32-characters", str(tmp_path / "gate.db"))
    app.state.workflow.factory = lambda target: LabResponse(target, TestClient(lab))
    return lab


def execute(client, action):
    return client.post(f"/api/actions/{action['id']}/execute", headers=auth("executor"))


def test_real_application_containment_and_rollback(client, approved, lab_factory):
    with TestClient(lab_factory) as probe:
        assert probe.get("/work").status_code == 200
        first = execute(client, approved)
        assert first.status_code == 200, first.text
        assert first.json()["state"] == "verified"
        assert probe.get("/work").status_code == 403
        replay = execute(client, approved)
        assert replay.json() == first.json()
        rollback = client.post(
            "/api/actions",
            json={
                "incident_id": approved["incident_id"],
                "target": "lab-host",
                "action": "rollback",
                "original_action_id": approved["id"],
            },
            headers=auth(),
        ).json()
        assert (
            client.post(
                f"/api/actions/{rollback['id']}/approve",
                json={"fingerprint": rollback["fingerprint"]},
                headers=auth("approver"),
            ).status_code
            == 200
        )
        result = execute(client, rollback).json()
        assert result["state"] == "verified", result
        assert probe.get("/work").status_code == 200
        assert client.get("/api/audit/checkpoint", headers=auth()).json()["valid"]


def test_no_execution_before_approval(client, proposed):
    assert execute(client, proposed).status_code == 403


def test_forged_fingerprint(client, proposed):
    assert (
        client.post(
            f"/api/actions/{proposed['id']}/approve",
            json={"fingerprint": "0" * 64},
            headers=auth("approver"),
        ).status_code
        == 403
    )


def test_self_approval_and_self_execution(client, settings, proposed):
    settings.credentials[token_hash("self")] = Principal(
        "analyst", "lab", frozenset({"approver", "executor"})
    )
    assert (
        client.post(
            f"/api/actions/{proposed['id']}/approve",
            json={"fingerprint": proposed["fingerprint"]},
            headers=auth("self"),
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"/api/actions/{proposed['id']}/approve",
            json={"fingerprint": proposed["fingerprint"]},
            headers=auth("approver"),
        ).status_code
        == 200
    )
    assert (
        client.post(f"/api/actions/{proposed['id']}/execute", headers=auth("self")).status_code
        == 403
    )


@pytest.mark.parametrize(
    "mutation", ["plan", "signature", "expired", "revoked", "target", "evidence", "tenant"]
)
def test_execution_time_rechecks(app, client, settings, approved, mutation):
    with app.state.db.session() as s:
        row = s.get(Action, approved["id"])
        if mutation == "plan":
            row.plan = {**row.plan, "target": "attacker"}
        elif mutation == "signature":
            row.approval = "0" * 64
        elif mutation == "expired":
            row.expires = now().timestamp() - 1
        elif mutation == "tenant":
            row.plan = {**row.plan, "tenant": "other"}
        elif mutation == "evidence":
            incident = s.get(Incident, row.incident_id)
            incident.data = {**incident.data, "evidence_ids": ["new-evidence"]}
    if mutation == "revoked":
        del settings.credentials[token_hash("approver")]
    elif mutation == "target":
        settings.targets["lab-host"]["enabled"] = False
    assert execute(client, approved).status_code == 403


def test_approval_expiry(client, app, proposed):
    with app.state.db.session() as s:
        s.get(Action, proposed["id"]).expires = 0
    assert (
        client.post(
            f"/api/actions/{proposed['id']}/approve",
            json={"fingerprint": proposed["fingerprint"]},
            headers=auth("approver"),
        ).status_code
        == 403
    )


def test_ambiguous_result_is_reconciled_without_reexecution(client, app, approved):
    calls = []

    class Adapter:
        def apply(self, plan):
            calls.append(plan["id"])
            raise httpx.ReadTimeout("synthetic ambiguous network outcome")

        def verify(self, plan):
            return {"verified": True, "test": "independent readback"}

        def close(self):
            pass

    app.state.workflow.factory = lambda _: Adapter()
    assert execute(client, approved).json()["state"] == "ambiguous"
    result = execute(client, approved).json()
    assert result["state"] == "verified" and result["result"]["reconcile"]
    assert calls == [approved["id"]]


def test_failed_verification_never_reports_success(client, app, approved):
    class Adapter:
        def apply(self, plan):
            return {"acknowledged": True}

        def verify(self, plan):
            return {"verified": False, "reachable": True}

        def close(self):
            pass

    app.state.workflow.factory = lambda _: Adapter()
    assert execute(client, approved).json()["state"] == "verification_failed"
    assert execute(client, approved).json()["state"] == "verification_failed"


def test_restart_recovery_readback_only(client, app, settings, approved, lab_factory):
    assert execute(client, approved).json()["state"] == "verified"
    with app.state.db.session() as s:
        row = s.get(Action, approved["id"])
        row.state, row.lease_until = "executing", 0
    restarted = create_app(settings)
    restarted.state.workflow.factory = lambda target: LabResponse(target, TestClient(lab_factory))
    with TestClient(restarted) as other:
        result = other.post("/api/recover", headers=auth("executor"))
        assert result.status_code == 200, result.text
        assert result.json()[0]["state"] == "verified"
        assert result.json()[0]["result"]["reconcile"]
    restarted.state.db.engine.dispose()


def test_concurrent_execution_has_one_side_effect(client, app, approved):
    started, release = threading.Event(), threading.Event()
    calls = []

    class Adapter:
        def apply(self, plan):
            calls.append(plan["id"])
            started.set()
            assert release.wait(5)
            return {"ok": True}

        def verify(self, plan):
            return {"verified": True}

        def close(self):
            pass

    app.state.workflow.factory = lambda _: Adapter()
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(execute, client, approved)
        assert started.wait(5)
        second = execute(client, approved)
        release.set()
        assert first.result().json()["state"] == "verified"
        assert second.status_code == 403
    assert len(calls) == 1


def test_audit_tampering_detected(app, client, seeded):
    assert client.get("/api/audit/checkpoint", headers=auth()).json()["valid"]
    with app.state.db.session() as s:
        row = s.scalar(select(Audit).where(Audit.tenant == "lab"))
        row.body = '{"forged":true}'
    assert not client.get("/api/audit/checkpoint", headers=auth()).json()["valid"]


def test_invalid_target_and_rollback(client, seeded):
    for body in [
        {"incident_id": seeded, "target": "missing"},
        {
            "incident_id": seeded,
            "target": "lab-host",
            "action": "rollback",
            "original_action_id": "missing",
        },
    ]:
        assert client.post("/api/actions", json=body, headers=auth()).status_code == 403


def test_lab_transport_authentication(tmp_path):
    with TestClient(
        create_lab("synthetic-lab-key-at-least-32-characters", str(tmp_path / "service.db"))
    ) as lab:
        assert lab.post("/control", json={}).status_code == 401
        assert (
            lab.post(
                "/control", json={}, headers={"X-Mesh-Time": "0", "X-Mesh-Signature": "forged"}
            ).status_code
            == 401
        )
        assert lab.post("/control", content=b"x" * 4097).status_code == 413
