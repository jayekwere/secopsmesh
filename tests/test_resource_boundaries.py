from conftest import auth
from sqlalchemy import event
from sqlalchemy.orm import Session

from secopsmesh.store import Action, Incident


def test_incident_trigger_proposes_but_never_approves(client, settings):
    from secopsmesh.labdata import fixtures

    settings.auto_propose = True
    result = client.post("/api/ingest/wazuh", json=fixtures()["wazuh"], headers=auth("collector"))
    assert result.status_code == 200
    plans = client.get("/api/actions", headers=auth()).json()
    assert len(plans) == 1 and plans[0]["state"] == "pending"
    assert plans[0]["requester"] == "workflow:contain"
    assert (
        client.post(f"/api/actions/{plans[0]['id']}/execute", headers=auth("executor")).status_code
        == 403
    )


def test_sliding_correlation_returns_maximal_windows_in_any_input_order():
    from datetime import timedelta

    from secopsmesh.adapters import parse
    from secopsmesh.detection import Rule, evaluate
    from secopsmesh.domain import now
    from secopsmesh.labdata import fixtures

    f = parse("wazuh", fixtures()["wazuh"], True)[0]
    rule = Rule(
        id="test-window",
        version=1,
        name="Bounded windows",
        kind="correlation",
        min_severity=70,
        min_confidence=0.4,
        categories=[],
        window_seconds=300,
        min_events=2,
        min_sources=1,
    )
    start = now() - timedelta(minutes=10)
    records = [
        (
            f"e{i}",
            f.model_copy(update={"observed_at": (start + timedelta(seconds=i * 120)).isoformat()}),
        )
        for i in range(5)
    ]
    expected = [["e0", "e1", "e2"], ["e1", "e2", "e3"], ["e2", "e3", "e4"]]
    assert [r["evidence_ids"] for r in evaluate([rule], records)] == expected
    assert evaluate([rule], records) == evaluate([rule], list(reversed(records)))


def test_overview_counts_complete_history_without_materializing_entities(app, client, seeded):
    with app.state.db.session() as session:
        for i in range(150):
            session.add(
                Incident(
                    id=f"history-{i}",
                    tenant="lab",
                    entity=f"asset-{i}",
                    window=i,
                    data={"risk": 90 if i % 2 else 20, "large_evidence": ["x" * 128] * 50},
                )
            )
        session.add(
            Incident(
                id="private-other", tenant="other", entity="other", window=0, data={"risk": 100}
            )
        )

    def prohibit_materialization(session, instance):
        if isinstance(instance, (Incident, Action)):
            raise AssertionError("aggregate endpoint loaded a JSON-bearing operational entity")

    event.listen(Session, "loaded_as_persistent", prohibit_materialization)
    try:
        result = client.get("/api/overview", headers=auth())
        assert result.status_code == 200
        assert result.json()["incidents"] == 151
        assert result.json()["high_risk"] == 76
        metrics = client.get("/api/metrics", headers=auth())
        assert metrics.status_code == 200 and "secopsmesh_incidents 151" in metrics.text
    finally:
        event.remove(Session, "loaded_as_persistent", prohibit_materialization)
