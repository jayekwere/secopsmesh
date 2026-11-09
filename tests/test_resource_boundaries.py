from conftest import auth
from sqlalchemy import event
from sqlalchemy.orm import Session

from secopsmesh.store import Action, Incident


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
