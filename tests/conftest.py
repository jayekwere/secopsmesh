import os
import uuid
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient

from secopsmesh.api import create_app
from secopsmesh.config import Principal, Settings, token_hash
from secopsmesh.domain import SOURCES
from secopsmesh.labdata import fixtures, lab_aliases


@pytest.fixture
def settings(tmp_path):
    test_url = os.environ.get("TEST_DATABASE_URL", "")
    if test_url:
        parsed = urlparse(test_url)
        if (
            parsed.hostname not in {"127.0.0.1", "localhost"}
            or parsed.path != "/mesh_test"
            or parsed.username != "mesh_test"
            or os.environ.get("SECMESH_ALLOW_TEST_DB_RESET") != "disposable-ci-only"
        ):
            raise RuntimeError(
                "test resets require an explicitly disposable loopback mesh_test database"
            )
    principals = {
        "collector": Principal(
            "collector", "lab", frozenset({"collector"}), frozenset(SOURCES), True
        ),
        "analyst": Principal("analyst", "lab", frozenset({"observer", "analyst"})),
        "approver": Principal("approver", "lab", frozenset({"approver"})),
        "executor": Principal("executor", "lab", frozenset({"executor"})),
        "other": Principal(
            "other",
            "other-" + uuid.uuid4().hex,
            frozenset({"observer", "analyst", "approver", "executor", "collector"}),
            frozenset(SOURCES),
        ),
    }
    return Settings(
        service_mode="embedded-test",
        database_url=os.environ.get("TEST_DATABASE_URL", "sqlite:///" + str(tmp_path / "test.db")),
        signing_key=b"synthetic-test-signing-key-32bytes-only",
        credentials={token_hash(k): p for k, p in principals.items()},
        aliases=lab_aliases(),
        targets={
            "lab-host": {
                "tenant": "lab",
                "kind": "lab",
                "enabled": True,
                "asset": "lab-host-01",
                "source_family": "wazuh",
                "environment": "wazuh",
                "collector_instance": "default",
                "url": "http://127.0.0.1:8091",
                "key": "synthetic-lab-key-at-least-32-characters",
            }
        },
    )


@pytest.fixture
def app(settings):
    app = create_app(settings)
    yield app
    # PostgreSQL job isolates each test with cleanup; only the dedicated CI database is allowed.
    if os.environ.get("TEST_DATABASE_URL"):
        from secopsmesh.store import Base

        Base.metadata.drop_all(app.state.db.engine)
    app.state.db.engine.dispose()


@pytest.fixture
def client(app):
    with TestClient(app) as client:
        yield client


def auth(role="analyst"):
    return {"Authorization": "Bearer " + role}


@pytest.fixture
def seeded(client):
    result = client.post("/api/ingest/wazuh", json=fixtures()["wazuh"], headers=auth("collector"))
    assert result.status_code == 200, result.text
    iid = result.json()["incident_ids"][0]
    return iid


@pytest.fixture
def proposed(client, seeded):
    response = client.post(
        "/api/actions", json={"incident_id": seeded, "target": "lab-host"}, headers=auth()
    )
    assert response.status_code == 200, response.text
    return response.json()


@pytest.fixture
def approved(client, proposed):
    response = client.post(
        f"/api/actions/{proposed['id']}/approve",
        json={"fingerprint": proposed["fingerprint"]},
        headers=auth("approver"),
    )
    assert response.status_code == 200, response.text
    return response.json()
