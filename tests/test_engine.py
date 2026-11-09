import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from conftest import auth

from secopsmesh.adapters import AdapterError, parse
from secopsmesh.domain import SOURCES, Finding, canonical, now
from secopsmesh.labdata import fixtures


@pytest.mark.parametrize("source", SOURCES)
def test_provider_contract(source):
    result = parse(source, fixtures()[source], True)
    assert len(result) == 1
    f = result[0]
    assert f.synthetic and f.asset and f.source_id and f.risk >= 70
    assert Finding.model_validate_json(f.model_dump_json()) == f


@pytest.mark.parametrize("source", SOURCES)
def test_provider_rejects_missing_fields(source):
    with pytest.raises((AdapterError, ValueError)):
        parse(source, {"unrecognized": "data"})


@pytest.mark.parametrize("source", SOURCES)
def test_api_ingestion_deduplicates(client, source):
    event = fixtures()[source]
    first = client.post("/api/ingest/" + source, json=event, headers=auth("collector"))
    assert first.status_code == 200, first.text
    second = client.post("/api/ingest/" + source, json=event, headers=auth("collector"))
    assert second.status_code == 200
    assert first.json()["accepted"] == second.json()["duplicates"]
    assert second.json()["accepted"] == []


def test_related_sources_keep_all_provenance(client):
    payloads = fixtures()
    for source in ["wazuh", "aws.guardduty", "aws.cloudtrail"]:
        response = client.post(
            "/api/ingest/" + source, json=payloads[source], headers=auth("collector")
        )
        assert response.status_code == 200, response.text
    incidents = client.get("/api/incidents", headers=auth()).json()
    assert len(incidents) == 1
    assert len(incidents[0]["evidence_ids"]) == 3
    assert incidents[0]["environments"] == ["aws", "wazuh"]
    assert "hybrid-identity-pivot" in {d["rule_id"] for d in incidents[0]["detections"]}


def test_untrusted_relationship_does_not_correlate(client):
    data = fixtures()
    data["wazuh"]["correlation_key"] = "attacker"
    data["azure.defender"]["correlation_key"] = "attacker"
    for source in ["wazuh", "azure.defender"]:
        assert (
            client.post(
                "/api/ingest/" + source, json=data[source], headers=auth("collector")
            ).status_code
            == 200
        )
    assert len(client.get("/api/incidents", headers=auth()).json()) == 2


def test_stale_data_not_current_detection(client):
    data = fixtures()["wazuh"]
    data["timestamp"] = (now() - timedelta(days=3)).isoformat()
    result = client.post("/api/ingest/wazuh", json=data, headers=auth("collector")).json()
    assert result["incident_ids"] == []
    finding = client.get("/api/events", headers=auth()).json()[0]
    assert "stale_evidence" in finding["quality"]


def test_future_and_conflicting_evidence(client):
    data = fixtures()["wazuh"]
    data["timestamp"] = (now() + timedelta(hours=1)).isoformat()
    assert (
        client.post("/api/ingest/wazuh", json=data, headers=auth("collector")).json()[
            "incident_ids"
        ]
        == []
    )
    data["rule"]["level"] = 2
    client.post("/api/ingest/wazuh", json=data, headers=auth("collector"))
    events = client.get("/api/events", headers=auth()).json()
    assert any("conflicting_source_revision" in e["quality"] for e in events)


def test_secret_redaction_and_synthetic_principal(client):
    data = fixtures()["wazuh"]
    data["synthetic"] = False
    data["rule"]["description"] += " Bearer abc123 password=canary"
    client.post("/api/ingest/wazuh", json=data, headers=auth("collector"))
    event = client.get("/api/events", headers=auth()).json()[0]
    text = canonical(event)
    assert event["synthetic"]
    assert (
        "synthetic-redaction-canary" not in text and "abc123" not in text and "=canary" not in text
    )


def test_cross_tenant_reads_and_mutations(client, proposed, seeded):
    assert client.get("/api/events", headers=auth("other")).json() == []
    assert client.get("/api/incidents", headers=auth("other")).json() == []
    for path in [f"/api/incidents/{seeded}", f"/api/incidents/{seeded}/investigations"]:
        assert client.get(path, headers=auth("other")).status_code == 403
    assert (
        client.post(
            f"/api/actions/{proposed['id']}/approve",
            json={"fingerprint": proposed["fingerprint"]},
            headers=auth("other"),
        ).status_code
        == 403
    )
    assert (
        client.post(f"/api/actions/{proposed['id']}/execute", headers=auth("other")).status_code
        == 403
    )


def test_concurrent_deduplication(client):
    payload = fixtures()["wazuh"]
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(
            pool.map(
                lambda _: client.post(
                    "/api/ingest/wazuh", json=copy.deepcopy(payload), headers=auth("collector")
                ),
                range(8),
            )
        )
    assert all(r.status_code == 200 for r in results), [r.text for r in results]
    assert sum(len(r.json()["accepted"]) for r in results) == 1
    assert client.get("/api/audit/checkpoint", headers=auth()).json()["valid"]


@pytest.mark.parametrize(
    "path",
    [
        "/api/overview",
        "/api/events",
        "/api/actions",
        "/api/audit",
        "/api/rules",
        "/api/sources",
        "/api/metrics",
        "/api/targets",
        "/api/openapi.json",
    ],
)
def test_authenticated_contract(client, path):
    assert client.get(path).status_code == 401
    assert client.get(path, headers=auth("collector")).status_code == 403
    assert client.get(path, headers=auth()).status_code == 200


def test_bounded_requests(client):
    assert (
        client.post(
            "/api/ingest/wazuh", content=b"x" * 262145, headers=auth("collector")
        ).status_code
        == 413
    )
    deep: dict = {}
    for _ in range(18):
        deep = {"child": deep}
    assert client.post("/api/ingest/wazuh", json=deep, headers=auth("collector")).status_code == 422
    assert (
        client.post(
            "/api/ingest/wazuh", json={"data": [1] * 101}, headers=auth("collector")
        ).status_code
        == 422
    )
    assert client.get("/api/events?limit=1000", headers=auth()).status_code == 422


def test_unsupported_source_and_collector_scope(client, settings):
    assert client.post("/api/ingest/unknown", json={}, headers=auth("collector")).status_code == 403
    from secopsmesh.config import Principal, token_hash

    settings.credentials[token_hash("limited")] = Principal(
        "limited", "lab", frozenset({"collector"}), frozenset({"aws.guardduty"})
    )
    assert (
        client.post(
            "/api/ingest/wazuh", json=fixtures()["wazuh"], headers=auth("limited")
        ).status_code
        == 403
    )
    assert client.post("/api/ingest/wazuh", json={}, headers=auth()).status_code == 403


def test_same_pod_name_in_different_namespaces_does_not_correlate(client, settings):
    settings.aliases = {}
    first = fixtures()["kubernetes.audit"]
    second = copy.deepcopy(first)
    second["auditID"] = "different-namespace-event"
    second["objectRef"]["namespace"] = "different-lab"
    for event in [first, second]:
        assert (
            client.post(
                "/api/ingest/kubernetes.audit", json=event, headers=auth("collector")
            ).status_code
            == 200
        )
    assert len(client.get("/api/incidents", headers=auth()).json()) == 2


def test_cross_source_origin_dedup_keeps_provenance_without_false_corroboration(client):
    records = fixtures()
    origin = "arn:aws:guardduty:us-west-2:000000000000:detector/lab/finding/same-origin"
    records["aws.guardduty"]["arn"] = origin
    records["aws.securityhub"]["Id"] = origin
    for source in ["aws.guardduty", "aws.securityhub"]:
        assert (
            client.post(
                "/api/ingest/" + source, json=records[source], headers=auth("collector")
            ).status_code
            == 200
        )
    groups = client.get("/api/findings", headers=auth()).json()["groups"]
    assert len(groups) == 1 and len(groups[0]["evidence_ids"]) == 2
    assert groups[0]["sources"] == ["aws.guardduty", "aws.securityhub"]
    report = client.post("/api/replay", headers=auth()).json()
    assert "hybrid-identity-pivot" not in {r["rule_id"] for r in report["detections"]}


@pytest.mark.parametrize("bad", [None, "invalid", {}, float("inf")])
def test_invalid_severity_fails_validation(client, bad):
    payload = fixtures()["aws.guardduty"]
    payload["severity"] = bad
    # JSON Infinity is deliberately sent as bytes to exercise the parser boundary.
    response = client.post(
        "/api/ingest/aws.guardduty",
        content=canonical(payload),
        headers={**auth("collector"), "Content-Type": "application/json"},
    )
    assert response.status_code == 422


def test_gcp_resource_enrichment_is_retained():
    payload = fixtures()["gcp.scc"]
    payload["resource"] = {
        "project": "projects/synthetic-lab",
        "name": payload["finding"]["resourceName"],
    }
    finding = parse("gcp.scc", payload)[0]
    assert finding.environment == "projects/synthetic-lab"
    assert finding.evidence["_resource"]["project"] == "projects/synthetic-lab"


def test_sysmon_supported_wazuh_collection_contract():
    payload = fixtures()["wazuh"]
    payload["data"] = {
        "win": {
            "system": {"providerName": "Microsoft-Windows-Sysmon", "eventID": "1"},
            "eventdata": {
                "user": "synthetic\\lab-user",
                "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            },
        }
    }
    finding = parse("wazuh", payload, True)[0]
    assert finding.identity == "synthetic\\lab-user" and finding.synthetic


def test_benign_replay_regression(client):
    data = fixtures()["wazuh"]
    data["rule"]["level"] = 2
    assert (
        client.post("/api/ingest/wazuh", json=data, headers=auth("collector")).json()[
            "incident_ids"
        ]
        == []
    )
    report = client.post("/api/replay", headers=auth()).json()
    assert report["events_evaluated"] == 1 and report["detections"] == []


def test_replay_order_deterministic(client, seeded):
    first = client.post("/api/replay", headers=auth()).json()
    second = client.post("/api/replay", headers=auth()).json()
    assert first == second and first["detections"]
