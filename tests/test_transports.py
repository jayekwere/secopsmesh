import base64
import copy
import json

import boto3
import httpx
import pytest
from botocore.stub import Stubber
from conftest import auth

from secopsmesh.adapters import AdapterError, parse
from secopsmesh.domain import canonical, now
from secopsmesh.labdata import fixtures
from secopsmesh.response import KubernetesResponse, LabResponse, ResponseError, service_signature
from secopsmesh.transport import AWSPoller, ProviderHTTP, WazuhIndexer


def test_aws_eventbridge_and_gcp_pubsub_envelopes():
    data = fixtures()
    assert parse("aws.guardduty", {"detail": data["aws.guardduty"]})[0].asset == "i-synthetic01"
    encoded = base64.b64encode(canonical(data["gcp.scc"]).encode()).decode()
    assert parse("gcp.scc", {"message": {"data": encoded}})[0].source_id.endswith("lab-scc-001")


def test_invalid_pubsub_and_batch():
    with pytest.raises(AdapterError):
        parse("gcp.scc", {"message": {"data": "%%%"}})
    with pytest.raises(AdapterError):
        parse("aws.securityhub", {"Findings": []})


@pytest.mark.parametrize(
    "url",
    [
        "http://management.azure.com",
        "https://evil.invalid",
        "https://user@management.azure.com",
        "https://management.azure.com/path",
        "https://management.azure.com#evil",
    ],
)
def test_provider_origin_allowlist(url):
    with pytest.raises(AdapterError):
        ProviderHTTP(url, lambda: "synthetic-token")


@pytest.mark.parametrize(
    "path",
    [
        "https://evil.invalid/steal",
        "//evil.invalid/steal",
        "/other/resource",
        "/subscriptions/lab/%2e%2e/secret",
        "https://user@management.azure.com/subscriptions/lab/alerts",
    ],
)
def test_ssrf_pagination_is_denied(path):
    provider = ProviderHTTP("https://management.azure.com", lambda: "synthetic-token")
    with pytest.raises(AdapterError):
        provider.url(path, "/subscriptions/lab/")
    provider.close()


def test_pagination_auth_checkpoint_and_retry():
    calls = []

    def handler(request):
        calls.append(str(request.url))
        assert request.headers["Authorization"] == "Bearer synthetic-token"
        if len(calls) == 1:
            return httpx.Response(503)
        if "page=2" not in str(request.url):
            return httpx.Response(
                200,
                json={
                    "value": [{"id": "one"}],
                    "nextLink": "https://management.azure.com/subscriptions/lab/alerts?page=2",
                },
            )
        return httpx.Response(200, json={"value": [{"id": "two"}]})

    provider = ProviderHTTP(
        "https://management.azure.com",
        lambda: "synthetic-token",
        httpx.Client(transport=httpx.MockTransport(handler)),
    )
    pages = list(provider.pages("/subscriptions/lab/alerts", "/subscriptions/lab/"))
    assert pages[0][1].endswith("page=2") and pages[-1][1] is None
    assert len(calls) == 3


@pytest.mark.parametrize("mode", ["cycle", "redirect", "large", "list", "timeout"])
def test_transport_failure_limits(mode):
    calls = []

    def handler(request):
        calls.append(1)
        if mode == "timeout":
            raise httpx.ReadTimeout("synthetic")
        if mode == "redirect":
            return httpx.Response(302, headers={"location": "https://evil.invalid"})
        if mode == "large":
            return httpx.Response(200, content=b"x" * 1048577)
        if mode == "list":
            return httpx.Response(200, json=[])
        return httpx.Response(200, json={"value": [], "nextLink": "/subscriptions/lab/alerts"})

    provider = ProviderHTTP(
        "https://management.azure.com",
        lambda: "synthetic-token",
        httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises((AdapterError, httpx.HTTPError)):
        list(provider.pages("/subscriptions/lab/alerts", "/subscriptions/lab/"))
    assert len(calls) <= 3


def test_wazuh_indexer_search_after():
    calls = []

    def handler(request):
        body = json.loads(request.content)
        calls.append(body)
        return httpx.Response(
            200, json={"hits": {"hits": [{"_source": fixtures()["wazuh"], "sort": ["time", "id"]}]}}
        )

    indexer = WazuhIndexer(
        "https://indexer.synthetic.invalid",
        "reader",
        "synthetic-password",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    result, checkpoint = indexer.page()
    assert parse("wazuh", result)
    indexer.page(checkpoint)
    assert calls[1]["search_after"] == ["time", "id"]
    assert calls[0]["size"] == 100
    indexer.close()
    with pytest.raises(AdapterError):
        WazuhIndexer("https://indexer.synthetic.invalid", "r", "p", False)


def test_guardduty_sdk_contract_uses_official_model():
    client = boto3.client(
        "guardduty",
        region_name="us-west-2",
        aws_access_key_id="synthetic",
        aws_secret_access_key="synthetic",
    )
    t = now().isoformat()
    row = {
        "AccountId": "000000000000",
        "Arn": "arn:aws:guardduty:us-west-2:000000000000:detector/synthetic/finding/lab",
        "CreatedAt": t,
        "Id": "lab",
        "Region": "us-west-2",
        "Resource": {"InstanceDetails": {"InstanceId": "i-synthetic01"}},
        "SchemaVersion": "2.0",
        "Severity": 8.0,
        "Type": "UnauthorizedAccess:IAMUser/AnomalousBehavior",
        "UpdatedAt": t,
        "Title": "Synthetic SDK alert",
    }
    with Stubber(client) as stub:
        stub.add_response(
            "list_findings",
            {"FindingIds": ["lab"], "NextToken": "next"},
            {"DetectorId": "detector", "MaxResults": 50},
        )
        stub.add_response(
            "get_findings", {"Findings": [row]}, {"DetectorId": "detector", "FindingIds": ["lab"]}
        )
        rows, checkpoint = AWSPoller(client, "aws.guardduty", "detector").page()
        assert checkpoint == "next"
        assert parse("aws.guardduty", rows[0])[0].asset == "i-synthetic01"
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("source", ["aws.securityhub", "aws.cloudtrail"])
def test_aws_readonly_polling(source):
    payload = fixtures()[source]

    class Client:
        def get_findings(self, **kwargs):
            assert kwargs == {"MaxResults": 50, "NextToken": "cursor"}
            return {"Findings": [payload]}

        def lookup_events(self, **kwargs):
            assert kwargs == {"MaxResults": 50, "NextToken": "cursor"}
            return {"Events": [{"CloudTrailEvent": canonical(payload)}]}

    rows, cursor = AWSPoller(Client(), source).page("cursor")
    assert parse(source, rows[0]) and cursor is None


def test_signed_webhook_replay_persisted(client, settings):
    settings.webhook_keys["collector"] = "synthetic-webhook-key-at-least-32bytes"
    body = canonical(fixtures()["wazuh"]).encode()
    timestamp, nonce = str(int(now().timestamp())), "synthetic-nonce-001"
    signature = service_signature(
        settings.webhook_keys["collector"], timestamp, nonce.encode() + b".wazuh." + body
    )
    headers = {
        **auth("collector"),
        "Content-Type": "application/json",
        "X-Mesh-Time": timestamp,
        "X-Mesh-Nonce": nonce,
        "X-Mesh-Signature": signature,
    }
    assert client.post("/api/webhooks/wazuh", content=body, headers=headers).status_code == 200
    assert client.post("/api/webhooks/wazuh", content=body, headers=headers).status_code == 403
    headers["X-Mesh-Nonce"] = "synthetic-nonce-002"
    assert client.post("/api/webhooks/wazuh", content=body, headers=headers).status_code == 403


def test_kubernetes_cilium_contract_and_independent_probe():
    state = {}
    calls = []

    def handler(request):
        calls.append(request.method)
        if request.url.path == "/probe":
            return httpx.Response(200, json={"reachable": not bool(state)})
        if request.method == "POST":
            state.update(json.loads(request.content))
            state["metadata"].update({"uid": "synthetic-uid", "resourceVersion": "1"})
            return httpx.Response(201, json=state)
        if request.method == "DELETE":
            body = json.loads(request.content)
            assert body["preconditions"] == {"uid": "synthetic-uid", "resourceVersion": "1"}
            state.clear()
            return httpx.Response(200, json={})
        return httpx.Response(200 if state else 404, json=copy.deepcopy(state))

    target = {
        "kind": "kubernetes",
        "namespace": "secopsmesh-lab",
        "url": "https://cluster.synthetic.invalid",
        "label": "lab-workload",
        "probe_url": "https://cluster.synthetic.invalid/probe",
    }
    adapter = KubernetesResponse(target, httpx.Client(transport=httpx.MockTransport(handler)))
    plan = {"id": "a" * 32, "action": "contain", "original_action_id": None}
    assert not adapter.verify(plan)["verified"]
    adapter.apply(plan)
    assert adapter.verify(plan)["verified"]
    rollback = {"id": "b" * 32, "action": "rollback", "original_action_id": plan["id"]}
    adapter.apply(rollback)
    assert adapter.verify(rollback)["verified"]
    assert calls.count("POST") == 1 and calls.count("DELETE") == 1


def test_kubernetes_policy_without_probe_is_unverified():
    target = {
        "namespace": "secopsmesh-lab",
        "url": "https://synthetic.invalid",
        "label": "workload",
    }
    adapter = KubernetesResponse(
        target, httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(404, json={})))
    )
    assert adapter.verify({"action": "rollback"})["verified"] is False
    with pytest.raises(ResponseError):
        KubernetesResponse({**target, "namespace": "production"}, httpx.Client())
    with pytest.raises(ResponseError):
        LabResponse({"url": "http://evil.invalid"})
