"""Read-only provider bridges. Checkpoint only after successful API ingestion."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import httpx

from .domain import SOURCES, canonical
from .transport import AWSPoller, ProviderHTTP, WazuhIndexer


def save_checkpoint(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".new")
    temporary.write_text(canonical(value))
    temporary.chmod(0o600)
    temporary.replace(path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", choices=SOURCES)
    parser.add_argument(
        "--checkpoint", type=Path, default=Path(".runtime/provider-checkpoint.json")
    )
    parser.add_argument("--api", default="http://127.0.0.1:8080")
    parser.add_argument("--max-pages", type=int, default=20)
    parser.add_argument("--eventhub", action="store_true")
    parser.add_argument("--pubsub", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.max_pages <= 100:
        parser.error("max-pages must be 1..100")
    checkpoint = json.loads(args.checkpoint.read_text()) if args.checkpoint.exists() else {}
    if checkpoint.get("source", args.source) != args.source:
        parser.error("use a separate checkpoint file for each source")
    client = httpx.Client(
        base_url=args.api,
        headers={"Authorization": "Bearer " + os.environ["SECMESH_COLLECTOR_TOKEN"]},
        timeout=30,
        follow_redirects=False,
        trust_env=False,
    )

    def submit(row: dict) -> None:
        result = client.post("/api/ingest/" + args.source, json=row)
        result.raise_for_status()

    if args.eventhub:
        if args.source not in {"azure.defender", "azure.monitor", "azure.recommendation"}:
            parser.error("Event Hubs supports Azure exported records")
        from azure.eventhub import EventHubConsumerClient
        from azure.identity import DefaultAzureCredential

        consumer = EventHubConsumerClient(
            fully_qualified_namespace=os.environ["AZURE_EVENTHUB_NAMESPACE"],
            eventhub_name=os.environ["AZURE_EVENTHUB_NAME"],
            consumer_group=os.environ.get("AZURE_EVENTHUB_GROUP", "$Default"),
            credential=DefaultAzureCredential(),
            retry_total=3,
            socket_timeout=10,
        )

        def on_event(context, event):
            if event is None:
                return
            submit(json.loads(event.body_as_str()))
            checkpoint[context.partition_id] = str(event.offset)
            save_checkpoint(args.checkpoint, {**checkpoint, "source": args.source})

        try:
            consumer.receive(
                on_event=on_event,
                starting_position={k: v for k, v in checkpoint.items() if k != "source"} or "-1",
                max_wait_time=5,
            )
        finally:
            consumer.close()
        return
    if args.pubsub:
        if args.source not in {"gcp.scc", "gcp.audit"}:
            parser.error("Pub/Sub bridge requires a GCP source")
        import google.auth
        from google.auth.transport.requests import Request

        credential, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/pubsub"])

        def token():
            if not credential.valid:
                credential.refresh(Request())
            return credential.token

        transport = ProviderHTTP("https://pubsub.googleapis.com", token)
        subscription = os.environ["GCP_SUBSCRIPTION"]
        import re

        if not re.fullmatch(r"projects/[a-z0-9-]+/subscriptions/[A-Za-z0-9._~-]+", subscription):
            parser.error("invalid subscription resource name")
        path = "/v1/" + subscription
        for _ in range(args.max_pages):
            response = transport.request("POST", path + ":pull", {"maxMessages": 50})
            messages = response.get("receivedMessages", [])
            for envelope in messages:
                submit({"message": envelope["message"]})
                transport.request("POST", path + ":acknowledge", {"ackIds": [envelope["ackId"]]})
            if not messages:
                break
        transport.close()
    elif args.source.startswith("aws."):
        import boto3
        from botocore.config import Config

        service = {
            "aws.guardduty": "guardduty",
            "aws.securityhub": "securityhub",
            "aws.cloudtrail": "cloudtrail",
        }[args.source]
        provider = boto3.client(
            service,
            config=Config(
                connect_timeout=5,
                read_timeout=15,
                retries={"max_attempts": 3, "mode": "standard"},
                ignore_configured_endpoint_urls=True,
            ),
        )
        poller = AWSPoller(provider, args.source, os.environ.get("AWS_GUARDDUTY_DETECTOR_ID", ""))
        cursor = checkpoint.get("cursor")
        for _ in range(args.max_pages):
            rows, cursor = poller.page(cursor)
            for row in rows:
                submit(row)
            save_checkpoint(args.checkpoint, {"source": args.source, "cursor": cursor})
            if not cursor:
                break
    elif args.source.startswith("azure."):
        from azure.identity import DefaultAzureCredential

        azure_credential = DefaultAzureCredential()
        transport = ProviderHTTP(
            "https://management.azure.com",
            lambda: azure_credential.get_token("https://management.azure.com/.default").token,
        )
        resource = os.environ["AZURE_RESOURCE_PATH"].rstrip("/")
        if args.source == "azure.sentinel.alert":
            response = transport.request(
                "POST", resource + "/alerts?api-version=2025-09-01", prefix=resource + "/"
            )
            for row in response.get("value", []):
                submit(row)
            transport.close()
            client.close()
            return
        suffix = {
            "azure.defender": "/providers/Microsoft.Security/alerts?api-version=2022-01-01&$top=100",
            "azure.recommendation": "/providers/Microsoft.Security/assessments?api-version=2020-01-01&$top=100",
            "azure.sentinel": "/providers/Microsoft.SecurityInsights/incidents?api-version=2025-09-01&$top=100",
        }.get(args.source)
        if suffix is None:
            parser.error("Azure Monitor ingestion uses --eventhub")
        for rows, cursor in transport.pages(
            resource + suffix, resource + "/", checkpoint.get("cursor"), args.max_pages
        ):
            for row in rows:
                submit(row)
            save_checkpoint(args.checkpoint, {"source": args.source, "cursor": cursor})
        transport.close()
    elif args.source == "gcp.scc":
        import google.auth
        from google.auth.transport.requests import Request

        credential, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )

        def scc_token():
            if not credential.valid:
                credential.refresh(Request())
            return credential.token

        transport = ProviderHTTP("https://securitycenter.googleapis.com", scc_token)
        resource = os.environ["GCP_SCC_PARENT"]
        import re

        if not re.fullmatch(
            r"(organizations|projects)/[a-zA-Z0-9-]+/sources/[a-zA-Z0-9-]+", resource
        ):
            parser.error("invalid SCC v1 parent")
        cursor = checkpoint.get("cursor")
        for _ in range(args.max_pages):
            path = (
                "/v1/"
                + resource
                + "/findings?"
                + str(
                    httpx.QueryParams(
                        {"pageSize": 100, **({"pageToken": cursor} if cursor else {})}
                    )
                )
            )
            response = transport.request("GET", path)
            for result in response.get("listFindingsResults", []):
                submit(result)
            cursor = response.get("nextPageToken")
            save_checkpoint(args.checkpoint, {"source": args.source, "cursor": cursor})
            if not cursor:
                break
        transport.close()
    elif args.source == "wazuh":
        indexer = WazuhIndexer(
            os.environ["WAZUH_INDEXER_URL"],
            os.environ["WAZUH_INDEXER_USER"],
            os.environ["WAZUH_INDEXER_PASSWORD"],
            os.environ.get("WAZUH_CA_FILE", True),
        )
        cursor = checkpoint.get("cursor")
        for _ in range(args.max_pages):
            page, next_cursor = indexer.page(cursor)
            if not page["hits"]["hits"]:
                break
            submit(page)
            save_checkpoint(args.checkpoint, {"source": args.source, "cursor": next_cursor})
            cursor = next_cursor
        indexer.close()
    else:
        parser.error(
            "this source uses the authenticated webhook/forwarder transport; see docs/CONNECTORS.md"
        )
    client.close()


if __name__ == "__main__":
    main()
