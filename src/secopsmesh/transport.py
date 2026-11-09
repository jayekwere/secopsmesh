"""Bounded read-only provider transports with same-origin pagination."""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterator
from urllib.parse import unquote, urljoin, urlparse

import httpx

from .adapters import AdapterError, bounded


class ProviderHTTP:
    def __init__(
        self,
        origin: str,
        token: Callable[[], str],
        client: httpx.Client | None = None,
        allowed_hosts: frozenset[str] = frozenset(
            {
                "management.azure.com",
                "securitycenter.googleapis.com",
                "logging.googleapis.com",
                "pubsub.googleapis.com",
            }
        ),
    ):
        parsed = urlparse(origin)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in allowed_hosts
            or parsed.username
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise AdapterError("provider origin is not allowlisted HTTPS")
        self.origin, self.token = origin.rstrip("/"), token
        self.client = client or httpx.Client(
            timeout=httpx.Timeout(15, connect=5), follow_redirects=False, trust_env=False
        )

    def url(self, path: str, prefix: str = "/") -> str:
        url = urljoin(self.origin + "/", path)
        parsed, configured = urlparse(url), urlparse(self.origin)
        if (
            (parsed.scheme, parsed.netloc) != (configured.scheme, configured.netloc)
            or parsed.username
            or parsed.fragment
        ):
            raise AdapterError("cross-origin pagination denied")
        if not unquote(parsed.path).startswith(prefix) or ".." in unquote(parsed.path).split("/"):
            raise AdapterError("pagination escaped configured resource")
        return url

    def request(
        self, method: str, path: str, payload: dict | None = None, prefix: str = "/"
    ) -> dict:
        if method not in {"GET", "POST"}:
            raise AdapterError("unsupported provider operation")
        url = self.url(path, prefix)
        for attempt in range(3):
            try:
                with self.client.stream(
                    method, url, headers={"Authorization": "Bearer " + self.token()}, json=payload
                ) as response:
                    if response.status_code in {429, 502, 503, 504} and attempt < 2:
                        time.sleep(min(0.1 * 2**attempt, 0.4))
                        continue
                    response.raise_for_status()
                    body = b""
                    for chunk in response.iter_bytes():
                        body += chunk
                        if len(body) > 1048576:
                            raise AdapterError("provider response exceeds 1 MiB")
                result = json.loads(body)
                if not isinstance(result, dict):
                    raise AdapterError("expected provider object")
                return result
            except (httpx.TimeoutException, httpx.NetworkError):
                if attempt == 2:
                    raise
                time.sleep(0.1 * 2**attempt)
        raise AdapterError("provider retry budget exhausted")

    def pages(
        self, path: str, prefix: str, cursor: str | None = None, max_pages: int = 20
    ) -> Iterator[tuple[list[dict], str | None]]:
        if not 1 <= max_pages <= 100:
            raise AdapterError("invalid page budget")
        next_path: str | None = cursor or path
        seen = set()
        for _ in range(max_pages):
            if not next_path:
                break
            if next_path in seen:
                raise AdapterError("pagination cycle")
            seen.add(next_path)
            response = self.request("GET", next_path, prefix=prefix)
            rows = response.get("value", [])
            if not isinstance(rows, list) or len(rows) > 100:
                raise AdapterError("provider page exceeds 100 records")
            bounded(rows)
            next_path = response.get("nextLink")
            if next_path:
                self.url(next_path, prefix)
            yield rows, next_path
            if not next_path:
                break

    def close(self) -> None:
        self.client.close()


class WazuhIndexer:
    def __init__(
        self,
        origin: str,
        username: str,
        password: str,
        ca_file: str | bool = True,
        client: httpx.Client | None = None,
    ):
        parsed = urlparse(origin)
        if (
            parsed.scheme != "https"
            or parsed.username
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise AdapterError("indexer requires an operator-configured HTTPS origin")
        self.origin = origin.rstrip("/")
        if ca_file is False:
            raise AdapterError("TLS verification cannot be disabled")
        self.client = client or httpx.Client(
            auth=(username, password),
            verify=ca_file,
            timeout=15,
            follow_redirects=False,
            trust_env=False,
        )

    def page(self, checkpoint: list | None = None) -> tuple[dict, list | None]:
        body = {
            "size": 100,
            "sort": [{"timestamp": "asc"}, {"id": "asc"}],
            "query": {"range": {"timestamp": {"gte": "now-24h"}}},
        }
        if checkpoint:
            body["search_after"] = checkpoint
        with self.client.stream(
            "POST", self.origin + "/wazuh-alerts-4.x-*/_search", json=body
        ) as response:
            response.raise_for_status()
            content = b""
            for chunk in response.iter_bytes():
                content += chunk
                if len(content) > 1048576:
                    raise AdapterError("indexer response exceeds 1 MiB")
        result = json.loads(content)
        rows = result.get("hits", {}).get("hits", [])
        if len(rows) > 100:
            raise AdapterError("indexer page exceeds limit")
        bounded(rows)
        return result, rows[-1]["sort"] if rows else checkpoint

    def close(self) -> None:
        self.client.close()


class AWSPoller:
    def __init__(self, client, source: str, detector_id: str = ""):
        self.client, self.source, self.detector = client, source, detector_id

    def page(self, cursor: str | None = None) -> tuple[list[dict], str | None]:
        args = {"NextToken": cursor} if cursor else {}
        if self.source == "aws.guardduty":
            result = self.client.list_findings(DetectorId=self.detector, MaxResults=50, **args)
            ids = result.get("FindingIds", [])
            if len(ids) > 50:
                raise AdapterError("GuardDuty page exceeds limit")
            rows = (
                self.client.get_findings(DetectorId=self.detector, FindingIds=ids).get(
                    "Findings", []
                )
                if ids
                else []
            )

            def eventbridge_case(value):
                if isinstance(value, dict):
                    return {k[0].lower() + k[1:]: eventbridge_case(v) for k, v in value.items()}
                if isinstance(value, list):
                    return [eventbridge_case(v) for v in value]
                return value

            rows = eventbridge_case(rows)
        elif self.source == "aws.securityhub":
            result = self.client.get_findings(MaxResults=50, **args)
            rows = result.get("Findings", [])
        elif self.source == "aws.cloudtrail":
            result = self.client.lookup_events(MaxResults=50, **args)
            rows = [json.loads(e["CloudTrailEvent"]) for e in result.get("Events", [])]
        else:
            raise AdapterError("unsupported AWS polling source")
        if len(rows) > 50:
            raise AdapterError("AWS response exceeds page limit")
        # boto3 timestamps are converted before sending the versioned JSON contract.
        rows = json.loads(json.dumps(rows, default=lambda v: v.isoformat()))
        bounded(rows)
        return rows, result.get("NextToken")
