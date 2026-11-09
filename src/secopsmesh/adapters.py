"""Pure provider contracts. Transport authentication lives outside this boundary."""

from __future__ import annotations

import base64
import json
from datetime import datetime
from typing import cast

from .domain import SOURCES, Finding, digest, now, redact, stamp


class AdapterError(ValueError):
    pass


def get(data: dict, path: str, default: object = ""):
    value = data
    for key in path.split("."):
        if not isinstance(value, dict):
            return default
        value = value.get(key, default)
    return value


def bounded(payload: object, depth: int = 0) -> None:
    if depth > 16:
        raise AdapterError("payload nesting exceeds 16")
    if isinstance(payload, dict):
        if len(payload) > 200:
            raise AdapterError("too many object fields")
        for k, v in payload.items():
            if not isinstance(k, str) or len(k) > 1024:
                raise AdapterError("invalid object key")
            bounded(v, depth + 1)
    elif isinstance(payload, list):
        if len(payload) > 100:
            raise AdapterError("batch exceeds 100 items")
        for v in payload:
            bounded(v, depth + 1)
    elif isinstance(payload, str) and len(payload) > 65536:
        raise AdapterError("string exceeds limit")


def records(source: str, payload: dict) -> list[dict]:
    bounded(payload)
    if source not in SOURCES:
        raise AdapterError("unsupported source")
    if "message" in payload:  # GCP Pub/Sub export envelope, authenticated bridge only.
        encoded = get(payload, "message.data")
        try:
            payload = json.loads(base64.b64decode(encoded, validate=True))
        except (ValueError, TypeError) as exc:
            raise AdapterError("invalid Pub/Sub message") from exc
        bounded(payload)
    if "detail" in payload and source.startswith("aws."):
        payload = payload["detail"]
    if source == "aws.securityhub":
        batch = payload.get("findings", payload.get("Findings", [payload]))
    elif source.startswith("azure."):
        batch = payload.get("value", payload.get("records", [payload]))
    elif source == "gcp.scc":
        batch = [payload.get("finding", payload)]
    elif source == "wazuh" and "hits" in payload:
        batch = [hit["_source"] for hit in payload["hits"]["hits"]]
    elif source == "kubernetes.audit":
        batch = payload.get("items", [payload])
    else:
        batch = [payload]
    if (
        not isinstance(batch, list)
        or not batch
        or len(batch) > 100
        or not all(isinstance(v, dict) for v in batch)
    ):
        raise AdapterError("expected 1..100 records")
    return batch


def severity(value: object) -> int:
    if isinstance(value, str):
        levels = {
            "INFORMATIONAL": 10,
            "LOW": 25,
            "MEDIUM": 50,
            "MODERATE": 50,
            "HIGH": 80,
            "CRITICAL": 95,
        }
        if value.upper() in levels:
            return levels[value.upper()]
    try:
        return max(0, min(100, int(float(value))))  # type: ignore[arg-type]
    except (ValueError, TypeError):
        return 40


def normalize(source: str, r: dict, synthetic: bool) -> Finding:
    rid = r.get("id", r.get("name", r.get("Id", "")))
    observed = r.get("updatedAt", r.get("eventTime", r.get("timestamp", r.get("createTime", ""))))
    title, category, asset, identity, environment, namespace = (
        "",
        "",
        "",
        "",
        source.split(".")[0],
        "",
    )
    score, confidence, techniques = 40, 0.75, []
    if source == "aws.guardduty":
        title, category = r.get("title", ""), r.get("type", "")
        asset = get(r, "resource.instanceDetails.instanceId") or get(
            r, "resource.accessKeyDetails.accessKeyId"
        )
        identity = get(r, "resource.accessKeyDetails.userName")
        environment = r.get("accountId", "aws") + ":" + r.get("region", "unknown")
        score = severity(float(r.get("severity", 4)) * 10)
    elif source == "aws.securityhub":
        rid, title = r.get("Id", ""), r.get("Title", "")
        observed = r.get("UpdatedAt", r.get("CreatedAt", ""))
        category = (r.get("Types") or ["securityhub.finding"])[0]
        asset = (r.get("Resources") or [{}])[0].get("Id", "")
        score = severity(get(r, "Severity.Label", get(r, "Severity.Normalized", 40)))
        identity = get(r, "UserIdentity.PrincipalId")
        environment = r.get("AwsAccountId", "aws")
    elif source == "aws.cloudtrail":
        rid = r.get("eventID", "")
        title, category = r.get("eventName", ""), "cloudtrail." + r.get("eventName", "unknown")
        asset = (
            get(r, "requestParameters.instanceId") or get(r, "resources", [{}])[0].get("ARN", "")
            if r.get("resources")
            else get(r, "requestParameters.instanceId")
        )
        asset = asset or r.get("recipientAccountId", "")
        identity = get(r, "userIdentity.arn") or get(r, "userIdentity.principalId")
        score = (
            85 if title in {"StopLogging", "DeleteTrail", "DisableKey", "PutBucketPolicy"} else 25
        )
        if title in {"StopLogging", "DeleteTrail"}:
            techniques = ["T1562.008"]
    elif source.startswith("azure."):
        p = r.get("properties", r)
        rid = r.get("id", p.get("systemAlertId", p.get("SystemAlertId", r.get("operationId", ""))))
        title = p.get(
            "alertDisplayName",
            p.get(
                "displayName", p.get("title", p.get("operationName", r.get("operationName", "")))
            ),
        )
        category = p.get("alertType", p.get("assessmentType", "azure." + source.split(".")[1]))
        observed = p.get(
            "timeGeneratedUtc",
            p.get(
                "lastModifiedTimeUtc",
                p.get("startTimeUtc", get(p, "status.firstEvaluationDate", r.get("time", ""))),
            ),
        )
        asset = (
            get(p, "resourceDetails.Id")
            or get(p, "resourceIdentifiers", [{}])[0].get("azureResourceId", "")
            if p.get("resourceIdentifiers")
            else get(p, "resourceDetails.Id")
        )
        asset = asset or get(p, "resourceDetails.id") or r.get("resourceId", "")
        identity = p.get("compromisedEntity", "")
        score = severity(p.get("severity", get(p, "metadata.severity", "MEDIUM")))
        environment = "azure:" + r.get("subscriptionId", "unknown")
    elif source == "gcp.scc":
        title = r.get("category", "")
        category, asset = title, r.get("resourceName", "")
        observed = r.get("eventTime", r.get("createTime", ""))
        score = severity(r.get("severity", "MEDIUM"))
        identity = get(r, "sourceProperties.principalEmail")
    elif source == "gcp.audit":
        rid, observed = r.get("insertId", ""), r.get("timestamp", "")
        title = get(r, "protoPayload.methodName")
        category, asset = "audit." + title, get(r, "protoPayload.resourceName")
        identity = get(r, "protoPayload.authenticationInfo.principalEmail")
        score = 85 if "SetIamPolicy" in title or "setIamPolicy" in title else 25
    elif source == "wazuh":
        title, category = get(r, "rule.description"), "wazuh." + str(get(r, "rule.id"))
        asset = str(get(r, "agent.id"))
        identity = (
            get(r, "data.win.eventdata.user") or get(r, "data.srcuser") or get(r, "data.dstuser")
        )
        score = severity(int(get(r, "rule.level", 6)) * 100 / 15)
        raw_techniques = get(r, "rule.mitre.id", [])
        techniques = [t for t in raw_techniques if isinstance(t, str) and t.startswith("T")][:16]
    elif source == "kubernetes.audit":
        rid, observed = (
            r.get("auditID", ""),
            r.get("stageTimestamp", r.get("requestReceivedTimestamp", "")),
        )
        title = str(r.get("verb", "")) + " " + str(get(r, "objectRef.resource"))
        category = (
            "k8s."
            + str(r.get("verb", ""))
            + "."
            + str(get(r, "objectRef.subresource") or get(r, "objectRef.resource"))
        )
        namespace = get(r, "objectRef.namespace")
        asset = get(r, "objectRef.uid") or get(r, "objectRef.name")
        identity = get(r, "user.username")
        score = 85 if category in {"k8s.create.exec", "k8s.get.secrets"} else 25
        if category == "k8s.create.exec":
            techniques = ["T1609"]
    elif source == "kubernetes.tetragon":
        process = get(r, "process_exec.process", {}) or get(r, "process_kprobe.process", {})
        rid = r.get("id") or digest(r)
        observed = r.get("time", "")
        title = str(process.get("binary", ""))
        category = "runtime.exec" if "process_exec" in r else "runtime.kprobe"
        namespace = get(process, "pod.namespace")
        asset = get(process, "pod.name")
        identity = get(process, "pod.workload") or get(process, "pod.container.name")
        score = 85 if title.rsplit("/", 1)[-1] in {"sh", "bash", "nc", "ncat"} else 25
    quality = []
    if not asset:
        asset = "unknown:" + str(rid)
        quality.append("missing_asset")
        confidence -= 0.25
    if not identity:
        quality.append("missing_identity")
    if not observed or not rid or not title:
        raise AdapterError("record requires source id, timestamp and title")
    try:
        dt = datetime.fromisoformat(str(observed).replace("Z", "+00:00"))
        age = (now() - dt).total_seconds()
    except (ValueError, TypeError) as exc:
        raise AdapterError("invalid or timezone-naive timestamp") from exc
    if age > 86400:
        quality.append("stale_evidence")
        confidence -= 0.15
    if age < -300:
        quality.append("future_timestamp")
        confidence -= 0.25
    clean_title = str(redact(title))[:512]
    origin_ref = ""
    if source == "aws.guardduty":
        origin_ref = r.get("arn", "")
    elif source == "aws.securityhub" and ":guardduty:" in str(rid):
        origin_ref = str(rid)
    return Finding(
        source=source,
        source_id=str(rid),
        origin_ref=origin_ref,
        observed_at=str(observed),
        received_at=stamp(),
        title=clean_title,
        category=str(category),
        severity=score,
        risk=score,
        confidence=max(0.1, confidence),
        asset=str(asset),
        identity=str(identity),
        environment=str(environment),
        namespace=str(namespace),
        techniques=techniques,
        quality=quality,
        synthetic=synthetic,
        evidence=cast(dict, redact(r)),
    )


def parse(source: str, payload: dict, synthetic: bool = False) -> list[Finding]:
    try:
        return [normalize(source, row, synthetic) for row in records(source, payload)]
    except (KeyError, TypeError, AttributeError, IndexError, OverflowError) as exc:
        raise AdapterError("provider record does not match the supported contract") from exc
