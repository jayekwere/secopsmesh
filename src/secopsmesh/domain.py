from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

SOURCES = (
    "aws.guardduty",
    "aws.securityhub",
    "aws.cloudtrail",
    "azure.defender",
    "azure.recommendation",
    "azure.monitor",
    "azure.sentinel",
    "azure.sentinel.alert",
    "gcp.scc",
    "gcp.audit",
    "wazuh",
    "kubernetes.audit",
    "kubernetes.tetragon",
)
SECRET = re.compile(r"password|secret|token|authorization|credential|api.?key|private.?key", re.I)


def now() -> datetime:
    return datetime.now(UTC)


def stamp() -> str:
    return now().isoformat()


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def redact(value: object, depth: int = 0) -> object:
    if depth > 12:
        return "[depth limited]"
    if isinstance(value, dict):
        return {
            str(k): "[REDACTED]" if SECRET.search(str(k)) else redact(v, depth + 1)
            for k, v in list(value.items())[:100]
        }
    if isinstance(value, list):
        return [redact(v, depth + 1) for v in value[:100]]
    if isinstance(value, str):
        value = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", value)
        value = re.sub(
            r"(?i)(password|secret|token|api_key)\s*[=:]\s*[^\s,;]+", r"\1=[REDACTED]", value
        )
        value = re.sub(r"AKIA[A-Z0-9]{16}", "[REDACTED_AWS_KEY]", value)
        return value[:4096]
    return value


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["1.0"] = "1.0"
    source: str = Field(max_length=64)
    source_id: str = Field(min_length=1, max_length=1024)
    origin_ref: str = Field(default="", max_length=2048)
    observed_at: str
    received_at: str
    title: str = Field(min_length=1, max_length=512)
    category: str = Field(min_length=1, max_length=128)
    severity: int = Field(ge=0, le=100)
    risk: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1)
    asset: str = Field(min_length=1, max_length=1024)
    identity: str = Field(max_length=1024)
    environment: str = Field(max_length=128)
    namespace: str = Field(default="", max_length=253)
    collector_instance: str = Field(default="default", min_length=1, max_length=128)
    techniques: list[str] = Field(default_factory=list, max_length=16)
    quality: list[str] = Field(default_factory=list, max_length=16)
    synthetic: bool
    evidence: dict

    @field_validator("observed_at", "received_at")
    @classmethod
    def aware_time(cls, value: str) -> str:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            raise ValueError("timezone is required")
        return dt.astimezone(UTC).isoformat()

    @field_validator("source")
    @classmethod
    def known_source(cls, value: str) -> str:
        if value not in SOURCES:
            raise ValueError("unknown source")
        return value


class PlanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    incident_id: str = Field(min_length=1, max_length=64)
    target: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_.-]+$")
    action: Literal["contain", "rollback"] = "contain"
    original_action_id: str | None = Field(default=None, max_length=64)


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")


class ToolRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Literal["incident_evidence", "asset_timeline"]
    incident_id: str = Field(max_length=64)


class AISummary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str = Field(min_length=1, max_length=3000)
    evidence_ids: list[str] = Field(min_length=1, max_length=30)
    next_steps: list[str] = Field(max_length=8)
    recommendations: list[str] = Field(max_length=8)

    @field_validator("next_steps", "recommendations")
    @classmethod
    def bounded_items(cls, value: list[str]) -> list[str]:
        if any(len(v) > 500 for v in value):
            raise ValueError("item too long")
        return value
