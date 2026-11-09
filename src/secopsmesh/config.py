from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

ROLES = {"observer", "collector", "analyst", "approver", "executor"}


@dataclass(frozen=True)
class Principal:
    name: str
    tenant: str
    roles: frozenset[str]
    sources: frozenset[str] = frozenset()
    synthetic: bool = False
    instance: str = "default"


@dataclass
class Settings:
    database_url: str
    signing_key: bytes
    credentials: dict[str, Principal]
    aliases: dict[str, dict[str, str]] = field(default_factory=dict)
    targets: dict[str, dict] = field(default_factory=dict)
    rules_dir: Path = Path("detections")
    ai_enabled: bool = False
    ai_key: str = ""
    ai_model: str = "claude-sonnet-4-5-20250929"
    ai_daily_budget_usd: float = 1.0
    webhook_keys: dict[str, str] = field(default_factory=dict)
    auto_propose: bool = False
    service_mode: str = "api"
    executor_url: str = ""

    def __post_init__(self) -> None:
        if len(self.signing_key) < 32:
            raise ValueError("signing key must contain at least 32 bytes")
        if not self.credentials:
            raise ValueError("at least one credential is required")
        if self.service_mode not in {"api", "executor", "embedded-test"}:
            raise ValueError("unsupported service mode")
        for digest, p in self.credentials.items():
            if len(digest) != 64 or not p.name or not p.tenant or not p.roles <= ROLES:
                raise ValueError("invalid principal configuration")
        for target in self.targets.values():
            if not target.get("tenant") or target.get("kind") not in {"lab", "kubernetes"}:
                raise ValueError("invalid target inventory")

    @classmethod
    def from_env(cls) -> Settings:
        key = os.environ.get("SECMESH_SIGNING_KEY", "").encode()
        raw = json.loads(os.environ.get("SECMESH_CREDENTIALS", "{}"))
        credentials = {
            digest: Principal(
                name=value["name"],
                tenant=value["tenant"],
                roles=frozenset(value["roles"]),
                sources=frozenset(value.get("sources", [])),
                synthetic=value.get("synthetic", False),
                instance=value.get("instance", "default"),
            )
            for digest, value in raw.items()
        }
        return cls(
            database_url=os.environ.get("SECMESH_DATABASE_URL", "sqlite:///./.runtime/mesh.db"),
            signing_key=key,
            credentials=credentials,
            aliases=json.loads(os.environ.get("SECMESH_ALIASES", "{}")),
            targets=json.loads(os.environ.get("SECMESH_TARGETS", "{}")),
            ai_enabled=os.environ.get("SECMESH_AI_ENABLED") == "true",
            ai_key=os.environ.get("ANTHROPIC_API_KEY", ""),
            ai_model=os.environ.get("SECMESH_AI_MODEL", "claude-sonnet-4-5-20250929"),
            webhook_keys=json.loads(os.environ.get("SECMESH_WEBHOOK_KEYS", "{}")),
            auto_propose=os.environ.get("SECMESH_AUTO_PROPOSE") == "true",
            service_mode=os.environ.get("SECMESH_SERVICE_MODE", "api"),
            executor_url=os.environ.get("SECMESH_EXECUTOR_URL", ""),
        )


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
