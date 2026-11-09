"""Deterministic, deny-by-default policy; no expression evaluation or plugins."""

from __future__ import annotations

import hashlib
import hmac
import re
from urllib.parse import urlparse

from .config import Principal, Settings
from .domain import canonical, digest
from .store import Action

POLICY_VERSION = "1.0"


class Denied(ValueError):
    pass


def require(p: Principal, role: str) -> None:
    if role not in p.roles:
        raise Denied("role is not authorized for this operation")


def target_policy(settings: Settings, tenant: str, target_id: str) -> dict:
    target = settings.targets.get(target_id)
    if not target or target["tenant"] != tenant or target.get("enabled") is not True:
        raise Denied("target is not enabled for this tenant")
    origin = urlparse(target.get("url", ""))
    if (
        origin.scheme not in {"http", "https"}
        or not origin.hostname
        or origin.username
        or origin.query
        or origin.fragment
        or origin.path not in {"", "/"}
    ):
        raise Denied("response inventory requires a credential-free fixed origin")
    if target["kind"] == "kubernetes":
        if (
            not re.fullmatch(r"secopsmesh-lab(?:-[a-z0-9-]+)?", target.get("namespace", ""))
            or origin.scheme != "https"
            or target.get("ca_file") is False
        ):
            raise Denied("Kubernetes response requires verified TLS and a disposable lab namespace")
    return target


def target_fingerprint(target: dict) -> str:
    # Bind target identity and scope, allowing credential rotation without changing the action.
    return digest({k: v for k, v in target.items() if k != "key"})


def target_scope(target: dict) -> dict:
    return {
        k: target[k]
        for k in [
            "kind",
            "asset",
            "source_family",
            "environment",
            "collector_instance",
            "namespace",
            "label",
            "url",
        ]
        if k in target
    }


def approval_signature(settings: Settings, row: Action) -> str:
    value = [row.tenant, row.id, row.fingerprint, row.requester, row.approver, row.expires]
    return hmac.new(settings.signing_key, canonical(value).encode(), hashlib.sha256).hexdigest()


def execution_policy(settings: Settings, row: Action, p: Principal, at: float) -> dict:
    require(p, "executor")
    if row.tenant != p.tenant or row.plan.get("tenant") != p.tenant:
        raise Denied("tenant mismatch")
    if row.requester == row.approver or not row.approver:
        raise Denied("independent approval required")
    if p.name in {row.requester, row.approver}:
        raise Denied("executor must be independent of requester and approver")
    # An approver/executor removed from configuration cannot exercise old authority.
    if not any(
        q.name == row.approver and q.tenant == p.tenant and "approver" in q.roles
        for q in settings.credentials.values()
    ):
        raise Denied("approver authority was revoked")
    if row.expires <= at:
        raise Denied("approval expired")
    if digest(row.plan) != row.fingerprint or row.plan.get("policy_version") != POLICY_VERSION:
        raise Denied("action plan fingerprint or policy changed")
    expected = approval_signature(settings, row)
    if not row.approval or not hmac.compare_digest(row.approval, expected):
        raise Denied("invalid approval signature")
    target = target_policy(settings, p.tenant, row.plan["target"])
    if target_fingerprint(target) != row.plan["target_fingerprint"]:
        raise Denied("target configuration changed")
    return target
