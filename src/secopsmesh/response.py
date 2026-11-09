from __future__ import annotations

import hashlib
import hmac
import re
from pathlib import Path
from urllib.parse import urlparse

import httpx

from .domain import canonical, digest, now


class ResponseError(RuntimeError):
    pass


def service_signature(key: str, timestamp: str, body: bytes) -> str:
    return hmac.new(key.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()


class LabResponse:
    def __init__(self, target: dict, client: httpx.Client | None = None):
        self.target = target
        self.client = client or httpx.Client(timeout=5, follow_redirects=False, trust_env=False)
        parsed = urlparse(target["url"])
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.username
            or parsed.query
            or parsed.fragment
        ):
            raise ResponseError("invalid lab origin")
        if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "lab"}:
            raise ResponseError("plaintext response transport is restricted to the isolated lab")

    def apply(self, plan: dict) -> dict:
        command = {
            "id": plan["id"],
            "action": plan["action"],
            "original_action_id": plan["original_action_id"],
        }
        body = canonical(command).encode()
        timestamp = str(int(now().timestamp()))
        response = self.client.post(
            self.target["url"] + "/control",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Mesh-Time": timestamp,
                "X-Mesh-Signature": service_signature(self.target["key"], timestamp, body),
            },
        )
        response.raise_for_status()
        return {"receipt": response.json(), "kind": "lab.application-gate"}

    def verify(self, plan: dict) -> dict:
        response = self.client.get(self.target["url"] + "/work")
        expected = 403 if plan["action"] == "contain" else 200
        # A separate unauthenticated request tests the application's data path.
        owner = response.headers.get("X-Mesh-Owner", "")
        good_owner = owner == plan["id"] if plan["action"] == "contain" else not owner
        return {
            "verified": response.status_code == expected and good_owner,
            "observed_status": response.status_code,
            "expected_status": expected,
            "owner": owner,
            "enforcement": "application traffic gate",
            "checked_at": now().isoformat(),
        }

    def close(self) -> None:
        self.client.close()


class KubernetesResponse:
    """Only Cilium deny policies for an exact operator-owned lab label are writable."""

    def __init__(self, target: dict, client: httpx.Client | None = None):
        self.target = target
        if not re.fullmatch(r"secopsmesh-lab(?:-[a-z0-9-]+)?", target["namespace"]):
            raise ResponseError("namespace is not a disposable lab")
        if not re.fullmatch(
            r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,61}[a-zA-Z0-9]|[a-zA-Z0-9]", target.get("label", "")
        ):
            raise ResponseError("exact target label is required")
        self.client = client or httpx.Client(
            timeout=5,
            follow_redirects=False,
            trust_env=False,
            verify=target.get("ca_file", True),
            headers={"Authorization": "Bearer " + Path(target["token_file"]).read_text().strip()},
        )
        origin = urlparse(target["url"])
        if origin.scheme != "https" or origin.username or origin.query or origin.fragment:
            raise ResponseError("Kubernetes requires a configured HTTPS origin")
        self.name = "mesh-" + digest(target["label"])[:20]
        self.collection = (
            target["url"].rstrip("/")
            + "/apis/cilium.io/v2/namespaces/"
            + target["namespace"]
            + "/ciliumnetworkpolicies"
        )

    def policy(self, plan: dict) -> dict:
        return {
            "apiVersion": "cilium.io/v2",
            "kind": "CiliumNetworkPolicy",
            "metadata": {
                "name": self.name,
                "namespace": self.target["namespace"],
                "annotations": {
                    "secopsmesh.io/action": plan["id"],
                    "secopsmesh.io/plan": digest(plan),
                },
            },
            "spec": {
                "endpointSelector": {"matchLabels": {"secopsmesh.io/target": self.target["label"]}},
                "ingressDeny": [{"fromEntities": ["all"]}],
                "egressDeny": [{"toEntities": ["all"]}],
            },
        }

    def apply(self, plan: dict) -> dict:
        if plan["action"] == "contain":
            expected = self.policy(plan)
            response = self.client.post(self.collection, json=expected)
            if response.status_code == 409:
                existing = self.client.get(self.collection + "/" + self.name)
                existing.raise_for_status()
                data = existing.json()
                if (
                    data.get("spec") != expected["spec"]
                    or data["metadata"].get("annotations") != expected["metadata"]["annotations"]
                ):
                    raise ResponseError("existing policy belongs to another action")
                response = existing
        else:
            existing = self.client.get(self.collection + "/" + self.name)
            if existing.status_code == 404:
                return {"already_absent": True}
            existing.raise_for_status()
            meta = existing.json()["metadata"]
            if (
                meta.get("annotations", {}).get("secopsmesh.io/action")
                != plan["original_action_id"]
            ):
                raise ResponseError("rollback does not own this policy")
            response = self.client.request(
                "DELETE",
                self.collection + "/" + self.name,
                json={
                    "apiVersion": "v1",
                    "kind": "DeleteOptions",
                    "preconditions": {
                        "uid": meta["uid"],
                        "resourceVersion": meta["resourceVersion"],
                    },
                },
            )
        response.raise_for_status()
        return {"kind": "cilium.deny-policy", "policy": self.name, "status": response.status_code}

    def verify(self, plan: dict) -> dict:
        response = self.client.get(self.collection + "/" + self.name)
        if plan["action"] == "contain":
            expected = self.policy(plan)
            policy_ok = (
                response.status_code == 200
                and response.json().get("spec") == expected["spec"]
                and response.json().get("metadata", {}).get("annotations")
                == expected["metadata"]["annotations"]
            )
        else:
            policy_ok = response.status_code == 404
        # Policy existence alone never establishes datapath enforcement.
        reachable = None
        if self.target.get("probe_url"):
            probe = self.client.get(self.target["probe_url"], headers={"Authorization": ""})
            probe.raise_for_status()
            reachable = probe.json().get("reachable")
        expected_reachable = plan["action"] == "rollback"
        return {
            "verified": policy_ok and reachable is expected_reachable,
            "policy_readback": policy_ok,
            "reachable": reachable,
            "enforcement": "packet probe" if reachable is not None else "unverified",
            "checked_at": now().isoformat(),
        }

    def close(self) -> None:
        self.client.close()


def response_adapter(target: dict):
    if target["kind"] == "lab":
        return LabResponse(target)
    if target["kind"] == "kubernetes":
        return KubernetesResponse(target)
    raise ResponseError("unsupported response capability")
