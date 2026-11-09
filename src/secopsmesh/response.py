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
        self.baseline: dict | None = None
        if target.get("ca_file") is False or target.get("probe_ca_file") is False:
            raise ResponseError("Kubernetes TLS verification cannot be disabled")
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
        self.probe_client = client or httpx.Client(
            timeout=5,
            follow_redirects=False,
            trust_env=False,
            verify=target.get("probe_ca_file", True),
        )
        origin = urlparse(target["url"])
        if (
            origin.scheme != "https"
            or origin.username
            or origin.query
            or origin.fragment
            or origin.path not in {"", "/"}
        ):
            raise ResponseError("Kubernetes requires a configured HTTPS origin")
        if target.get("probe_url"):
            probe_origin = urlparse(target["probe_url"])
            if (
                probe_origin.username
                or probe_origin.query
                or probe_origin.fragment
                or probe_origin.scheme not in {"http", "https"}
            ):
                raise ResponseError("invalid probe origin")
            if probe_origin.scheme == "http" and probe_origin.hostname not in {
                "127.0.0.1",
                "localhost",
            }:
                raise ResponseError("plaintext probe requires a loopback lab endpoint")
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

    def probe(self) -> dict:
        if not self.target.get("probe_url"):
            raise ResponseError("independent packet probe is required")
        response = self.probe_client.get(self.target["probe_url"], headers={"Authorization": ""})
        response.raise_for_status()
        if len(response.content) > 4096:
            raise ResponseError("probe response exceeds budget")
        proof = response.json()
        if (
            proof.get("schema_version") != "1.0"
            or proof.get("target") != self.target["label"]
            or type(proof.get("reachable")) is not bool
            or type(proof.get("control_reachable")) is not bool
        ):
            raise ResponseError("probe contract or target mismatch")
        return {**proof, "checked_at": now().isoformat()}

    def preflight(self, plan: dict) -> dict:
        proof = self.probe()
        expected = plan["action"] == "contain"
        reason = "http_200" if expected else "timeout"
        if (
            proof["control_reachable"] is not True
            or proof["reachable"] is not expected
            or proof.get("reason") != reason
        ):
            raise ResponseError("positive baseline/control measurement is required before response")
        self.baseline = proof
        return proof

    def apply(self, plan: dict) -> dict:
        if self.baseline is None:
            raise ResponseError("durable preflight evidence is required")
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
        proof: dict = {}
        if self.target.get("probe_url"):
            proof = self.probe()
            reachable = proof["reachable"]
        expected_reachable = plan["action"] == "rollback"
        baseline = self.baseline or {}
        baseline_ok = (
            bool(baseline)
            and baseline.get("target") == self.target["label"]
            and baseline.get("control_reachable") is True
            and baseline.get("reachable") is (not expected_reachable)
        )
        reason_ok = proof.get("reason") == ("http_200" if expected_reachable else "timeout")
        return {
            "verified": policy_ok
            and baseline_ok
            and proof.get("control_reachable") is True
            and reachable is expected_reachable
            and reason_ok,
            "policy_readback": policy_ok,
            "baseline_present": baseline_ok,
            "probe": proof,
            "reachable": reachable,
            "enforcement": "packet probe" if reachable is not None else "unverified",
            "checked_at": now().isoformat(),
        }

    def close(self) -> None:
        self.client.close()
        if self.probe_client is not self.client:
            self.probe_client.close()


def response_adapter(target: dict):
    if target["kind"] == "lab":
        return LabResponse(target)
    if target["kind"] == "kubernetes":
        return KubernetesResponse(target)
    raise ResponseError("unsupported response capability")
