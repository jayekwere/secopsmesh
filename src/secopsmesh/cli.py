from __future__ import annotations

import argparse
import json
import os
import secrets
import time
from pathlib import Path

import httpx
import uvicorn

from .config import token_hash
from .domain import SOURCES, canonical
from .labdata import fixtures, lab_aliases


def initialize(
    directory: Path, api_port: int = 8080, lab_port: int = 8091, executor_port: int = 8082
) -> dict:
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if (directory / "config.json").exists():
        raise ValueError("refusing to overwrite existing lab credentials")
    tokens = {
        role: secrets.token_urlsafe(32)
        for role in ["observer", "collector", "analyst", "approver", "executor"]
    }
    tokens["other_observer"] = secrets.token_urlsafe(32)
    key = secrets.token_urlsafe(48)
    credentials = {
        token_hash(token): {
            "name": "lab-" + role,
            "tenant": "lab-other" if role == "other_observer" else "lab",
            "roles": ["observer" if role == "other_observer" else role],
            "sources": list(SOURCES) if role == "collector" else [],
            "synthetic": True,
        }
        for role, token in tokens.items()
    }
    environment = {
        "SECMESH_SIGNING_KEY": secrets.token_urlsafe(48),
        "SECMESH_CREDENTIALS": canonical(credentials),
        "SECMESH_DATABASE_URL": "sqlite:///" + str((directory / "mesh.db").resolve()),
        "SECMESH_ALIASES": canonical(lab_aliases()),
        "SECMESH_LAB_KEY": key,
        "SECMESH_LAB_DB": str((directory / "lab.db").resolve()),
        "SECMESH_AI_ENABLED": "false",
        "SECMESH_SERVICE_MODE": "executor",
        "SECMESH_TARGETS": canonical(
            {
                "lab-host": {
                    "kind": "lab",
                    "tenant": "lab",
                    "asset": "lab-host-01",
                    "source_family": "wazuh",
                    "environment": "wazuh",
                    "collector_instance": "default",
                    "enabled": True,
                    "url": f"http://127.0.0.1:{lab_port}",
                    "key": key,
                }
            }
        ),
    }
    control_environment = {
        k: v for k, v in environment.items() if k not in {"SECMESH_LAB_KEY", "SECMESH_LAB_DB"}
    }
    control_environment["SECMESH_SERVICE_MODE"] = "api"
    control_environment["SECMESH_EXECUTOR_URL"] = f"http://127.0.0.1:{executor_port}"
    control_targets = json.loads(environment["SECMESH_TARGETS"])
    for target in control_targets.values():
        target.pop("key", None)
    control_environment["SECMESH_TARGETS"] = canonical(control_targets)
    for name, data in [
        ("config.json", control_environment),
        ("executor-config.json", environment),
        ("tokens.json", tokens),
    ]:
        path = directory / name
        path.write_text(canonical(data) + "\n")
        path.chmod(0o600)
    return {
        "api": f"http://127.0.0.1:{api_port}",
        "lab": f"http://127.0.0.1:{lab_port}",
        "credential_directory": str(directory.resolve()),
    }


def load_environment(path: Path) -> None:
    values = json.loads(path.read_text())
    for key, value in values.items():
        if not key.startswith("SECMESH_"):
            raise ValueError("configuration contains a non-SecOpsMesh environment key")
        os.environ[key] = str(value)


def main() -> None:
    parser = argparse.ArgumentParser(description="SecOpsMesh operational commands")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init-lab")
    init.add_argument("--directory", type=Path, default=Path(".runtime"))
    for name, port in [("serve", 8080), ("executor", 8082), ("lab", 8091)]:
        p = sub.add_parser(name)
        p.add_argument(
            "--config",
            type=Path,
            default=Path(
                ".runtime/config.json" if name == "serve" else ".runtime/executor-config.json"
            ),
        )
        p.add_argument("--port", type=int, default=port)
        p.add_argument("--host", default="127.0.0.1")
        p.add_argument("--ssl-certfile")
        p.add_argument("--ssl-keyfile")
    seed = sub.add_parser("seed")
    seed.add_argument("--api", default="http://127.0.0.1:8080")
    seed.add_argument("--tokens", type=Path, default=Path(".runtime/tokens.json"))
    worker = sub.add_parser("worker")
    worker.add_argument("--api", default="http://127.0.0.1:8080")
    worker.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if args.command == "init-lab":
        print(canonical(initialize(args.directory)))
    elif args.command in {"serve", "executor", "lab"}:
        if args.config.exists():
            load_environment(args.config)
        if args.command in {"serve", "executor"}:
            from .api import create_app

            app = create_app()
        else:
            from .lab_service import create_lab

            app = create_lab()
        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            log_level="warning",
            ssl_certfile=args.ssl_certfile,
            ssl_keyfile=args.ssl_keyfile,
        )
    elif args.command == "seed":
        tokens = json.loads(args.tokens.read_text())
        with httpx.Client(base_url=args.api, timeout=30, trust_env=False) as client:
            results = {}
            for source, payload in fixtures().items():
                result = client.post(
                    "/api/ingest/" + source,
                    json=payload,
                    headers={"Authorization": "Bearer " + tokens["collector"]},
                )
                result.raise_for_status()
                results[source] = result.json()
            print(canonical({"synthetic": True, "results": results}))
    else:
        token = os.environ["SECMESH_EXECUTOR_TOKEN"]
        with httpx.Client(
            base_url=args.api,
            timeout=120,
            headers={"Authorization": "Bearer " + token},
            trust_env=False,
        ) as client:
            while True:
                result = client.post("/api/recover")
                result.raise_for_status()
                print(canonical(result.json()), flush=True)
                if args.once:
                    break
                time.sleep(5)


if __name__ == "__main__":
    main()
