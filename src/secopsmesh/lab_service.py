"""Disposable application traffic gate. Never touches a host firewall or shell."""

from __future__ import annotations

import hmac
import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from .domain import digest, now
from .response import service_signature


class Command(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[a-f0-9]{32}$")
    action: Literal["contain", "rollback"]
    original_action_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")


def create_lab(key: str | None = None, path: str | None = None) -> FastAPI:
    secret = key or os.environ.get("SECMESH_LAB_KEY", "")
    if len(secret) < 32:
        raise ValueError("lab control key must have at least 32 characters")
    db_path = path or os.environ.get("SECMESH_LAB_DB", ".runtime/lab.db")
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(db_path)) as db, db:
        db.execute("CREATE TABLE IF NOT EXISTS gate (id INTEGER PRIMARY KEY, owner TEXT NOT NULL)")
        db.execute("INSERT OR IGNORE INTO gate VALUES(1,'')")
        db.execute(
            "CREATE TABLE IF NOT EXISTS commands (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, result TEXT NOT NULL)"
        )
    app = FastAPI(title="SecOpsMesh disposable lab")

    @app.get("/health")
    def health():
        return {"status": "ready", "scope": "synthetic disposable application"}

    @app.get("/work")
    def work():
        with closing(sqlite3.connect(db_path)) as db, db:
            owner = db.execute("SELECT owner FROM gate WHERE id=1").fetchone()[0]
        return JSONResponse(
            {"service": "synthetic lab workload", "contained": bool(owner)},
            status_code=403 if owner else 200,
            headers={"X-Mesh-Owner": owner},
        )

    @app.post("/control")
    async def control(request: Request):
        body = b""
        async for chunk in request.stream():
            body += chunk
            if len(body) > 4096:
                raise HTTPException(413, "command too large")
        timestamp = request.headers.get("X-Mesh-Time", "")
        try:
            age = abs(now().timestamp() - int(timestamp))
        except ValueError:
            raise HTTPException(401, "invalid transport authentication") from None
        signature = request.headers.get("X-Mesh-Signature", "")
        if age > 60 or not hmac.compare_digest(
            signature, service_signature(secret, timestamp, body)
        ):
            raise HTTPException(401, "invalid transport authentication")
        try:
            command = Command.model_validate_json(body)
        except ValueError:
            raise HTTPException(422, "invalid typed command") from None
        fingerprint = digest(command.model_dump())
        with closing(sqlite3.connect(db_path, timeout=10)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT fingerprint,result FROM commands WHERE id=?", (command.id,)
            ).fetchone()
            if existing:
                if existing[0] != fingerprint:
                    raise HTTPException(409, "idempotency key conflicts with prior command")
                return json.loads(existing[1])
            owner = db.execute("SELECT owner FROM gate WHERE id=1").fetchone()[0]
            if command.action == "contain":
                if owner and owner != command.id:
                    raise HTTPException(409, "another containment owns this target")
                owner = command.id
            else:
                if not command.original_action_id or owner != command.original_action_id:
                    raise HTTPException(409, "rollback does not own containment")
                owner = ""
            db.execute("UPDATE gate SET owner=? WHERE id=1", (owner,))
            result = {
                "id": command.id,
                "contained": bool(owner),
                "scope": "application traffic gate",
            }
            db.execute(
                "INSERT INTO commands VALUES(?,?,?)", (command.id, fingerprint, json.dumps(result))
            )
        return result

    return app
