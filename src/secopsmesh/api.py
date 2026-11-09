from __future__ import annotations

import asyncio
import hmac
import json
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, ValidationError
from sqlalchemy import func, select

from .adapters import AdapterError
from .config import Principal, Settings, token_hash
from .domain import SOURCES, ApprovalRequest, PlanRequest, canonical, digest, now, stamp
from .engine import Engine, action_view, event_view
from .investigation import Investigator, can_read
from .policy import Denied, require
from .response import service_signature
from .store import Action, Audit, Database, Event, Incident, Investigation, Nonce, SourceState
from .workflow import Workflow


class LimitsMiddleware:
    def __init__(self, app, settings: Settings):
        self.app, self.settings = app, settings
        self.rates: dict[tuple[str, int], int] = {}

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope["headers"])
        path = scope["path"]
        if (
            self.settings.service_mode == "executor"
            and path != "/health"
            and path != "/api/recover"
            and not (path.startswith("/api/actions/") and path.endswith("/execute"))
        ):
            return await JSONResponse(
                {"detail": "not exposed by executor service"}, status_code=404
            )(scope, receive, send)
        if path.startswith("/api/"):
            auth = headers.get(b"authorization", b"").decode("latin1")
            principal = (
                self.settings.credentials.get(token_hash(auth[7:]))
                if auth.startswith("Bearer ")
                else None
            )
            if principal is None:
                return await JSONResponse({"detail": "authentication required"}, status_code=401)(
                    scope, receive, send
                )
            scope.setdefault("state", {})["principal"] = principal
            minute = int(time.monotonic() // 60)
            self.rates = {k: v for k, v in self.rates.items() if k[1] == minute}
            rate_key = (token_hash(auth), minute)
            self.rates[rate_key] = self.rates.get(rate_key, 0) + 1
            if self.rates[rate_key] > 240:
                return await JSONResponse(
                    {"detail": "request rate exceeded"},
                    status_code=429,
                    headers={"Retry-After": "60"},
                )(scope, receive, send)
        body = b""
        while True:
            try:
                message = await asyncio.wait_for(receive(), timeout=5)
            except TimeoutError:
                return await JSONResponse({"detail": "request body timeout"}, status_code=408)(
                    scope, receive, send
                )
            if message["type"] == "http.disconnect":
                return
            body += message.get("body", b"")
            if len(body) > 262144:
                return await JSONResponse({"detail": "request exceeds 256 KiB"}, status_code=413)(
                    scope, receive, send
                )
            if not message.get("more_body", False):
                break
        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        async def secure_send(message):
            if message["type"] == "http.response.start":
                message["headers"] += [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"cache-control", b"no-store"),
                    (
                        b"content-security-policy",
                        b"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
                    ),
                ]
            await send(message)

        await self.app(scope, replay, secure_send)


def principal(request: Request) -> Principal:
    return request.state.principal


def reader(p: Principal = Depends(principal)) -> Principal:
    can_read(p)
    return p


class InvestigationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    use_ai: bool = False


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    db = Database(settings.database_url, settings.signing_key)
    engine = Engine(db, settings)
    investigator = Investigator(db, settings)
    workflow = Workflow(db, settings)
    app = FastAPI(
        title="SecOpsMesh", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None
    )
    app.state.db, app.state.engine, app.state.workflow = db, engine, workflow
    app.state.settings = settings
    app.add_middleware(LimitsMiddleware, settings=settings)

    @app.exception_handler(Denied)
    async def denied(_, exc):
        return JSONResponse({"detail": str(exc)}, status_code=403)

    @app.exception_handler(AdapterError)
    @app.exception_handler(ValidationError)
    async def invalid(_, exc):
        return JSONResponse(
            {"detail": "invalid provider contract", "error_type": type(exc).__name__},
            status_code=422,
        )

    @app.get("/health")
    def health():
        with db.session() as s:
            s.execute(select(1))
        return {"status": "ready", "version": "0.1.0"}

    @app.get("/api/me")
    def me(p: Principal = Depends(principal)):
        return {
            "name": p.name,
            "tenant": p.tenant,
            "roles": sorted(p.roles),
            "synthetic": p.synthetic,
        }

    @app.get("/api/openapi.json")
    def schema(p: Principal = Depends(reader)):
        return app.openapi()

    @app.post("/api/ingest/{source}")
    def ingest(source: str, payload: dict, p: Principal = Depends(principal)):
        return engine.ingest(p, source, payload)

    @app.post("/api/webhooks/{source}")
    async def webhook(source: str, request: Request, p: Principal = Depends(principal)):
        require(p, "collector")
        key = settings.webhook_keys.get(p.name)
        if not key:
            raise Denied("signed webhook is not configured for this collector")
        timestamp = request.headers.get("X-Mesh-Time", "")
        nonce = request.headers.get("X-Mesh-Nonce", "")
        if not 16 <= len(nonce) <= 128:
            raise Denied("invalid webhook nonce")
        try:
            if abs(now().timestamp() - int(timestamp)) > 60:
                raise Denied("webhook timestamp expired")
        except ValueError:
            raise Denied("invalid webhook timestamp") from None
        body = await request.body()
        expected = service_signature(
            key, timestamp, nonce.encode() + b"." + source.encode() + b"." + body
        )
        if not hmac.compare_digest(expected, request.headers.get("X-Mesh-Signature", "")):
            raise Denied("invalid webhook signature")
        nid = digest([p.tenant, p.name, nonce])
        with db.session() as s:
            db.lock(s, p.tenant)
            if s.get(Nonce, nid):
                raise Denied("webhook replay denied")
            s.add(Nonce(id=nid, expires=now().timestamp() + 86400))
        try:
            return engine.ingest(p, source, json.loads(body))
        except (ValueError, TypeError):
            raise HTTPException(422, "invalid webhook payload") from None

    @app.get("/api/overview")
    def overview(p: Principal = Depends(reader)):
        with db.session() as s:
            events = s.scalar(
                select(func.count()).select_from(Event).where(Event.tenant == p.tenant)
            )
            incidents = s.scalars(select(Incident).where(Incident.tenant == p.tenant)).all()
            actions = s.scalars(select(Action).where(Action.tenant == p.tenant)).all()
            return {
                "events": events,
                "incidents": len(incidents),
                "high_risk": sum(i.data["risk"] >= 70 for i in incidents),
                "pending_approvals": sum(a.state == "pending" for a in actions),
                "verified_actions": sum(a.state == "verified" for a in actions),
                "uncertain_actions": sum(
                    a.state in {"ambiguous", "verification_failed"} for a in actions
                ),
                "synthetic_events": s.scalar(
                    select(func.count())
                    .select_from(Event)
                    .where(Event.tenant == p.tenant, Event.data["synthetic"].as_boolean().is_(True))
                ),
                "as_of": stamp(),
                "ai_enabled": settings.ai_enabled,
            }

    @app.get("/api/sources")
    def sources(p: Principal = Depends(reader)):
        with db.session() as s:
            states = {
                r.source: r.data
                for r in s.scalars(select(SourceState).where(SourceState.tenant == p.tenant))
            }
        result = []
        for source in SOURCES:
            state = states.get(source, {})
            last = state.get("last_received")
            from datetime import datetime

            fresh = (
                bool(last) and now().timestamp() - datetime.fromisoformat(last).timestamp() < 900
            )
            result.append(
                {
                    "source": source,
                    "health": "receiving" if fresh else "stale" if last else "not_configured",
                    **state,
                    "acceptance": "contract-tested; live acceptance pending",
                }
            )
        return result

    @app.get("/api/events")
    def events(
        source: str | None = None,
        asset: str | None = None,
        offset: int = Query(0, ge=0, le=100000),
        limit: int = Query(50, ge=1, le=100),
        p: Principal = Depends(reader),
    ):
        with db.session() as s:
            query = select(Event).where(Event.tenant == p.tenant)
            if source:
                query = query.where(Event.source == source)
            if asset:
                query = query.where(Event.asset == asset)
            return [
                event_view(r)
                for r in s.scalars(
                    query.order_by(Event.observed.desc(), Event.id).offset(offset).limit(limit)
                )
            ]

    @app.get("/api/events/{event_id}")
    def event_detail(event_id: str, p: Principal = Depends(reader)):
        with db.session() as s:
            row = s.get(Event, event_id)
            if not row or row.tenant != p.tenant:
                raise HTTPException(404, "evidence not found")
            return event_view(row)

    @app.get("/api/incidents")
    def incidents(p: Principal = Depends(reader)):
        with db.session() as s:
            return [
                {"id": r.id, **r.data}
                for r in s.scalars(
                    select(Incident)
                    .where(Incident.tenant == p.tenant)
                    .order_by(Incident.window.desc())
                    .limit(100)
                )
            ]

    @app.get("/api/incidents/{incident_id}")
    def incident_detail(incident_id: str, p: Principal = Depends(reader)):
        return investigator.evidence(p, incident_id)

    @app.get("/api/incidents/{incident_id}/investigations")
    def investigations(incident_id: str, p: Principal = Depends(reader)):
        investigator.evidence(p, incident_id)
        with db.session() as s:
            return [
                {"id": r.id, "created": r.created, **r.data}
                for r in s.scalars(
                    select(Investigation)
                    .where(
                        Investigation.tenant == p.tenant, Investigation.incident_id == incident_id
                    )
                    .order_by(Investigation.created.desc())
                    .limit(30)
                )
            ]

    @app.post("/api/incidents/{incident_id}/investigate")
    def investigate(incident_id: str, body: InvestigationRequest, p: Principal = Depends(reader)):
        require(p, "analyst")
        try:
            return investigator.investigate(p, incident_id, body.use_ai)
        except Denied:
            raise
        except ValueError as exc:
            raise HTTPException(502, str(exc)) from None

    @app.post("/api/mcp")
    def mcp(body: dict, p: Principal = Depends(reader)):
        if body.get("jsonrpc") != "2.0" or body.get("method") not in {
            "initialize",
            "tools/list",
            "tools/call",
        }:
            raise Denied("unsupported read-only MCP method")
        method = body["method"]
        result: dict
        if method == "initialize":
            result = {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "secopsmesh-readonly", "version": "0.1.0"},
            }
        elif method == "tools/list":
            result = {
                "tools": [
                    {
                        "name": name,
                        "description": "Tenant-scoped read-only security evidence",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"incident_id": {"type": "string", "maxLength": 64}},
                            "required": ["incident_id"],
                            "additionalProperties": False,
                        },
                    }
                    for name in ["incident_evidence", "asset_timeline"]
                ]
            }
        else:
            params = body.get("params", {})
            args = params.get("arguments", {})
            if (
                set(args) != {"incident_id"}
                or not isinstance(args.get("incident_id"), str)
                or len(args["incident_id"]) > 64
            ):
                raise Denied("invalid MCP arguments")
            result = {
                "content": [
                    {
                        "type": "text",
                        "text": canonical(
                            investigator.tool(p, params.get("name", ""), args["incident_id"])
                        ),
                    }
                ],
                "isError": False,
            }
        return {"jsonrpc": "2.0", "id": body.get("id"), "result": result}

    @app.get("/api/rules")
    def rules(p: Principal = Depends(reader)):
        return [r.model_dump() for r in engine.rules]

    @app.post("/api/replay")
    def replay(p: Principal = Depends(reader)):
        require(p, "analyst")
        from .detection import evaluate

        with db.session() as s:
            db.lock(s, p.tenant)
            rows = s.scalars(
                select(Event).where(Event.tenant == p.tenant).order_by(Event.observed).limit(1000)
            ).all()
            from .domain import Finding

            groups: dict[str, list] = {}
            for row in rows:
                f = Finding.model_validate(row.data)
                groups.setdefault(engine.entity(p.tenant, f), []).append((row.id, f))
            results = [hit for group in groups.values() for hit in evaluate(engine.rules, group)]
            report = {
                "schema_version": "1.0",
                "events_evaluated": len(rows),
                "bounded_at": 1000,
                "detections": results,
                "rule_digest": digest([r.model_dump() for r in engine.rules]),
            }
            db.audit(
                s,
                p.tenant,
                p.name,
                "detection.replay",
                {"report_digest": digest(report), "events_evaluated": len(rows)},
            )
            return report

    @app.get("/api/targets")
    def targets(p: Principal = Depends(reader)):
        return [
            {"id": tid, **{k: t[k] for k in ["kind", "asset", "enabled"] if k in t}}
            for tid, t in settings.targets.items()
            if t["tenant"] == p.tenant
        ]

    @app.get("/api/actions")
    def actions(p: Principal = Depends(reader)):
        with db.session() as s:
            return [
                action_view(r)
                for r in s.scalars(select(Action).where(Action.tenant == p.tenant).limit(100))
            ]

    @app.post("/api/actions")
    def propose(body: PlanRequest, p: Principal = Depends(principal)):
        return engine.propose(p, body)

    @app.post("/api/actions/{action_id}/approve")
    def approve(action_id: str, body: ApprovalRequest, p: Principal = Depends(principal)):
        return workflow.approve(p, action_id, body.fingerprint)

    @app.post("/api/actions/{action_id}/execute")
    def execute(action_id: str, request: Request, p: Principal = Depends(principal)):
        if settings.service_mode == "api":
            require(p, "executor")
            return proxy_execution(
                "/api/actions/" + action_id + "/execute", p, request.headers["authorization"][7:]
            )
        return workflow.execute(p, action_id)

    @app.post("/api/recover")
    def recover(request: Request, p: Principal = Depends(principal)):
        if settings.service_mode == "api":
            require(p, "executor")
            return proxy_execution("/api/recover", p, request.headers["authorization"][7:])
        return [workflow.execute(p, aid) for aid in workflow.recoverable(p)]

    def proxy_execution(path: str, p: Principal, credential: str):
        origin = urlparse(settings.executor_url)
        if (
            origin.scheme not in {"http", "https"}
            or origin.username
            or origin.query
            or origin.fragment
            or origin.path not in {"", "/"}
        ):
            raise Denied("a fixed executor service origin is required")
        if origin.scheme == "http" and origin.hostname not in {
            "127.0.0.1",
            "localhost",
            "executor",
        }:
            raise Denied("plaintext executor transport is restricted to the isolated lab")
        # Forward only the caller's credential. The API stores no executor credential.
        credential_digest = next(
            (key for key, identity in settings.credentials.items() if identity is p), None
        )
        if credential_digest is None or token_hash(credential) != credential_digest:
            raise Denied("executor credential binding failed")
        try:
            with httpx.Client(timeout=120, follow_redirects=False, trust_env=False) as transport:
                result = transport.post(
                    settings.executor_url.rstrip("/") + path,
                    headers={"Authorization": "Bearer " + credential},
                )
                if result.status_code >= 400:
                    raise HTTPException(
                        result.status_code, "executor denied or could not complete the request"
                    )
                return result.json()
        except httpx.HTTPError:
            raise HTTPException(
                503, "executor unavailable; reconcile the durable action before retrying"
            ) from None

    @app.get("/api/audit")
    def audit(offset: int = Query(0, ge=0, le=100000), p: Principal = Depends(reader)):
        with db.session() as s:
            return [
                {
                    "seq": r.seq,
                    **json.loads(r.body),
                    "previous": r.previous,
                    "signature": r.signature,
                }
                for r in s.scalars(
                    select(Audit)
                    .where(Audit.tenant == p.tenant)
                    .order_by(Audit.seq.desc())
                    .offset(offset)
                    .limit(100)
                )
            ]

    @app.get("/api/audit/checkpoint")
    def checkpoint(p: Principal = Depends(reader)):
        return db.verify_audit(p.tenant)

    @app.get("/api/metrics", response_class=PlainTextResponse)
    def metrics(p: Principal = Depends(reader)):
        data = overview(p)
        return "".join(
            f"# TYPE secopsmesh_{k} gauge\nsecopsmesh_{k} {v}\n"
            for k, v in data.items()
            if type(v) is int
        )

    dist = Path("frontend/dist")
    if dist.exists():
        app.mount("/", StaticFiles(directory=dist, html=True), name="dashboard")
    return app
