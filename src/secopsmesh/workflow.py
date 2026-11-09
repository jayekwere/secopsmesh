from __future__ import annotations

import hmac

from sqlalchemy import select, update

from .config import Principal, Settings
from .domain import digest, now, stamp
from .engine import action_view
from .policy import Denied, approval_signature, execution_policy, require
from .response import response_adapter
from .store import Action, Database, Incident


class Workflow:
    def __init__(self, db: Database, settings: Settings, factory=response_adapter):
        self.db, self.settings, self.factory = db, settings, factory

    def approve(self, p: Principal, action_id: str, fingerprint: str) -> dict:
        require(p, "approver")
        with self.db.session() as s:
            self.db.lock(s, p.tenant)
            row = s.get(Action, action_id)
            if not row or row.tenant != p.tenant:
                raise Denied("action not found")
            if row.state != "pending" or row.expires <= now().timestamp():
                raise Denied("action is not pending or has expired")
            if row.requester == p.name:
                raise Denied("requester cannot approve their own action")
            if (
                not hmac.compare_digest(row.fingerprint, fingerprint)
                or digest(row.plan) != fingerprint
            ):
                raise Denied("exact plan fingerprint required")
            incident = s.get(Incident, row.incident_id)
            if (
                not incident
                or digest(sorted(incident.data["evidence_ids"])) != row.plan["evidence_digest"]
            ):
                raise Denied("incident evidence changed; propose a new plan")
            row.approver, row.state = p.name, "approved"
            row.approval = approval_signature(self.settings, row)
            self.db.audit(
                s,
                p.tenant,
                p.name,
                "action.approved",
                {"id": row.id, "fingerprint": row.fingerprint},
            )
            return action_view(row)

    def execute(self, p: Principal, action_id: str) -> dict:
        require(p, "executor")
        at = now().timestamp()
        reconcile = False
        with self.db.session() as s:
            self.db.lock(s, p.tenant)
            row = s.get(Action, action_id)
            if not row or row.tenant != p.tenant:
                raise Denied("action not found")
            if row.state == "verified":
                return action_view(row)  # Idempotent response: no side effects.
            if row.state in {"executing", "ambiguous", "verification_failed"}:
                if row.state == "executing" and row.lease_until > at:
                    raise Denied("another executor owns the execution lease")
                reconcile = True
            elif row.state != "approved":
                raise Denied("action requires independent approval")
            # Expired execution may be reconciled read-only; never retried after ambiguity.
            target = execution_policy(
                self.settings, row, p, min(at, row.expires - 1) if reconcile else at
            )
            incident = s.get(Incident, row.incident_id)
            if not reconcile and (
                not incident
                or digest(sorted(incident.data["evidence_ids"])) != row.plan["evidence_digest"]
            ):
                raise Denied("incident evidence changed after approval")
            result = s.execute(
                update(Action)
                .where(
                    Action.id == row.id, Action.state == row.state, Action.attempts == row.attempts
                )
                .values(state="executing", lease_until=at + 60, attempts=row.attempts + 1)
            )
            if result.rowcount != 1:
                raise Denied("concurrent claim lost")
            plan = dict(row.plan)
            self.db.audit(
                s,
                p.tenant,
                p.name,
                "action.reconcile" if reconcile else "action.claimed",
                {"id": row.id, "fingerprint": row.fingerprint},
            )
        # The intent has committed before any network mutation.
        adapter = None
        receipt: dict = {}
        verification: dict = {}
        state = "ambiguous"
        try:
            adapter = self.factory(target)
            if not reconcile:
                receipt = adapter.apply(plan)
            verification = adapter.verify(plan)
            state = "verified" if verification.get("verified") is True else "verification_failed"
        except Exception as exc:
            # Never expose credential-bearing exception text or assume a timeout means failure.
            receipt = {"error_type": type(exc).__name__, "reconciliation_required": True}
        finally:
            if adapter is not None:
                adapter.close()
        with self.db.session() as s:
            self.db.lock(s, p.tenant)
            row = s.get(Action, action_id)
            if row is None:
                raise RuntimeError("durable action disappeared")
            row.state, row.lease_until = state, 0
            history = row.result.get("history", [])
            record = {
                "at": stamp(),
                "reconcile": reconcile,
                "receipt": receipt,
                "verification": verification,
                "state": state,
            }
            row.result = {**record, "history": (history + [record])[-20:]}
            self.db.audit(s, p.tenant, p.name, "action." + state, {"id": row.id, "outcome": record})
            return action_view(row)

    def recoverable(self, p: Principal) -> list[str]:
        require(p, "executor")
        with self.db.session() as s:
            return list(
                s.scalars(
                    select(Action.id)
                    .where(
                        Action.tenant == p.tenant,
                        Action.state.in_(
                            ["approved", "ambiguous", "verification_failed", "executing"]
                        ),
                        Action.lease_until <= now().timestamp(),
                    )
                    .limit(100)
                )
            )
