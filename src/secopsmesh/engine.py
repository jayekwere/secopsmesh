from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select

from .adapters import parse
from .config import Principal, Settings
from .detection import evaluate, load_rules
from .domain import Finding, PlanRequest, digest, now, stamp
from .policy import POLICY_VERSION, Denied, require, target_fingerprint, target_policy
from .store import Action, Database, Event, Incident, SourceState


def event_view(row: Event) -> dict:
    return {"id": row.id, "finding_key": row.fingerprint, **row.data}


def action_view(row: Action) -> dict:
    return {
        "id": row.id,
        "incident_id": row.incident_id,
        "state": row.state,
        "fingerprint": row.fingerprint,
        "requester": row.requester,
        "approver": row.approver,
        "expires": row.expires,
        "attempts": row.attempts,
        "plan": row.plan,
        "result": row.result,
    }


class Engine:
    def __init__(self, db: Database, settings: Settings):
        self.db, self.settings = db, settings
        self.rules = load_rules(settings.rules_dir)

    def entity(self, tenant: str, finding: Finding) -> str:
        aliases = self.settings.aliases.get(tenant, {})
        # No raw-event relationship hint is trusted. An exact configured alias is required.
        return (
            aliases.get("identity:" + finding.identity)
            or aliases.get("asset:" + finding.asset)
            or "asset:"
            + ":".join(
                [
                    finding.collector_instance,
                    finding.source.split(".")[0],
                    finding.environment,
                    finding.namespace,
                    finding.asset,
                ]
            )
        )

    def ingest(self, p: Principal, source: str, payload: dict) -> dict:
        require(p, "collector")
        if source not in p.sources:
            raise Denied("collector is not authorized for this source")
        findings = parse(source, payload, p.synthetic)
        accepted, duplicate, incident_ids = [], [], set()
        with self.db.session() as s:
            self.db.lock(s, p.tenant)
            for finding in findings:
                finding.collector_instance = p.instance
                data = finding.model_dump()
                stable = {
                    k: v
                    for k, v in data.items()
                    if k not in {"received_at", "quality", "confidence", "risk"}
                }
                eid = digest([p.tenant, stable])
                if s.get(Event, eid):
                    duplicate.append(eid)
                    continue
                observed = datetime.fromisoformat(finding.observed_at).timestamp()
                fingerprint = (
                    digest([p.tenant, "upstream", finding.origin_ref])
                    if finding.origin_ref
                    else digest([p.tenant, finding.asset, finding.category, int(observed // 60)])
                )
                row = Event(
                    id=eid,
                    tenant=p.tenant,
                    source=source,
                    source_id=finding.source_id,
                    asset=finding.asset,
                    identity=finding.identity,
                    observed=observed,
                    received=finding.received_at,
                    fingerprint=fingerprint,
                    data=data,
                )
                # Source revisions are preserved; contradictory severity is explicit.
                revisions = s.scalars(
                    select(Event)
                    .where(
                        Event.tenant == p.tenant,
                        Event.source == source,
                        Event.source_id == finding.source_id,
                    )
                    .limit(20)
                ).all()
                if any(r.data["severity"] != finding.severity for r in revisions):
                    data["quality"] = list(
                        dict.fromkeys(data["quality"] + ["conflicting_source_revision"])
                    )
                    row.data = data
                s.add(row)
                s.flush()
                entity = self.entity(p.tenant, finding)
                # Inspect bounded adjacent windows so a boundary does not break a short correlation.
                window = int(observed // 900)
                candidates = s.scalars(
                    select(Event)
                    .where(
                        Event.tenant == p.tenant,
                        Event.observed >= observed - 900,
                        Event.observed <= observed + 900,
                    )
                    .order_by(Event.observed.desc())
                    .limit(500)
                ).all()
                related = [
                    (r.id, Finding.model_validate(r.data))
                    for r in candidates
                    if self.entity(p.tenant, Finding.model_validate(r.data)) == entity
                ]
                hits = evaluate(self.rules, related)
                if hits:
                    existing = s.scalars(
                        select(Incident)
                        .where(
                            Incident.tenant == p.tenant,
                            Incident.entity == entity,
                            Incident.window.in_([window - 1, window, window + 1]),
                        )
                        .order_by(Incident.window)
                        .limit(3)
                    ).all()
                    eligible = [
                        i for i in existing if abs(observed - i.data["last_observed"]) <= 900
                    ]
                    iid = eligible[0].id if eligible else digest([p.tenant, entity, window])
                    incident = s.get(Incident, iid)
                    previous_ids = incident.data["evidence_ids"] if incident else []
                    ids = sorted(
                        set(previous_ids + [eid for hit in hits for eid in hit["evidence_ids"]])
                    )
                    # The 500-event bound is explicit and visible as a data-quality limit.
                    ids = ids[-500:]
                    all_rows = s.scalars(
                        select(Event).where(Event.tenant == p.tenant, Event.id.in_(ids))
                    ).all()
                    families = sorted({r.source.split(".")[0] for r in all_rows})
                    risk = min(
                        100,
                        max(r.data["severity"] for r in all_rows)
                        + (10 if len(families) > 1 else 0),
                    )
                    incident_data = {
                        "title": "Related security activity: " + entity[:90],
                        "status": "open",
                        "entity": entity,
                        "risk": risk,
                        "evidence_ids": ids,
                        "detections": hits,
                        "environments": families,
                        "last_observed": max(r.observed for r in all_rows),
                        "updated_at": stamp(),
                        "synthetic": all(r.data["synthetic"] for r in all_rows),
                        "quality": ["bounded_correlation"] if len(candidates) == 500 else [],
                    }
                    if incident:
                        incident.data = incident_data
                    else:
                        s.add(
                            Incident(
                                id=iid,
                                tenant=p.tenant,
                                entity=entity,
                                window=window,
                                data=incident_data,
                            )
                        )
                    s.flush()
                    incident_ids.add(iid)
                    if self.settings.auto_propose and risk >= 70:
                        for tid, target in self.settings.targets.items():
                            if (
                                target.get("asset") == finding.asset
                                and target.get("tenant") == p.tenant
                                and target.get("enabled")
                            ):
                                existing_action = s.scalar(
                                    select(Action).where(
                                        Action.tenant == p.tenant, Action.incident_id == iid
                                    )
                                )
                                if not existing_action:
                                    system = Principal(
                                        "workflow:contain", p.tenant, frozenset({"analyst"})
                                    )
                                    self._propose(
                                        s, system, PlanRequest(incident_id=iid, target=tid)
                                    )
                accepted.append(eid)
            sid = digest([p.tenant, source])
            status = s.get(SourceState, sid)
            health = {
                "last_received": stamp(),
                "last_error": None,
                "mode": "synthetic" if p.synthetic else "live-unverified",
                "accepted": len(accepted) + (status.data.get("accepted", 0) if status else 0),
                "duplicates": len(duplicate) + (status.data.get("duplicates", 0) if status else 0),
            }
            if status:
                status.data = health
            else:
                s.add(SourceState(id=sid, tenant=p.tenant, source=source, data=health))
            self.db.audit(
                s,
                p.tenant,
                p.name,
                "ingest",
                {"source": source, "accepted": accepted, "duplicates": len(duplicate)},
            )
        return {"accepted": accepted, "duplicates": duplicate, "incident_ids": sorted(incident_ids)}

    def _propose(self, s, p: Principal, request: PlanRequest) -> Action:
        require(p, "analyst")
        incident = s.get(Incident, request.incident_id)
        if not incident or incident.tenant != p.tenant:
            raise Denied("incident not found")
        target = target_policy(self.settings, p.tenant, request.target)
        evidence = s.scalars(
            select(Event).where(
                Event.tenant == p.tenant, Event.id.in_(incident.data["evidence_ids"])
            )
        ).all()
        if not all(k in target for k in ["source_family", "environment", "collector_instance"]):
            raise Denied("target inventory requires exact telemetry scope")
        if not any(
            target.get("asset") == r.asset
            and target["source_family"] == r.source.split(".")[0]
            and target["environment"] == r.data["environment"]
            and target["collector_instance"] == r.data.get("collector_instance", "default")
            and target.get("namespace", "") == r.data["namespace"]
            for r in evidence
        ):
            raise Denied("target does not occur in incident evidence")
        if request.action == "rollback":
            original = s.get(Action, request.original_action_id or "")
            if (
                not original
                or original.tenant != p.tenant
                or original.state != "verified"
                or original.plan["action"] != "contain"
                or original.plan["target"] != request.target
            ):
                raise Denied("rollback requires a verified containment for this target")
        elif request.original_action_id:
            raise Denied("containment cannot name an original action")
        aid = uuid.uuid4().hex
        expires = now().timestamp() + 900
        plan = {
            "id": aid,
            "tenant": p.tenant,
            "incident_id": incident.id,
            "target": request.target,
            "action": request.action,
            "original_action_id": request.original_action_id,
            "target_fingerprint": target_fingerprint(target),
            "policy_version": POLICY_VERSION,
            "evidence_digest": digest(sorted(incident.data["evidence_ids"])),
            "expires": expires,
        }
        row = Action(
            id=aid,
            tenant=p.tenant,
            incident_id=incident.id,
            state="pending",
            fingerprint=digest(plan),
            requester=p.name,
            approver=None,
            approval=None,
            expires=expires,
            plan=plan,
            result={},
            lease_until=0,
            attempts=0,
        )
        s.add(row)
        self.db.audit(
            s, p.tenant, p.name, "action.proposed", {"id": aid, "fingerprint": row.fingerprint}
        )
        return row

    def propose(self, p: Principal, request: PlanRequest) -> dict:
        with self.db.session() as s:
            self.db.lock(s, p.tenant)
            return action_view(self._propose(s, p, request))
