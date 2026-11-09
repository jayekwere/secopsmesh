from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from .domain import Finding, digest


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[a-z0-9-]{3,80}$")
    version: int = Field(ge=1)
    name: str = Field(min_length=1, max_length=150)
    kind: Literal["single", "correlation"]
    min_severity: int = Field(ge=0, le=100)
    min_confidence: float = Field(ge=0, le=1)
    categories: list[str] = Field(max_length=30)
    window_seconds: int = Field(ge=60, le=3600)
    min_events: int = Field(ge=1, le=100)
    min_sources: int = Field(ge=1, le=12)


class RuleSet(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"]
    rules: list[Rule] = Field(min_length=1, max_length=100)


def load_rules(directory: Path) -> list[Rule]:
    path = directory / "rules.yaml"
    if path.stat().st_size > 65536:
        raise ValueError("rules file too large")
    rules = RuleSet.model_validate(yaml.safe_load(path.read_text())).rules
    if len({r.id for r in rules}) != len(rules):
        raise ValueError("duplicate rule id")
    return rules


def evaluate(rules: list[Rule], events: list[tuple[str, Finding]]) -> list[dict]:
    """Order-independent sliding windows; duplicates do not count twice."""
    results: list[dict] = []
    for rule in rules:
        eligible = sorted(
            [
                (eid, f)
                for eid, f in dict(events).items()
                if f.severity >= rule.min_severity
                and f.confidence >= rule.min_confidence
                and not {"stale_evidence", "future_timestamp"}.intersection(f.quality)
                and (not rule.categories or f.category in rule.categories)
            ],
            key=lambda item: (item[1].observed_at, item[0]),
        )
        if rule.kind == "single":
            groups = [[entry] for entry in eligible]
        else:
            groups = []
            for i, (_, end) in enumerate(eligible):
                end_time = datetime.fromisoformat(end.observed_at).timestamp()
                group = [
                    entry
                    for entry in eligible[: i + 1]
                    if end_time - datetime.fromisoformat(entry[1].observed_at).timestamp()
                    <= rule.window_seconds
                ]
                if (
                    len({f.origin_ref or eid for eid, f in group}) >= rule.min_events
                    and len({f.source for _, f in group}) >= rule.min_sources
                ):
                    groups.append(group)
        for group in groups:
            ids = sorted(eid for eid, _ in group)
            results.append(
                {
                    "id": digest([rule.id, rule.version, ids]),
                    "rule_id": rule.id,
                    "rule_version": rule.version,
                    "name": rule.name,
                    "evidence_ids": ids,
                }
            )
    # Keep the maximal evidence set for each correlation rule, all individual single hits.
    return [
        r
        for r in results
        if not any(
            r["rule_id"] == other["rule_id"] and set(r["evidence_ids"]) < set(other["evidence_ids"])
            for other in results
        )
    ]
