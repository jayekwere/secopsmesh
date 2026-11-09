# Detection authoring and replay

Rules live in `detections/rules.yaml`, schema version `1.0`. The loader uses safe YAML, a 64 KiB file bound, a maximum of 100 rules, unique IDs and a Pydantic schema with unknown-field rejection. Rules are operator-controlled source code, not uploadable expressions.

```yaml
schema_version: '1.0'
rules:
  - id: high-confidence-provider-alert
    version: 1
    name: High-severity provider evidence
    kind: single
    min_severity: 70
    min_confidence: 0.4
    categories: []
    window_seconds: 900
    min_events: 1
    min_sources: 1
```

`kind` is `single` or `correlation`. Severity is 0..100 and confidence 0..1. Empty categories means any normalized category; otherwise exact category matches are required. Correlation rules use sliding windows of 60..3600 seconds and require bounded event/source counts. Entity grouping is performed before evaluation, scoped by tenant and explicit trusted aliases or collector/environment/namespace/asset scope. Do not correlate unrelated people by a common display name.

Re-delivered exact records do not count twice. Findings with a shared upstream reference retain both evidence records but do not satisfy a multi-event threshold solely through forwarding. Stale/future-flagged evidence does not create a current detection. Missing identity/asset information reduces confidence and remains visible. A supplied Wazuh ATT&CK mapping is provenance from that source; explicit CloudTrail/Kubernetes mappings apply only to known implemented operations.

Increase a rule's version when semantics change. Add both malicious and benign scenarios, a false-positive regression, a boundary/time-order case and evidence-citation expectations. `tests/test_engine.py` and `tests/test_transports.py` contain examples. Run `pytest`; CI validates rules through real application startup and deterministic replay tests.

`POST /api/replay` requires analyst authority and returns schema version, events evaluated, bounded-at value, deterministic detection IDs, rule versions, evidence IDs and rule-set digest. It evaluates up to 1000 historical records in the tenant and writes a replay audit record; it does not mutate response state. Export that JSON for evaluation evidence. Findings' original receipt-time quality flags remain part of the historical replay input, making reruns deterministic.

Operational correlation examines up to 500 neighboring records and retains up to 500 evidence references per incident. A boundary indicator is shown when that query limit is reached. These are explicit resource bounds, not a claim of complete event coverage at arbitrary scale. This release ships three defensible rules and selected provider classifications; it does not claim a comprehensive detection library or ATT&CK coverage score.
