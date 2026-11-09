# Pre-release security review and remediation

The final independent source review audited commit `6a6ed79f255d165c5d75f9084f0ad2e0d8833cb2`, before remediation. A general baseline auditor, focused browser-session reviewer and parent source validation found **one medium and one low issue; no critical/high issue was established**. This is a source-backed review, not certification or a live provider penetration test.

The immutable generated [pre-fix report](../evidence/security-review-6a6ed79.md) preserves the original findings and limitations. It intentionally describes the old source. The release incorporates the following fixes and executable regressions:

| Finding | Fix | Verification |
|---|---|---|
| CWE-488: saved replay and delayed requests could disclose prior-tenant browser state after a same-tab credential switch | Give each session its own remounted component; synchronously invalidate and abort its requests on sign-out; reject stale follow-up calls/results. All replay, drawer, report, checkpoint, error and busy state is discarded together. | Real two-tenant browser tests cover completed replay retention, a delayed refresh released after the new login, and a delayed incident inspector. The original full approval/containment/rollback browser flow also passes. |
| CWE-770: overview/metrics loaded every JSON-bearing incident/action row just to count it | Tenant-scoped SQL aggregate projections return fixed-size counts without materializing operational entities. | A regression seeds history beyond list pagination, verifies exact counts and rejects any incident/action entity materialization during overview or metrics requests. It runs against SQLite and PostgreSQL in CI. |

The backend role/tenant/approval controls were effective in the inspected paths; the browser defect did not establish server-side cross-tenant response authority. The availability issue required authenticated/preexisting tenant state and was calibrated low; no fabricated exhaustion threshold is claimed.

Earlier architecture review also led to environment/namespace/collector scoping, upstream-reference corroboration deduplication, removal of unnecessary privileged token placement in the API container, streaming Wazuh response limits, and a guarded disposable test database. The outdated isolated package installer was upgraded after advisory scanning.

Residual production risks remain explicit: trusted API/executor database/signing authority, operator identity lifecycle, ingress-wide bounds, external audit checkpoints, source redaction limits, provider live onboarding, and trusted network-probe interpretation. See [security configuration](SECURITY-CONFIGURATION.md) and [validation](VALIDATION.md). The source review and release test reports are separate evidence classes.
