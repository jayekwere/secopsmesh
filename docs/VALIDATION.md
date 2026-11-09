# Validation record and production-readiness assessment

The authoritative evidence is the exact release commit's GitHub Actions runs and attached machine-readable artifacts. Local evidence is retained in `evidence/`. Results are measured, not inferred from code existence. This document is updated with final run references during publication.

## Evidence classes

- **Implemented and locally verified:** normalization/schema validation, thirteen provider contracts, exact-delivery and upstream-reference deduplication, scoped correlation, deterministic detection replay, API roles/tenant separation, read-only investigation/MCP, tamper/expiry/role-revocation enforcement, concurrency, restart/readback recovery, real HTTP application containment and rollback, five full browser acceptance tests, TypeScript build, lint/type/SAST/dependency checks.
- **Disposable service acceptance:** PostgreSQL tests, container build/runtime/Compose workflow, and real kind/Cilium audit/packet/RBAC/admission acceptance are independently executed in GitHub runners. Consult the retained reports for actual final success/failure rather than treating their presence as proof of a pass.
- **Contract-tested, live acceptance pending:** AWS GuardDuty/Security Hub/CloudTrail/EventBridge bridge, Azure Defender/recommendations/Monitor/Event Hubs/Sentinel, GCP SCC/audit/Pub/Sub, external Wazuh Indexer/manager forwarding, external Claude API and optional Kubernetes deployment chart.
- **Not implemented:** destructive cloud response adapters, general remote execution, enterprise SSO/session management, distributed broker/ownership coordinator, automatic cross-version database migrations, an extensive detection-content catalog, externally managed audit retention, and HA/scale certification. Terraform provisioning is intentionally absent; no external resources were deployed.

## Re-run checks

```sh
.venv/bin/ruff check src tests scripts
.venv/bin/ruff format --check src tests scripts
.venv/bin/mypy src/secopsmesh
.venv/bin/pytest --cov=secopsmesh --cov-report=json:reports/coverage.json --junitxml=reports/backend-junit.xml
.venv/bin/bandit -r src -q -f json -o reports/bandit.json
.venv/bin/pip-audit --strict --disable-pip --no-deps -r requirements.lock
npm audit --prefix frontend
npm run build --prefix frontend
.venv/bin/python scripts/demo.py --output reports/demo.json
npm run test:e2e --prefix frontend
```

Coverage threshold is 85% of backend application statements. CLI entry points and provider-worker orchestration are excluded from that statement denominator and are exercised separately through executable demos/transport contracts; this distinction is deliberate and visible in `pyproject.toml`. The suite is not a claim of 85% coverage of every shipped line. The first measured baseline was 117 passing backend tests and 92.08% coverage; subsequent control fixes add tests, and final release measurements supersede that baseline.

The PostgreSQL test reset requires an explicitly disposable loopback `mesh_test` database, user `mesh_test`, and `SECMESH_ALLOW_TEST_DB_RESET=disposable-ci-only`. It refuses arbitrary environment database URLs. Never point destructive test cleanup at operational data.

## Security review dispositions

A fresh-context, read-only architecture review preceded the final engineering pass. It identified and led to fixes for environment/namespace asset collisions, forwarded finding double-counting, unnecessary placement of generated role tokens in the API container, unbounded Wazuh response buffering, an unsafe test-database override, and stale documentation about credential rotation/browser authority. Tests cover the important behavior changes. Dependency scanning also found an outdated isolated package installer; it was upgraded to a fixed version. These are engineering review findings, not fabricated incidents in a production system.

## Operational risks and limits

- API and executor still share trusted database/signing authority. A fully compromised authorizer is outside the isolation guarantees; separate network memberships do not change that fact.
- Real deployments need HTTPS/mTLS, identity lifecycle management, an ingress-wide total request deadline/rate/concurrency policy, authenticated monitoring, secrets management, backups/restore tests, separately retained audit checkpoints, and controlled egress.
- Per-tenant write serialization favors correctness. Correlation/replay/page/history limits are explicit. There is no measured production throughput, latency SLO, resilience guarantee or absence-of-threat claim.
- Evidence redaction is bounded defense in depth and may miss unknown secret formats. Original source retention and data classification remain operator obligations.
- Cloud and provider credential chains are unverified against your future accounts. Regional API/export differences, permission boundaries, mapping changes and pagination-token expiry require live onboarding acceptance.
- Cilium policy/readback and a trusted independent probe are both needed; a failed application, DNS outage or untrusted probe must not be mistaken for successful network containment. The lab establishes baseline and restored traffic to reduce that ambiguity.
- Internal AI reservations are not provider invoices. The model/version, provider-side spend cap and external data transfer require explicit operator configuration; there is no default AI egress.
- Optional Helm rendering is not a verified production installation. You supply existing secrets, database, TLS certificates, ingress and exact egress ranges. No certificate, certification, compliance status or production outcome is claimed.
