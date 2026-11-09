# Security Review: secopsmesh

## Scope

Static source-backed final engineering security audit of SecOpsMesh revision 6a6ed79, with one independent baseline and focused session review. Two confirmed pre-release findings require remediation before release.

- Scan mode: repository
- Target kind: git_revision
- Target ID: target_sha256_e5276c2c037ec74f1fa670a931110118f43b7068b83c015bc739acfefbeb23a1
- Revision: 6a6ed79f255d165c5d75f9084f0ad2e0d8833cb2
- Inventory strategy: repository
- Included paths: .
- Excluded paths: none
- Artifacts reviewed: SECURITY.md, README.md, CHANGELOG.md, CONTRIBUTING.md, pyproject.toml, requirements.lock, requirements.runtime.lock, .gitignore, .dockerignore, Dockerfile, compose.yaml, .github/workflows/validate.yml, .github/workflows/kubernetes.yml, src/secopsmesh/__init__.py, src/secopsmesh/adapters.py, src/secopsmesh/api.py, src/secopsmesh/cli.py, src/secopsmesh/config.py, src/secopsmesh/detection.py, src/secopsmesh/domain.py, src/secopsmesh/engine.py, src/secopsmesh/investigation.py, src/secopsmesh/lab_service.py, src/secopsmesh/labdata.py, src/secopsmesh/policy.py, src/secopsmesh/provider_worker.py, src/secopsmesh/response.py, src/secopsmesh/store.py, src/secopsmesh/transport.py, src/secopsmesh/workflow.py, tests/conftest.py, tests/test_engine.py, tests/test_investigation.py, tests/test_transports.py, tests/test_workflow.py, frontend/src/main.tsx, frontend/src/style.css, frontend/e2e/operations.spec.ts, frontend/package.json, frontend/index.html, frontend/vite.config.ts, frontend/playwright.config.ts, frontend/tsconfig.json, scripts/browser-server.py, scripts/compose-config.py, scripts/container-acceptance.py, scripts/credential.py, scripts/demo.py, scripts/kubernetes-acceptance.py, scripts/kubernetes-lab.sh, scripts/security-checks.sh, scripts/wazuh-forwarder.py, detections/rules.yaml, lab/audit-policy.yaml, lab/probe.py, lab/workloads.yaml, deploy/helm/secopsmesh/Chart.yaml, deploy/helm/secopsmesh/values.yaml, deploy/helm/secopsmesh/templates/networkpolicy.yaml, deploy/helm/secopsmesh/templates/workloads.yaml, docs/API.md, docs/AUTOMATION.md, docs/CONNECTORS.md, docs/DEMOS.md, docs/DEPLOYMENT.md, docs/DESIGN-DECISIONS.md, docs/DETECTIONS.md, docs/SECURITY-CONFIGURATION.md, docs/THREAT-MODEL.md, docs/VALIDATION.md
- Scan context: Generated design threat model preceded implementation; reconciled source-backed model incorporates fresh architecture review. Repository is standalone and uses synthetic/authorized lab data.

Limitations and exclusions:
- No runtime exploit or new external-provider test was executed within the read-only audit.
- The findings describe immutable pre-fix source; subsequent remediation must identify its exact commit and validation evidence.
- Kubernetes packet probe false can also reflect application/DNS failure; stronger durable baseline/control measurement is a follow-up.
- Trusted API and executor share database/signing authority; host/root/signing compromise is outside tenant/role isolation guarantees.
- Excluded evidence/\*\*: Generated validation JSON/XML and binary screenshots are evidence artifacts, not audited application implementation.
- Excluded frontend/package-lock.json: Third-party dependency lock data is checked by separate advisory/supply-chain validation, not an audit of dependency implementation.
- Excluded LICENSE: Standard Apache-2.0 legal text has no executable product boundary.

### Scan Summary

| Field | Value |
| --- | --- |
| Scan outcome | completed |
| Reportable findings | 2 |
| Severity mix | medium: 1, low: 1 |
| Confidence mix | high: 2 |
| Coverage | complete |
| Validation mode | static source trace with independent reviewers and parent validation |

Canonical artifacts: `scan-manifest.json`, `findings.json`, and `coverage.json`. This report is a deterministic projection of those files.

## Threat Model

# SecOpsMesh source-backed threat model

## Overview
SecOpsMesh accepts authenticated provider telemetry, normalizes bounded redacted evidence, runs versioned deterministic detections, persists tenant-scoped incidents, and exposes read-only investigation plus approval-bound response. API, executor and disposable application target are separate processes. PostgreSQL is the Compose backend; a same-user SQLite lab is also supported. External cloud/Claude acceptance was not supplied by the user and is not established by parser contracts. Sources: src/secopsmesh/api.py:126, src/secopsmesh/engine.py:58, src/secopsmesh/workflow.py:52, compose.yaml:1.

The initial design threat model preceded implementation. A fresh-context architecture reviewer independently traced the effective resources and controls; this reconciled model incorporates verified subsequent fixes. Architecture mapping is not, by itself, completed audit coverage.

## Assets and effective resources
| Workflow | Resource / effective location | Readers or authority | Control and limitation |
|---|---|---|---|
| Local API/executor | Generated absolute .runtime/mesh.db | Same OS user and both processes | Tenant predicates and SQLite write serialization; no hostile local-process isolation (src/secopsmesh/cli.py:18, src/secopsmesh/store.py:134) |
| Compose API/executor | PostgreSQL db:5432/mesh, same database role | API and executor | Internal state network; shared control-plane database authority remains trusted (scripts/compose-config.py:12, compose.yaml:3) |
| Approval/audit | SECMESH_SIGNING_KEY in both services | API signer and executor verifier/audit writer | HMAC plan binding and per-tenant audit chain; full authorizer/signing compromise can subvert this plane (src/secopsmesh/policy.py:40, src/secopsmesh/store.py:158) |
| Operator credentials | Ignored tokens.json, 0600 | Operator/test harness only | No application-container mount; API holds configured hashes and forwards only incoming executor bearer (src/secopsmesh/cli.py:18, src/secopsmesh/api.py:491, compose.yaml:29) |
| Lab response | Executor target key; separate lab.env; lab-state:/app/.runtime/lab.db | Executor and lab, not API response network | Fixed URL, typed HMAC command, durable idempotency and ownership rollback (src/secopsmesh/response.py:22, src/secopsmesh/lab_service.py:21, scripts/compose-config.py:18) |
| Kubernetes response | Configured HTTPS origin, verified CA, scoped token_file and deterministic Cilium policy | Executor | Disposable namespace, exact label/plan annotations, UID/resourceVersion delete preconditions; real RBAC/CNI/probe acceptance is distinct (src/secopsmesh/response.py:77, lab/workloads.yaml:1) |
| Provider credentials | Separate SDK collector identity/environment | Provider worker | Read-only SDK/API interfaces, scoped source bearer, bounded page/checkpoint/retry behavior (src/secopsmesh/provider_worker.py:1, src/secopsmesh/transport.py:15) |
| External AI | Fixed https://api.anthropic.com/v1/messages, only when explicitly enabled | Minimized packet recipient Anthropic | No raw evidence/identity or privileged tools; bounded I/O and reservation, not a provider invoice guarantee (src/secopsmesh/investigation.py:76) |

## Trust boundaries and security objectives
1. Client to API: configured SHA-256 bearer identity determines tenant and roles, not caller-supplied fields. Collector-only roles cannot read operational evidence. Body/nesting/count/string bounds protect parsers; per-token process-local rate limits and per-chunk timeouts do not replace a production ingress-wide total deadline. Source: src/secopsmesh/api.py:30, src/secopsmesh/adapters.py:26.
2. Collector to evidence: authenticated source allowlist, principal-derived synthetic label and collector instance, strict versioned schema, redaction and durable event IDs. A compromised collector can still lie about its authorized telemetry; normalized JSON does not prove provider authenticity. Source: src/secopsmesh/engine.py:58, src/secopsmesh/domain.py:65.
3. Evidence to correlation: operator-owned aliases or collector/source/environment/namespace/asset scope; raw relationship hints have no authority. Shared upstream references retain provenance without satisfying a multi-event threshold solely through forwarding. Stale/future evidence is excluded from current rule hits; absent findings never imply security. Source: src/secopsmesh/engine.py:40, src/secopsmesh/detection.py:43.
4. Analyst to authorization: an enabled inventory target must match exact evidence scope. Plan includes tenant, incident, action, target fingerprint, evidence digest, expiry and policy version. Independent approver reviews the exact fingerprint; a third principal executes. Approval signature and current role/expiry/evidence/target policy are rechecked. Source: src/secopsmesh/engine.py:232, src/secopsmesh/policy.py:45, src/secopsmesh/workflow.py:19.
5. API to executor: route-restricted separate service, fixed validated origin, redirects/proxies disabled, incoming executor token only. Compose excludes API from response network. Shared database/signing authority means this is not isolation from a fully compromised trusted API. Source: src/secopsmesh/api.py:476, compose.yaml:17.
6. Executor to target: commit intent and claim before one typed mutation; independent readback establishes verified outcome. Concurrent requests cannot both claim; ambiguity/restart performs readback only. No arbitrary shell capability exists in response adapters. Lab containment gates application traffic, not a host firewall. Source: src/secopsmesh/workflow.py:52, src/secopsmesh/response.py:22.
7. Evidence to AI/MCP: only two tenant-scoped read-only tools, no execution/approval tools. Claude has no tools; output schema and citations are validated and advice has no authority. External AI disabled without explicit configuration/key. Source: src/secopsmesh/api.py:363, src/secopsmesh/investigation.py:33.
8. Storage to audit consumers: HMAC chain and signed checkpoint detect tampering; an independently retained checkpoint is needed to detect truncation against a prior state. An administrator with signing authority can forge a new chain. Source: src/secopsmesh/store.py:158.

## Attacker capabilities, hypotheses and assumptions
Unauthenticated callers can reach readiness/static content but cannot use authenticated APIs. A collector can submit malicious bounded telemetry within its tenant/source scope; an analyst can propose, an approver can approve another principal and an executor can execute eligible plans, but no one configured principal satisfies all three authority checks. Provider-controlled pagination cannot leave its allowlisted origin/prefix. Evidence strings may contain prompt injection, but no model-owned privileged capability exists.

Primary hypotheses for review are cross-tenant lookup omissions, mismatched scope or plan binding, approval/lease/replay bypass, false verification, credential disclosure/SSRF, unsafe parser interpretations and resource exhaustion. These are hypotheses, not findings. Operators control configuration, rules, secrets, database and target inventory. Local host/root compromise is outside application isolation. Production deployment requires TLS, identity lifecycle, ingress-wide bounds, backups/restore validation, controlled egress and external audit retention. No production performance/SLO, absence-of-threat, certification or live cloud acceptance is established.

Severity calibration: critical means reachable unauthenticated general execution or severe cross-tenant privileged response; high means credible tenant disclosure/response-authority bypass; medium/low depend on realistic authority gain, impact and preconditions. Operator-only misconfiguration and synthetic canaries alone are not vulnerabilities.


## Findings

| Finding | Severity | Confidence | Detailed write-up |
| --- | --- | --- | --- |
| [Previous tenant data survives credential switching and delayed responses](#finding-1) | medium | high | inline below |
| [Overview counts materialize the tenant's entire incident and action history](#finding-2) | low | high | inline below |

### Confidence Scale

| Label | Meaning |
| --- | --- |
| high | Direct evidence supports the finding with no material unresolved blocker. |
| medium | Evidence supports a plausible issue, but material runtime or reachability proof remains. |
| low | Evidence is incomplete and the item is retained only for explicit follow-up. |

<a id="finding-1"></a>

### [1] Previous tenant data survives credential switching and delayed responses

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Two independent reviewers and the parent traced the exact retained-state and stale async writes in the current source. The retained replay path is deterministic; this scan did not execute the browser. |
| Category | browser session isolation |
| CWE | CWE-488 |
| Affected lines | frontend/src/main.tsx:149-150, frontend/src/main.tsx:190-207, frontend/src/main.tsx:209-217, frontend/src/main.tsx:220-245, frontend/src/main.tsx:935-938, frontend/src/main.tsx:1018-1021, frontend/src/main.tsx:1360-1370, frontend/src/main.tsx:1385-1394, frontend/src/main.tsx:1408-1417, frontend/src/main.tsx:971-978 |

#### Summary

Complete a tenant A detection replay, use Switch credential, and sign in as tenant B in the same tab: the saved A replay remains renderable. An outstanding A refresh or operation can also restore fuller A evidence, incident or action state after the transition. The backend tenant predicates remain intact.

#### Root Cause

Authenticated evidence and async continuations live in one long-lived App component, independently of the current identity. Logout neither replaces the session-owned component nor invalidates all pending operations and omits replay reset. Current identity rendering therefore consumes prior-session results.

**Request captures the current render's bearer** — `frontend/src/main.tsx:110-134`

The request uses its captured credential but has no cancellation/session-generation binding.

```typescript
  const api = useCallback(
    async (
      path: string,
      method = "GET",
      body?: unknown,
      credential = token,
    ) => {
      const response = await fetch("/api" + path, {
        method,
        headers: {
          Authorization: "Bearer " + credential,
          ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
      const result = await response.json();
      if (!response.ok)
        throw new Error(
          typeof result.detail === "string"
            ? result.detail
            : "The request could not be validated.",
        );
      return result;
    },
    [token],
```

**Late refresh replaces shared state** — `frontend/src/main.tsx:149-150`

After all requests settle, the old closure unconditionally writes data that the next identity's shell can render.

```typescript
      const responses = await Promise.all(paths.map((p) => api("/" + p)));
      setData(Object.fromEntries(paths.map((p, i) => [p, responses[i]])));
```

**Logout leaves the App instance and replay alive** — `frontend/src/main.tsx:190-207`

Most state is reset, but replay is omitted and old promises are not invalidated.

```typescript
  function logout() {
    setToken("");
    setMe(null);
    setSelected(null);
    setPacket(null);
    setReports([]);
    setCheckpoint(null);
    setData({
      overview: {},
      sources: [],
      events: [],
      incidents: [],
      actions: [],
      rules: [],
      audit: [],
      targets: [],
    });
  }
```

**Sibling incident handler writes without ownership** — `frontend/src/main.tsx:209-217`

Delayed incident/history completion can restore packet, reports and selected incident after sign-out.

```typescript
  async function inspectIncident(incident: RecordData) {
    await run(async () => {
      const [detail, history] = await Promise.all([
        api("/incidents/" + incident.id),
        api("/incidents/" + incident.id + "/investigations"),
      ]);
      setPacket(detail);
      setReports(history);
      setSelected({ kind: "incident", ...incident });
```

**Saved replay is rendered without owner check** — `frontend/src/main.tsx:971-978`

The next tenant can render the retained tenant A report.

```typescript
              {replay && (
                <section className="panel">
                  <div className="panel-heading">
                    <h2>Replay evaluation</h2>
                    <Badge>{replay.events_evaluated} events evaluated</Badge>
                  </div>
                  <pre>{JSON.stringify(replay, null, 2)}</pre>
                </section>
```

#### Validation

Verified all listed async result consumers and the replay retention branch against current source. Server-side tenant predicates and response authorization were inspected as counterevidence, so this is limited to browser session confidentiality.

Validation method: static source trace

- **Status:** confirmed

**Request captures the current render's bearer** — `frontend/src/main.tsx:110-134`

The request uses its captured credential but has no cancellation/session-generation binding.

```typescript
  const api = useCallback(
    async (
      path: string,
      method = "GET",
      body?: unknown,
      credential = token,
    ) => {
      const response = await fetch("/api" + path, {
        method,
        headers: {
          Authorization: "Bearer " + credential,
          ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
      const result = await response.json();
      if (!response.ok)
        throw new Error(
          typeof result.detail === "string"
            ? result.detail
            : "The request could not be validated.",
        );
      return result;
    },
    [token],
```

**Late refresh replaces shared state** — `frontend/src/main.tsx:149-150`

After all requests settle, the old closure unconditionally writes data that the next identity's shell can render.

```typescript
      const responses = await Promise.all(paths.map((p) => api("/" + p)));
      setData(Object.fromEntries(paths.map((p, i) => [p, responses[i]])));
```

**Logout leaves the App instance and replay alive** — `frontend/src/main.tsx:190-207`

Most state is reset, but replay is omitted and old promises are not invalidated.

```typescript
  function logout() {
    setToken("");
    setMe(null);
    setSelected(null);
    setPacket(null);
    setReports([]);
    setCheckpoint(null);
    setData({
      overview: {},
      sources: [],
      events: [],
      incidents: [],
      actions: [],
      rules: [],
      audit: [],
      targets: [],
    });
  }
```

**Sibling incident handler writes without ownership** — `frontend/src/main.tsx:209-217`

Delayed incident/history completion can restore packet, reports and selected incident after sign-out.

```typescript
  async function inspectIncident(incident: RecordData) {
    await run(async () => {
      const [detail, history] = await Promise.all([
        api("/incidents/" + incident.id),
        api("/incidents/" + incident.id + "/investigations"),
      ]);
      setPacket(detail);
      setReports(history);
      setSelected({ kind: "incident", ...incident });
```

**Saved replay is rendered without owner check** — `frontend/src/main.tsx:971-978`

The next tenant can render the retained tenant A report.

```typescript
              {replay && (
                <section className="panel">
                  <div className="panel-heading">
                    <h2>Replay evaluation</h2>
                    <Badge>{replay.events_evaluated} events evaluated</Badge>
                  </div>
                  <pre>{JSON.stringify(replay, null, 2)}</pre>
                </section>
```

Counterevidence and remaining uncertainty:
- A browser reload clears React memory; the supported same-tab Switch credential action does not reload.
- Backend tenant/role/plan checks still protect new API calls and privileged effects.

Limitations:
- No runtime exploit was executed in this read-only scan.

#### Dataflow

Tenant A bearer -\> async evidence/operation request -\> shared React state or retained replay -\> logout/B login -\> B shell, report or inspector.

**Request captures the current render's bearer** — `frontend/src/main.tsx:110-134`

The request uses its captured credential but has no cancellation/session-generation binding.

```typescript
  const api = useCallback(
    async (
      path: string,
      method = "GET",
      body?: unknown,
      credential = token,
    ) => {
      const response = await fetch("/api" + path, {
        method,
        headers: {
          Authorization: "Bearer " + credential,
          ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
      const result = await response.json();
      if (!response.ok)
        throw new Error(
          typeof result.detail === "string"
            ? result.detail
            : "The request could not be validated.",
        );
      return result;
    },
    [token],
```

**Late refresh replaces shared state** — `frontend/src/main.tsx:149-150`

After all requests settle, the old closure unconditionally writes data that the next identity's shell can render.

```typescript
      const responses = await Promise.all(paths.map((p) => api("/" + p)));
      setData(Object.fromEntries(paths.map((p, i) => [p, responses[i]])));
```

**Logout leaves the App instance and replay alive** — `frontend/src/main.tsx:190-207`

Most state is reset, but replay is omitted and old promises are not invalidated.

```typescript
  function logout() {
    setToken("");
    setMe(null);
    setSelected(null);
    setPacket(null);
    setReports([]);
    setCheckpoint(null);
    setData({
      overview: {},
      sources: [],
      events: [],
      incidents: [],
      actions: [],
      rules: [],
      audit: [],
      targets: [],
    });
  }
```

**Saved replay is rendered without owner check** — `frontend/src/main.tsx:971-978`

The next tenant can render the retained tenant A report.

```typescript
              {replay && (
                <section className="panel">
                  <div className="panel-heading">
                    <h2>Replay evaluation</h2>
                    <Badge>{replay.events_evaluated} events evaluated</Badge>
                  </div>
                  <pre>{JSON.stringify(replay, null, 2)}</pre>
                </section>
```

#### Reachability

A subsequent B operations user reuses A's live tab. The saved replay path needs no pending request; full evidence/action disclosure needs an A request to settle during or after the transition.

- **Attacker:** Subsequent tenant B operations user

Preconditions:
- Same live tab previously authenticated as A.
- Completed A replay, or an A request that settles after sign-out.

#### Severity

**Medium** — The supported same-tab transition can disclose protected security evidence to a subsequent tenant user without their holding A's credential. Reuse of a victim's live tab is required, and fuller disclosure additionally needs a pending response; no remote API or privileged response bypass is established.

An enforced session remount/invalidation boundary and delayed-response regressions would remove this path; exposure would be broader if sessions were routinely shared across tenant operators.

#### Remediation

Remount all session-owned state on sign-out/credential replacement, abort in-flight requests and reject old-session follow-up requests/results. Reset replay, inspectors, reports, checkpoints, errors and busy state together. Do not rely only on hiding the shell.

Tests:
- Two real synthetic tenants: complete A replay, sign out, log in as B observer and assert no A replay metadata remains.
- Delay A refresh/incident/action responses across sign-out/B login, release them after B data arrives and assert no A evidence/inspector is rendered.
- Ensure late operations cannot start a captured A refresh after sign-out.

<a id="finding-2"></a>

### [2] Overview counts materialize the tenant's entire incident and action history

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | The two unbounded .all() calls and Python len/sum consumers are explicit, and the metrics route reuses the same implementation. |
| Category | resource allocation limits |
| CWE | CWE-770 |
| Affected lines | src/secopsmesh/api.py:212-221, src/secopsmesh/api.py:556-559 |

#### Summary

With a growing tenant history, requesting overview or metrics deserializes every Incident and Action JSON row merely to count them. Source-authorized telemetry can grow that state; routine dashboard refresh repeatedly triggers the allocation.

#### Root Cause

A small authenticated dashboard read selects every JSON-bearing incident/action ORM object into application memory, then computes counts in Python. The per-request row allocation scales with retained tenant history instead of returning fixed-size aggregates.

**All JSON-bearing ORM rows are loaded for counts** — `src/secopsmesh/api.py:206-222`

The authenticated tenant predicate prevents disclosure, but neither query projects counts or bounds application allocation.

```python
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
```

**Metrics repeats the same materialization** — `src/secopsmesh/api.py:556-559`

The metrics endpoint calls overview, so it shares this independently reachable allocation path.

```python

    @app.get("/api/metrics", response_class=PlainTextResponse)
    def metrics(p: Principal = Depends(reader)):
        data = overview(p)
```

#### Validation

Parent verified the unbounded selects, their Python aggregate consumers, the authenticated metrics caller and source-authorized incident creation. No memory-exhaustion experiment was performed.

Validation method: static source trace

- **Status:** confirmed

**All JSON-bearing ORM rows are loaded for counts** — `src/secopsmesh/api.py:206-222`

The authenticated tenant predicate prevents disclosure, but neither query projects counts or bounds application allocation.

```python
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
```

**Metrics repeats the same materialization** — `src/secopsmesh/api.py:556-559`

The metrics endpoint calls overview, so it shares this independently reachable allocation path.

```python

    @app.get("/api/metrics", response_class=PlainTextResponse)
    def metrics(p: Principal = Depends(reader)):
        data = overview(p)
```

Counterevidence and remaining uncertainty:
- Authentication and substantial retained state are required.
- Per-token rate limiting and tenant predicates remain effective.

Limitations:
- No production scale, memory threshold or availability failure is claimed.

#### Dataflow

Source-authorized distinct-asset detections -\> retained Incident/Action history -\> overview/metrics -\> full ORM/JSON allocation -\> shared API memory and CPU pressure.

**All JSON-bearing ORM rows are loaded for counts** — `src/secopsmesh/api.py:206-222`

The authenticated tenant predicate prevents disclosure, but neither query projects counts or bounds application allocation.

```python
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
```

**Metrics repeats the same materialization** — `src/secopsmesh/api.py:556-559`

The metrics endpoint calls overview, so it shares this independently reachable allocation path.

```python

    @app.get("/api/metrics", response_class=PlainTextResponse)
    def metrics(p: Principal = Depends(reader)):
        data = overview(p)
```

#### Reachability

Authorized collection or preexisting legitimate history creates the prerequisite state; any operations reader or the normal periodic dashboard refresh triggers the allocation.

- **Attacker:** Authenticated source collector and/or operations reader

Preconditions:
- Substantial tenant incident/action history.
- An authenticated overview/metrics read.

#### Severity

**Low** — An authenticated collector or sufficiently populated legitimate tenant supplies the state prerequisite, and an operations read triggers unbounded allocation. Rate limiting reduces request frequency, and no exhaustion threshold was measured. The impact is constrained availability pressure rather than tenant disclosure or response authority.

SQL aggregate projections remove full-row allocation. Measured multi-tenant memory exhaustion at low input volume would raise impact/likelihood confidence.

#### Remediation

Replace both ORM row materializations with tenant-scoped SQL COUNT and conditional aggregate queries. Preserve exact counts without truncating the result and keep the JSON payloads out of the projection.

Tests:
- Seed incident/action history beyond list pagination bounds and verify exact tenant-specific overview and metrics counts without loading incident/action entities.

## Reviewed Surfaces

| Surface | Risk Area | Outcome | Notes |
| --- | --- | --- | --- |
| Browser tenant-session lifecycle | session confidentiality | Reported | Confirmed CWE-488 across retained replay and delayed refresh/incident/investigation/action/checkpoint consumers; same broken lifecycle control and one remediation, with every affected operation retained in finding locations. |
| Overview and metrics resource projection | availability bounds | Reported | Confirmed CWE-770 in api.py:212-221 and metrics caller; authentication/state prerequisites calibrate severity low. |
| Focused async-session corroboration | duplicate report reconciliation | Rejected | Not a separate finding: the same missing session-ownership control is reported in session-isolation.stale-react-state. All sibling asynchronous operations remain included in the confirmed finding. |
| Focused retained-replay corroboration | duplicate report reconciliation | Rejected | Not a separate finding: the retained completed replay manifestation and its distinct no-race reachability are preserved in session-isolation.stale-react-state. The vulnerability is not dismissed. |
| API authentication, tenant predicates and object scope | authorization | No issue found | api.py/config.py/engine.py/investigation.py derive tenant from a configured principal, enforce source and role scopes, and check object ownership and target telemetry scope. No server tenant or approval bypass was established. |
| Plan approval, concurrency, recovery and rollback | privileged authority | No issue found | policy.py/workflow.py/store.py/lab_service.py/response.py enforce exact signatures, independent names, expiry, current approver/evidence/target checks and atomic claims. Intent commits before mutation; ambiguous recovery is read-only. Lab command idempotency and ownership, Cilium ownership and UID/resourceVersion deletion guards were traced. |
| Provider parsing, detection, HTTP transport, AI and MCP | untrusted input and outbound authority | No issue found | Reviewed all shipped provider adapters/worker paths, safe YAML rules, bounded schema, fixed-origin/resource-prefix pagination and redaction. AI receives minimized data, has no tools, remains disabled by default and cannot authorize a response. MCP exposes two read-only tenant-scoped tools. Live provider/Claude acceptance is not established by this audit. |
| Deployment, scripts, tests, CI and credential material | credential placement and supply chain | No issue found | Independent baseline fully reviewed shipped implementation, scripts, tests, workflows, deployment and operator security documentation at 6a6ed79. No embedded real provider key/private key found; synthetic test keys, canaries and disposable CI password have source-backed dummy context. Shared database/signing authority, identity-chain operation timeouts and trusted-probe limitations are explicit assumptions. |
| Static stylesheet and generated validation evidence | executable untrusted input | Not applicable | Static CSS is fixed presentation with no dynamic code boundary. Generated reports/screenshots are excluded from application-source coverage; dependency contents are validated separately through lock/advisory/image checks. |

## Open Questions And Follow Up

- Complete live acceptance against the owner's future authorized Wazuh/AWS/Azure/GCP and optional Claude environments; no credentials were supplied.
- Strengthen Kubernetes verification with durable positive baseline/control measurements and distinguish DNS/application failure from packet timeout before treating this adapter as production response.
- Correct the stale browser/executor-credential sentence in docs/DESIGN-DECISIONS.md.
