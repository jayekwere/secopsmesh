# API contract

The canonical route prefix is `/api`. Use `Authorization: Bearer <injected credential>`. Tenant and principal are server-derived; there is no trusted `tenant` request override. Machine-readable OpenAPI is available to an operations reader at `/api/openapi.json`. The API serves the built console from the same origin. `/health` is public and returns readiness/version only.

| Method and path | Role | Behavior |
|---|---|---|
| GET `/me` | Any configured principal | Own identity, tenant, roles, synthetic label |
| POST `/ingest/{source}` | Collector with source scope | Validate envelope/record, normalize, deduplicate, correlate and audit transactionally |
| POST `/webhooks/{source}` | Collector + signed webhook | Same ingestion plus timestamp/nonce/HMAC enforcement |
| GET `/overview` | Operations reader | Database-derived counts, synthetic count, uncertainty, receipt time |
| GET `/sources` | Operations reader | All supported source contracts, measured receipt freshness and acceptance labels |
| GET `/events?source=&asset=&offset=&limit=` | Operations reader | Up to 100 records/page, tenant-scoped, normalized evidence/provenance |
| GET `/events/{id}` | Operations reader | One tenant-owned evidence record |
| GET `/findings` | Operations reader | Logical finding groups with every evidence ID/source, bounded to 1000 recent records |
| GET `/incidents` | Operations reader | Up to 100 correlated incidents |
| GET `/incidents/{id}` | Operations reader | Incident and up to 30 cited evidence records; truncation explicit |
| POST `/incidents/{id}/investigate` | Analyst | `{ "use_ai": false }`; persist deterministic or explicitly requested AI report |
| GET `/incidents/{id}/investigations` | Operations reader | Persisted investigation history |
| POST `/mcp` | Operations reader | Restricted JSON-RPC investigation tools, described below |
| GET `/rules` | Operations reader | Validated rule schema/versions |
| POST `/replay` | Analyst | Deterministic evaluation report and audit record, no response execution |
| GET `/targets` | Operations reader | Sanitized target metadata, never response credentials |
| GET `/actions` | Operations reader | Durable plans, state and outcome history |
| POST `/actions` | Analyst | Typed plan proposal: `incident_id`, `target`, `action`, optional `original_action_id` |
| POST `/actions/{id}/approve` | Independent approver | Exact `{ "fingerprint": "<64 hex>" }` approval |
| POST `/actions/{id}/execute` | Independent executor | Proxy to separate executor, policy recheck, durable claim, mutation/readback or read-only reconciliation |
| POST `/recover` | Executor | Up to 100 eligible approvals/uncertain actions with no active lease |
| GET `/audit?offset=` | Operations reader | Latest 100 tenant audit rows/page with chain signatures |
| GET `/audit/checkpoint` | Operations reader | HMAC chain verification and signed checkpoint |
| GET `/metrics` | Operations reader | Tenant-scoped Prometheus gauge exposition |

Operations reader means observer, analyst, approver or executor; a collector-only credential cannot inspect evidence. Most missing or unauthorized object references deliberately return a generic denial without disclosing other tenants' existence. Contract violations return 422; missing authentication 401; policy denials 403; request bounds 413; rate excess 429; unavailable executor 503. Ambiguous/failed response outcomes are durable **action states**, not fabricated HTTP success indicators. Inspect `state` and `result.verification.verified`.

## Finding v1.0

Fields include `schema_version`, source/source ID/upstream origin reference, observation/receipt timestamps, title/category, severity/risk/confidence, asset/identity/environment/namespace/collector instance, defensible technique references, quality flags, synthetic provenance and bounded redacted evidence. API event views add immutable evidence `id` and logical `finding_key`. Matching upstream GuardDuty/Security Hub references group without discarding either provenance record.

Severity and risk are prioritization inputs, not calibrated probabilities. Quality flags include missing identity/asset, stale evidence, future timestamp and conflicting source revisions. No alert count or absence of findings establishes an asset's security. Retained evidence is not the original unredacted provider archive.

## Read-only MCP interface

The endpoint implements a deliberately restricted JSON-RPC MCP-compatible investigation surface: `initialize`, `tools/list`, `tools/call`. It does not implement a general-purpose MCP proxy, arbitrary client-defined tools, subscriptions, resources or privileged commands. Supported tools are `incident_evidence` and `asset_timeline`, each accepting only `incident_id`:

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"incident_evidence","arguments":{"incident_id":"<tenant-owned incident ID>"}}}
```

Unknown tools/methods or injected tenant/command arguments are denied. Every successful tool retrieval is audited. The optional Claude integration receives a minimized packet directly and no tools; its model response cannot call this API with privileged authority.
