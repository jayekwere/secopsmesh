# Security configuration

## Authority and secrets

All `/api/` routes require a bearer credential mapped by SHA-256 digest to a configured principal. Generate 256-bit random tokens; the short fixture tokens in unit tests are not deployment defaults. Each principal fixes its tenant, roles, allowed collection sources, collector instance and synthetic/live label. Unknown roles, empty authority configuration and signing keys shorter than 32 bytes fail startup.

Roles: observer reads operations data; collector ingests only its source allowlist; analyst investigates/proposes/replays; approver approves another principal's immutable plan; executor executes another requester/approver's valid plan. A principal name, not just a token, defines separation of duties. Do not issue multiple names to the same person to simulate independent approval. No public administrative API modifies role configuration.

Inject `SECMESH_SIGNING_KEY`, `SECMESH_CREDENTIALS`, `SECMESH_DATABASE_URL`, `SECMESH_TARGETS` and optional `SECMESH_ALIASES` via secret management or protected files. The API's target inventory omits response keys. Only the executor has response credentials. Provider SDK credentials belong to the separate collector, not the browser. Browser operations users may hold their own executor-role token; the browser never receives the lab HMAC key, Kubernetes bearer or provider credentials. Tokens remain in memory and disappear on reload/sign-out.

API and executor share an authorization/audit signing key and operational database authority in this release. **Compromise of the trusted API process or its database/signing authority can subvert the control plane.** The separate executor/network boundary reduces credential placement and direct target exposure; it is not a cryptographic defense against a fully compromised authorizer. A separately hardened authorizer, per-service database grants, external approval signatures and stronger host isolation are future production hardening work.

Credential removal/rotation is an operator configuration change requiring service restart. Update both services' approver maps consistently. Old approver authority is rechecked before execution. Target fingerprints bind resource identity, scope, endpoint, policy version and enabled state, excluding the secret value so that ordinary credential rotation can preserve the same approved action. A credential file's contents are not a signed plan attribute.

## Response inventory

Targets are disabled unless explicitly `enabled: true`. A target must belong to the principal tenant and match incident evidence by `asset`, `source_family`, `environment`, `collector_instance` and namespace. The action plan binds that exact inventory digest. The engine supports only `contain` and ownership-bound `rollback`; it has no arbitrary shell, URL-from-evidence or model-supplied response command.

Lab targets require a fixed origin and separate HMAC key; plaintext is restricted to loopback or the isolated Compose lab hostname. Kubernetes targets require HTTPS, verified CA, a service-account token file, exact label and disposable namespace. The adapter only writes Cilium deny policies. Use least-privilege RBAC and the admission policy from the lab, with an exact approved selector. Never reuse a cluster-admin credential. A readback without an independently functioning packet probe remains unverified.

## Transport and ingestion

The API limits request bodies to 256 KiB, nesting to 16, batches/lists to 100, object fields to 200, and strings to 64 KiB before normalization. Canonical strings have narrower schema limits. Inbound transport waits at most five seconds for each body chunk; a production reverse proxy must additionally impose a **total** request deadline, connection/concurrency limits and global rate policy. The built-in 240/minute limiter is per credential per process, not distributed across replicas.

Webhooks additionally require a timestamped HMAC over the nonce, source and exact bytes. Nonces persist in the database. Native provider authentication is terminated in the authorized bridge; provider-looking JSON is not proof of AWS/Azure/GCP provenance. Collectors may be wrong or compromised, so detection output still requires independent human review.

Provider HTTP pagination is same-origin and resource-prefix constrained, redirects/proxies are disabled, and read-only responses are limited to 1 MiB. API requests and provider workers have explicit timeout/retry/page limits. Workload identity acquisition also depends on vendor SDK credential-chain behavior; bound those processes and metadata endpoints in your deployment. Do not expose arbitrary operator connector origins as an unauthenticated configuration API.

## Evidence and AI

Persisted evidence is bounded and recursively redacted. Secret-like field names, bearer strings and common inline secret patterns are removed. Redaction is a defense in depth, **not a DLP guarantee**; avoid collecting secret-bearing Kubernetes request bodies or unrestricted command arguments. Original provider evidence should remain in its authorized source retention system. Store evidence references, not proprietary or personal records in public demos.

External AI is disabled by default. Enable it only after authorizing external transfer and injecting `ANTHROPIC_API_KEY`; set `SECMESH_AI_ENABLED=true` and an available `SECMESH_AI_MODEL` identifier. The bundled default model identifier requires provider availability verification. Only IDs, sources, redacted titles, severity and quality indicators are sent; raw records, asset identities and credentials are omitted.

Each request allows 8192 input bytes, 1024 output tokens, 32768 response bytes and a cancellable 15-second total external-request deadline in addition to I/O timeouts. There is no model tool execution. The database reserves $0.10 per attempt against a default $1/day tenant allowance, including failed attempts. This is a conservative **internal reservation model, not measured provider billing or a guaranteed invoice cap**; configure provider-side spend limits and validate pricing/model availability before enabling. Output must satisfy the schema and cite existing evidence. Advice never becomes approval.

## Audit and supply chain

Audit records form a per-tenant HMAC chain with a signed checkpoint. This detects altered records, and retained independent checkpoints can detect truncation. A database administrator possessing the signing key can forge a new chain. External checkpoint storage, key rotation procedures and tamper-resistant retention are operator responsibilities.

Python and npm dependencies are locked. Container bases use immutable digests; Actions use immutable SHA references and read-only default permissions. CI fails on lint/type/test/coverage/SAST/dependency/secret/IaC/image checks and retains machine-readable reports. Image scanning fails on fixable high/critical advisories; unfixed distribution advisories remain visible in the report and require explicit production risk assessment. No scan is a certification that a system is vulnerability-free.
