# Architecture decisions

1. A modular Python service and SQLAlchemy support PostgreSQL in deployment and SQLite for a zero-account lab. No broker: database transactions durably commit normalized events, detections, incidents and audit together. Response tasks use atomic conditional updates, with explicit reconciliation after a crash.
2. The browser never receives executor or collector credentials. Each API credential maps to one tenant, principal and fixed role set. Roles are observer, collector, analyst, approver and executor. The lab uses separately generated credentials.
3. A distinct response service owns only a disposable application's traffic gate. This is real reversible application containment, not a claim of host firewall isolation. The optional Kubernetes adapter owns only named policies in an explicitly allowlisted lab namespace; kernel enforcement must be proven with a separate traffic probe.
4. Cross-source deduplication retains each source's evidence and detects repeated deliveries. Identity/asset aliases come from trusted configuration, never from an event's arbitrary correlation hint. Correlation is time-bounded and tenant-scoped.
5. Research reviewed [Wazuh](https://github.com/wazuh/wazuh), [Falcosidekick](https://github.com/falcosecurity/falcosidekick), and [Shuffle](https://github.com/Shuffle/Shuffle) read-only. Ideas retained: supported external collection, adapter separation and explicit workflows. SecOpsMesh implements a distinct approval/readback-focused architecture; no upstream code is copied.
6. External AI remains disabled unless an operator explicitly configures it. Deterministic investigation is fully functional without a key. AI output is never authorization.

