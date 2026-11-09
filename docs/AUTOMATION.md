# Controlled automation

The workflow is `pending → approved → executing → verified`, with `ambiguous` or `verification_failed` when outcome evidence is insufficient. The policy engine is a small enforceable Python policy module, an explicitly chosen equivalent to Rego. It uses typed inputs, fixed roles and predicates, no dynamic expression evaluation, plugins or shell commands. Policy behavior is covered by adversarial tests and CI.

1. A detection forms a tenant-scoped incident. An analyst proposes `contain` for an explicitly enabled, scope-matched inventory target. Optional deterministic incident-triggered rules may create the same proposal; they cannot approve it.
2. The server creates an immutable plan containing action ID, tenant, incident, target, action, original containment reference for rollback, evidence digest, target fingerprint, policy version and 15-minute expiry.
3. Another principal with approver authority reviews the exact plan and submits its fingerprint. The server requires unchanged evidence and signs the approval binding requester, approver, expiry, tenant, action and fingerprint.
4. A third principal with executor authority requests execution. The executor rechecks all bindings, current approver authority, expiry and exact evidence. It atomically claims the row and commits intent/audit **before** any network mutation.
5. The adapter performs one typed mutation. It independently reads the result through the application's data path or Kubernetes policy plus packet probe. Acknowledgement alone never produces `verified`.
6. A verified containment can be rolled back only through another analyst proposal, independent approval and execution. Lab rollback must own the current containment; Kubernetes deletion uses action ownership plus UID/resourceVersion preconditions.

Concurrent requests cannot both claim the same action. Replaying a completed execution returns its durable outcome without contacting the target. A timeout is **ambiguous**, because the target may have applied the request. After ambiguity, failed verification or a crashed/expired lease, recovery performs readback only. It never repeats the mutation. Failed readback remains visible and requires investigation; submitting more requests cannot turn an unknown result into an assumed success.

Per-operation transport retries are bounded. Privileged mutations have no blind automatic retry. An unresolved response may need a new explicitly reviewed plan after an operator establishes the actual target state. Audit history retains up to 20 readback outcomes per action while the append-only operational audit retains every attempt.

The local target is a real isolated application traffic gate: unauthenticated `/work` returns 200 before containment, 403 with matching action ownership after containment, and 200 after authorized rollback. It is **not host-wide network isolation**. Kubernetes response is a Cilium explicit deny policy; absence of a policy or an unreachable service alone is not sufficient verification. Cloud destructive/remediation actions are not implemented or silently enabled.
