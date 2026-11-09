# Reproducible demonstrations

Run `.venv/bin/python scripts/demo.py --output reports/demo.json` from the repository root. It creates temporary credentials/databases and owns three real loopback HTTP processes: API, executor and disposable response target. It terminates those processes when finished. Fixture records are independently generated synthetic lab data. No provider account is contacted.

| Demo | Executed logic | What it proves / does not prove |
|---|---|---|
| 1: On-premises | Wazuh JSON → normalize → rule → incident → cited report → typed plan → distinct approver → distinct executor → gate blocks `/work` → independent readback → approved rollback | Real application containment protocol and reversal. Does not prove host firewall isolation or live Wazuh agent collection. |
| 2: AWS | GuardDuty EventBridge envelope, Security Hub finding and CloudTrail StopLogging event → explicit identity alias → evidence-backed report | Provider-shaped contracts and AWS evidence correlation. No live account acceptance. |
| 3: Azure | Defender, assessment, Monitor and Sentinel incident/alert contracts → risk classification → persisted investigation history | Parsing, normalization, risk/history and API display. No Azure control plane contacted. |
| 4: GCP | SCC Pub/Sub envelope → normalized evidence/resource context → replay duplicate → audit-log correlation | Envelope validation, durable deduplication and enrichment/correlation. No real subscription or SCC deployment. |
| 5: Kubernetes | Offline harness exercises audit/Tetragon ingestion; separate disposable Cilium job performs real enforcement | See the actual Kubernetes acceptance report. Offline parser tests do not establish kernel policy enforcement. |
| 6: Hybrid | Operator-owned aliases relate lab on-premises identity to AWS role/assets → one incident cites every source | Explicit, tenant-scoped cross-environment relationship; arbitrary event hints cannot establish it. |
| 7: Failure cases | Unapproved execution, forged plan fingerprint, replay, unauthorized MCP tool and untrusted instructions over real API; additional adversarial pytest cases | Denials and durable outcome semantics. Unit/contract tests remain distinct from live-provider security testing. |

The JSON includes each scenario's status, IDs, plan fingerprints, outcome/readback details and signed audit checkpoint. It explicitly marks Kubernetes offline acceptance as requiring the separate live lab. Do not convert that status into a pass unless the actual job succeeded.

## Actual Kubernetes packet enforcement

The GitHub workflow `Kubernetes enforcement lab` uses a disposable kind cluster, pinned node image and Cilium chart, an actual Kubernetes audit policy, and restricted lab pods. It:

1. Confirms baseline HTTP traffic from a separate probe pod to the disposable victim.
2. Performs one fixed benign lab pods/exec operation to generate real audit telemetry.
3. Verifies that the response service account cannot list cluster namespaces and that admission rejects an unapproved target selector.
4. Ingests the real audit event through the same application engine and obtains independent approval.
5. Creates a typed Cilium explicit deny policy and independently observes blocked packets. Readback may reconcile bounded policy convergence without applying the mutation again.
6. Replays execution to prove no duplicate mutation, then requires a separately approved rollback and observes restored packets.
7. Retains `kubernetes-acceptance.json` and the post-rollback policy inventory.

All activity remains synthetic lab intent, even though the Kubernetes API and network enforcement are real. This release makes no claim that its fixed benign shell command is malicious or that a production attack was observed.

## Browser demonstration

After the built API is running, use the analyst credential to inspect findings, open the hybrid incident, generate a report, and propose a plan. Switch to the separate approver credential, review the full plan/fingerprint and approve it. Switch to executor to run it and inspect independent verification. Return to analyst for a rollback proposal, then repeat independent approval/execution. The automated Playwright suite performs this full sequence against the actual backend, along with evidence redaction, search, replay, audit integrity and mobile navigation.

Screenshots in `evidence/` were captured from the running application with actual system-generated synthetic records. They are not static designs or evidence of live cloud access.
