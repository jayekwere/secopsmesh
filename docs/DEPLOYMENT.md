# Deployment and operations

## Local lab

Python 3.12+ and Node 24+ are supported; CI uses Python 3.12 on Ubuntu. Install only into a virtual environment and the project frontend directory. The README contains the exact commands. No paid service is needed.

`secopsmesh init-lab` generates a new ignored `.runtime` directory and refuses to overwrite credentials. It creates:

| File | Consumer | Contents |
|---|---|---|
| `config.json` | API process | Hash-only principal map, approval/audit key, database URL, aliases, target metadata; no lab response key |
| `executor-config.json` | Executor process | Same authority configuration plus narrowly scoped response credential |
| `tokens.json` | Operator/test harness only | Five distinct random role credentials; never mounted into application containers |
| `mesh.db` | API and executor | SQLite operational records |
| `lab.db` | Lab response process only | Gate ownership and command idempotency |

Generated secrets use 0600 files and a 0700 directory. Local processes run as the same OS user; this mode does **not** isolate a hostile process or host administrator. It tests application boundaries and network protocols. Use a private operator terminal to retrieve the appropriate local role token; never put it in public demonstration evidence.

Run lab, executor and API independently. `secopsmesh worker --once` (with injected `SECMESH_EXECUTOR_TOKEN`) processes eligible approved actions and read-only recoveries through the API; without `--once` it checks every five seconds. The UI also offers explicit executor actions. Automatic incident-triggered **proposal** is opt-in through `SECMESH_AUTO_PROPOSE=true`; it never approves a response.

## Docker Compose

`scripts/compose-config.py` creates separate ignored env files for API, executor, lab and PostgreSQL. It refuses to overwrite an existing configuration. The API never mounts the raw token file; host-side seeding sends only the collector credential. Container images are built from digest-pinned Python and Node bases, run as UID 10001, and have read-only roots, dropped capabilities, no-new-privileges, PID/memory limits and bounded writable tmpfs. The database image and state volumes are separate.

The API and executor share a PostgreSQL state network. Only the executor and lab join the response network. Networks are internal; external AI/provider polling is unavailable until the operator deliberately supplies controlled egress. Only API port 8080 is published on host loopback. The executor and target are not publicly published. The local internal network uses HTTP; beyond an isolated lab, provide authenticated TLS/mTLS transport and explicit egress policy.

```sh
.venv/bin/python scripts/compose-config.py
docker compose config --quiet
docker compose up --build -d --wait
.venv/bin/secopsmesh seed --tokens .runtime/compose/tokens.json
.venv/bin/python scripts/container-acceptance.py
docker compose logs --tail=100 api executor lab
```

`docker compose down` stops services and preserves volumes. `docker compose down -v` deletes **this named lab stack's** state; use it only when intentionally resetting the disposable lab. Credentials must remain aligned with persisted state. Restore database backups and corresponding authority keys together. The repository contains no automatic destructive cleanup against external infrastructure.

## Kubernetes

The optional chart in `deploy/helm/secopsmesh` uses externally created secrets and an externally managed PostgreSQL URL. It does not provision cloud resources or a database. Rendering/linting is distinct from operational live acceptance. Supply an immutable image digest, ingress TLS, operational database backups, and explicit network policy for your actual endpoints before considering a real deployment.

Response is restricted to a disposable `secopsmesh-lab` namespace family. The real acceptance job creates its **own named kind cluster** and isolated kubeconfig, installs pinned Cilium, loads the built app image, generates an actual pods/exec audit event, then runs the application workflow. A separate probe pod measures baseline traffic, blocked traffic and restored traffic. A response service account cannot list cluster namespaces; admission denies selecting another workload. This is isolated lab acceptance, not validation of an arbitrary production CNI installation.

Run this only on an existing authorized disposable Linux Docker runner:

```sh
SECMESH_DISPOSABLE_KUBERNETES_LAB=yes bash scripts/kubernetes-lab.sh
```

The flag is required. The script sets a task-owned kubeconfig and deletes only its named `secopsmesh-lab` cluster on exit. It does not operate against your current Kubernetes context.

## Database lifecycle and recovery

Schema creation is idempotent for an empty v0.1 installation. Start executor before API when sharing a new database; Compose enforces startup ordering. **Automated cross-version schema migrations are not implemented.** Pin the release and back up before upgrades. SQLite is for one-host labs; PostgreSQL is the intended operational backend.

The tenant audit-head lock serializes writes within a tenant; PostgreSQL locks different tenant heads independently. This deliberately favors correctness over maximum ingestion throughput. No throughput claim or HA service-level objective is made. Periodically export `/api/audit/checkpoint` to an independent append-only store. Back up the database with your usual PostgreSQL tooling and test restores separately.

After a crash, actions with expired execution leases are reconciled using readback. An uncertain mutation is never automatically retried. A plan with stale evidence or changed target configuration requires a new proposal. Database corruption, missing state or failed verification requires operator investigation. Failed probes are not proof of containment.
