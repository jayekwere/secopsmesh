# Connector specifications and future connection guide

All cloud and external Wazuh integrations are **implemented and contract-tested, with live acceptance pending**. The source-health API measures receipt freshness; it does not attest that a provider account is connected. No provider access was supplied during development. Use only an account you authorize and read-only credentials. These commands do not deploy cloud infrastructure or enable paid products.

## Common setup

Install the locked project environment as in the README, or use the built container with a separately authorized workload identity. Serve the API behind HTTPS beyond loopback. Set `SECMESH_API_URL` to your fixed API origin. Keep response targets disabled while onboarding telemetry.

Create a source-specific principal in the API's operator configuration. Example for an AWS collector in the existing local `lab` tenant:

```sh
.venv/bin/python scripts/credential.py --config .runtime/config.json \
  --name aws-readonly --tenant lab --role collector --instance aws-account-region \
  --source aws.guardduty --source aws.securityhub --source aws.cloudtrail \
  --token-file .runtime/aws-collector.token
```

Restart the API to load the changed principal map. Inject the token from that file as `SECMESH_COLLECTOR_TOKEN` into the collector process; do not put it in command-line arguments, screenshots, source control, or provider findings. For a new tenant, issue separate observer/analyst/approver/executor credentials in both API and executor configuration using separate names. No role can select its tenant in a request body. Keep `--instance` unique for each independent account/manager/cluster collection boundary. The synthetic flag is assigned by the credential; omit `--synthetic` for your authorized live collection.

Each polling invocation is bounded to 20 pages by default (`--max-pages 1..100`). Use one checkpoint file per source and provider resource. Schedule repeated invocations in your existing runner. Checkpoint files are atomically replaced only after all records on a page receive successful API ingestion. Re-delivery after a crash is safe. Provider cursors may expire; remove only the corresponding stale checkpoint and replay the provider's available time range. Exact-delivery deduplication remains durable in the operational database.

## AWS

Use the AWS default credential chain with an explicitly read-only assumed role or workload identity; no credentials are accepted from an event. Select a region with `AWS_REGION` / `AWS_DEFAULT_REGION`. The SDK disables configured endpoint overrides, sets 5-second connect and 15-second read timeouts, and bounds standard retries to three. Relevant read permissions:

```json
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["guardduty:ListFindings","guardduty:GetFindings","securityhub:GetFindings","cloudtrail:LookupEvents"],"Resource":"*"}]}
```

Scope resource ARNs and organizational conditions where those operations support it. The wildcard is a read-only example, not a universal least-privilege policy for every deployment. The platform never needs IAM mutation permissions for ingestion.

Set `AWS_GUARDDUTY_DETECTOR_ID` to an existing detector ID, then run:

```sh
.venv/bin/python -m secopsmesh.provider_worker aws.guardduty --checkpoint .runtime/aws-gd.json
.venv/bin/python -m secopsmesh.provider_worker aws.securityhub --checkpoint .runtime/aws-sh.json
.venv/bin/python -m secopsmesh.provider_worker aws.cloudtrail --checkpoint .runtime/aws-ct.json
```

CloudTrail uses the supported event-history `LookupEvents` interface, not an unlimited trail archive. It normalizes event JSON and maps explicitly implemented high-risk operations such as `StopLogging`; it is not a complete CloudTrail analytics catalog.

For EventBridge, use an existing authorized rule for GuardDuty or Security Hub to a controlled bridge (for example, your existing Lambda or worker). That bridge authenticates to `POST /api/ingest/aws.guardduty` or `/aws.securityhub`, forwarding the EventBridge envelope unchanged. **A public unauthenticated EventBridge webhook is not implemented.** The bridge's SigV4/provider trust and your API bearer are different boundaries. [GuardDuty EventBridge contract](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings_eventbridge.html).

Live acceptance: compare original finding IDs/account/region to persisted evidence, replay one delivery and verify duplicate count, then correlate an independently observed CloudTrail record. No cloud response action is enabled.

## Azure

Use `DefaultAzureCredential` with an existing managed identity or service principal. Prefer workload federation over client secrets. Grant Security Reader at the selected subscription/resource scope; Sentinel reading requires appropriate Microsoft Sentinel Reader / Log Analytics access at the selected workspace. Event Hubs requires Azure Event Hubs Data Receiver on the selected hub/group. Authorization varies by existing organization policy; do not grant Contributor or Owner for ingestion.

For Defender alerts and recommendations set `AZURE_RESOURCE_PATH=/subscriptions/<subscription-id>`:

```sh
.venv/bin/python -m secopsmesh.provider_worker azure.defender --checkpoint .runtime/azure-alerts.json
.venv/bin/python -m secopsmesh.provider_worker azure.recommendation --checkpoint .runtime/azure-recommendations.json
```

For Sentinel incidents set `AZURE_RESOURCE_PATH=/subscriptions/<id>/resourceGroups/<group>/providers/Microsoft.OperationalInsights/workspaces/<workspace>`. For alerts associated with an incident, set it to that full workspace path followed by `/providers/Microsoft.SecurityInsights/incidents/<incident-id>`:

```sh
.venv/bin/python -m secopsmesh.provider_worker azure.sentinel --checkpoint .runtime/sentinel-incidents.json
.venv/bin/python -m secopsmesh.provider_worker azure.sentinel.alert --checkpoint .runtime/sentinel-alerts.json
```

The incident interface uses API version `2025-09-01`; Defender alerts use `2022-01-01`, assessments use `2020-01-01`. `nextLink` must remain under the configured resource path and `https://management.azure.com`; redirects are disabled. [Sentinel incidents contract](https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents/list?view=rest-securityinsights-2025-09-01).

For an existing Azure Monitor / Defender continuous export to Event Hubs, inject `AZURE_EVENTHUB_NAMESPACE`, `AZURE_EVENTHUB_NAME`, and optional `AZURE_EVENTHUB_GROUP` (default `$Default`):

```sh
.venv/bin/python -m secopsmesh.provider_worker azure.monitor --eventhub --checkpoint .runtime/azure-monitor-offsets.json
```

Use `azure.defender` or `azure.recommendation` for those exported record types. Offset checkpoints are per partition and advance only after successful API ingestion. Keep one active consumer process per checkpoint file; multiple independent consumers need an external ownership/checkpoint coordinator. Monitor exporters differ in field shape: records need a stable ID/operation ID, time, operation/display title, and resource ID. Transform unsupported custom log schemas in your authorized bridge; rejection is explicit rather than guessing security meaning.

## GCP

Use Application Default Credentials from an existing workload identity with Security Center Findings Viewer for the selected SCC scope. For Pub/Sub, grant Subscriber only on the selected subscription. Grant Logging Viewer only to the existing audit-log export identity where needed. Do not enable SCC tiers, create sinks, or provision topics without your separate authorization.

Set `GCP_SCC_PARENT=organizations/<organization-id>/sources/<source-id>` (or `projects/<project-id>/sources/<source-id>`) for the supported SCC v1 finding list:

```sh
.venv/bin/python -m secopsmesh.provider_worker gcp.scc --checkpoint .runtime/gcp-scc.json
```

For an existing SCC notification or Cloud Audit Logs export to Pub/Sub, set `GCP_SUBSCRIPTION=projects/<project-id>/subscriptions/<subscription-id>`:

```sh
.venv/bin/python -m secopsmesh.provider_worker gcp.scc --pubsub --checkpoint .runtime/gcp-scc-pubsub.json
.venv/bin/python -m secopsmesh.provider_worker gcp.audit --pubsub --checkpoint .runtime/gcp-audit-pubsub.json
```

The pull bridge acknowledges each message only after API ingestion. Redelivery after an uncertain acknowledgement is deduplicated. SCC export resource context is retained as redacted enrichment. The `message.data` base64 envelope is bounded and validated. Newer SCC regional/v2 resource families require additional live contract validation; this release does not claim support for every SCC API version. [SCC notification setup](https://docs.cloud.google.com/security-command-center/docs/how-to-notifications).

## Wazuh, Windows and Linux

Keep existing Wazuh agents and manager collection. Windows Sysmon should arrive via Wazuh's Windows EventChannel configuration for `Microsoft-Windows-Sysmon/Operational`; Linux authentication/audit events should arrive through the manager's supported log collection/decoders. SecOpsMesh consumes the resulting JSON alert (`id`, `timestamp`, `agent`, `rule`, optional `data`) and does not replace a Wazuh agent or claim to collect directly from endpoints.

For pull collection, inject `WAZUH_INDEXER_URL` (HTTPS origin), `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASSWORD`, and optional `WAZUH_CA_FILE`. Use a read-only Indexer role restricted to `wazuh-alerts-4.x-*`, with search/read only:

```sh
.venv/bin/python -m secopsmesh.provider_worker wazuh --checkpoint .runtime/wazuh-indexer.json
```

The supported query is a 100-record `search_after` scan sorted by `timestamp` and `id` over the previous 24 hours. Confirm your index mapping makes `id` sortable; customize an operator-owned adapter for other mappings. An outage longer than that lookback requires a separately authorized historical replay. CA validation cannot be disabled.

For push, install `scripts/wazuh-forwarder.py` into your authorized manager's custom integration path using the manager's documented integration mechanism and the project environment. Configure `SECMESH_API_URL` and source-specific token through a protected service environment. The first positional argument is the manager-generated JSON alert file; extra integrator arguments do not choose the destination. Select JSON alert format. Retain manager alerts if delivery fails; the forwarder retries only transient transport errors, at most three times. [Wazuh custom integration mechanism](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html).

## Kubernetes and Tetragon

Forward Kubernetes audit `Event`/`EventList` records to `POST /api/ingest/kubernetes.audit` using a cluster-specific collector principal. Use Metadata level when sufficient; avoid request bodies that may contain Kubernetes Secrets. Forward Tetragon JSON `process_exec` / `process_kprobe` records to `/api/ingest/kubernetes.tetragon`. An authenticated existing log pipeline or the signed webhook interface can carry both. SecOpsMesh does not silently install a cluster agent.

Record a unique collector `instance`, namespace, workload and service-account context. Aliases across clusters must be explicit. For response, inventory must also match source family, environment, collector instance and namespace; a matching pod name alone is insufficient. Use only a disposable `secopsmesh-lab` or `secopsmesh-lab-*` namespace and separate scoped response service account. `lab/workloads.yaml` provides RBAC plus admission policy, and `scripts/kubernetes-lab.sh` performs the actual baseline/deny/rollback packet test in a disposable runner.

## Signed webhook transport

`POST /api/webhooks/{source}` requires the collector bearer plus configured `SECMESH_WEBHOOK_KEYS` keyed by principal name. Send `X-Mesh-Time` (Unix seconds), a unique `X-Mesh-Nonce` (16..128 characters), and `X-Mesh-Signature`:

`HMAC-SHA256(key, timestamp + '.' + nonce + '.' + source + '.' + exact_request_bytes)`

The API accepts at most 60 seconds of clock skew and persistently rejects nonce replay. Native provider push authentication is **not** inferred from provider-looking JSON. Use an explicitly authenticated bridge; never bypass collector authentication to make a vendor webhook appear connected.
