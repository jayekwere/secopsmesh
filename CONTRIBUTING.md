# Contributing

Keep the project standalone and use independently generated synthetic data or explicitly authorized test resources. Do not submit credentials, private records or proprietary infrastructure details.

Use a focused branch and pull request. Describe the concrete behavior change, affected trust boundary, evidence and limitations. Connector work needs an official contract reference, bounded parsing/transport, authentication, timeout/retry/checkpoint behavior and malformed-input tests. Live-provider acceptance must identify the authorized environment and exact result without publishing secrets; a fixture pass is not live validation.

Detection changes need versioning, a malicious scenario, benign/false-positive regression and deterministic replay expectation. Response changes need an exact scoped plan, independent authorization, durable idempotency, ambiguous-state recovery, readback and supported rollback. General remote shells and direct model-driven privileged changes are out of scope.

Run the commands in [validation](docs/VALIDATION.md). CI must pass; do not mask missing checks with unconditional success or skip flags. Update documentation and validation labels when scope changes. Follow the repository's Apache-2.0 license and disclose external code/assets with compatible attribution. This implementation does not copy upstream Wazuh, Falcosidekick or Shuffle code.
