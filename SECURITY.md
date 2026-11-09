# Security policy

SecOpsMesh v0.1.x is a security-focused reference implementation and reproducible lab. It is not certified or approved for unattended production remediation. Use synthetic/authorized data and disposable targets until you complete your own live acceptance and operational review.

Report suspected vulnerabilities privately through this repository's GitHub Security Advisories when available. Do not open public issues containing credentials, personal records or a working exploit against a live environment. If private reporting is unavailable, open a minimal issue requesting a private coordination channel without sensitive details.

Reportable boundaries include cross-tenant evidence access, authorization/approval bypass, plan/target substitution, replayed privileged side effects, arbitrary code/command execution from telemetry, SSRF or credential disclosure, false verification success, and audit-integrity failures within the documented trust assumptions. Host/root/database/signing-authority compromise, operator-granted broad permissions, and synthetic fixture content are distinct deployment contexts and do not alone establish an application vulnerability.

Required invariants: derive tenant from identity; fail closed; preserve exact independently approved plans; commit execution intent before mutation; reconcile ambiguity read-only; keep model output advisory; never claim that no findings means secure. See [threat model](docs/THREAT-MODEL.md) and [configuration](docs/SECURITY-CONFIGURATION.md).

No guaranteed response time, support SLA, certification or vulnerability-free claim is made. Supported dependency versions and CI evidence are tied to release commits. Please include the exact version, boundary, realistic attacker authority, expected/actual behavior and a safe disposable reproduction.
