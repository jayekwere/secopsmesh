"""Publish only the exact commit with complete successful acceptance evidence."""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path


def command(*arguments):
    if arguments[0] not in {"gh", "git"}:
        raise ValueError("release command is not allowlisted")
    return subprocess.check_output(arguments, text=True)  # noqa: S603 -- fixed local release tools; tag and commit are validated


def read_json(path):
    return json.loads(path.read_text())


def junit(path):
    root = ET.parse(path).getroot()  # noqa: S314 -- only bounded, trusted CI-generated test reports
    suites = list(root.iter("testsuite"))
    result = {
        key: sum(int(s.get(key, 0)) for s in suites)
        for key in ["tests", "failures", "errors", "skipped"]
    }
    if result["tests"] < 1 or result["failures"] or result["errors"]:
        raise ValueError("required test report is empty or failed")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag")
    parser.add_argument("--publish", action="store_true")
    args = parser.parse_args()
    version = tomllib.loads(Path("pyproject.toml").read_text())["project"]["version"]
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", args.tag) or args.tag != "v" + version:
        parser.error("tag must match the package version")
    commit = os.environ["GITHUB_SHA"]
    repository = os.environ["GITHUB_REPOSITORY"]
    if not re.fullmatch(r"[a-f0-9]{40}", commit) or not re.fullmatch(
        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository
    ):
        parser.error("invalid GitHub source identity")
    if (
        os.environ.get("GITHUB_REF") != "refs/heads/main"
        or command("git", "rev-parse", "HEAD").strip() != commit
    ):
        parser.error("release must run on the exact main checkout")
    destination = Path("dist/release")
    destination.mkdir(parents=True, exist_ok=True)
    if args.publish:
        for line in (destination / "SHA256SUMS").read_text().splitlines():
            expected, filename = line.split("  ", 1)
            if (
                not re.fullmatch(r"[A-Za-z0-9._-]+", filename)
                or hashlib.sha256((destination / filename).read_bytes()).hexdigest() != expected
            ):
                raise ValueError("release artifact changed after attestation preparation")
        command(
            "gh",
            "release",
            "create",
            args.tag,
            *[str(p) for p in sorted(destination.iterdir())],
            "--repo",
            repository,
            "--target",
            commit,
            "--title",
            "SecOpsMesh " + args.tag,
            "--notes-file",
            ".runtime/release-notes.md",
        )
        print("Published validated release " + args.tag + " at " + commit)
        return

    response = json.loads(
        command("gh", "api", f"repos/{repository}/actions/runs?head_sha={commit}&per_page=100")
    )
    required = {"Validate SecOpsMesh", "Kubernetes enforcement lab"}
    latest = {}
    for run in response["workflow_runs"]:
        if run["name"] in required and run["head_sha"] == commit and run["head_branch"] == "main":
            if run["name"] not in latest or run["id"] > latest[run["name"]]["id"]:
                latest[run["name"]] = run
    if set(latest) != required or any(
        r["status"] != "completed" or r["conclusion"] != "success" for r in latest.values()
    ):
        raise ValueError(
            "required security/acceptance workflows are missing, incomplete or unsuccessful for this exact commit"
        )
    evidence = Path(".runtime/release-evidence")
    evidence.mkdir(parents=True, exist_ok=True)
    for workflow_name, artifact, directory in [
        ("Validate SecOpsMesh", "application-evidence", "application"),
        ("Validate SecOpsMesh", "container-security-evidence", "containers"),
        ("Validate SecOpsMesh", "postgres-evidence", "postgres"),
        ("Kubernetes enforcement lab", "kubernetes-enforcement-evidence", "kubernetes"),
    ]:
        command(
            "gh",
            "run",
            "download",
            str(latest[workflow_name]["id"]),
            "--repo",
            repository,
            "--name",
            artifact,
            "--dir",
            str(evidence / directory),
        )
    app, containers, kube = (
        evidence / "application",
        evidence / "containers",
        evidence / "kubernetes",
    )
    backend = junit(app / "backend-junit.xml")
    browser = junit(app / "browser-junit.xml")
    postgres = junit(evidence / "postgres/postgres-junit.xml")
    coverage = read_json(app / "coverage.json")["totals"]["percent_covered"]
    if coverage < 85:
        raise ValueError("coverage threshold did not pass")
    if read_json(app / "bandit.json")["results"] or read_json(containers / "gitleaks.json"):
        raise ValueError("SAST or secret findings remain")
    if any(d.get("vulns") for d in read_json(app / "dependency-audit.json")["dependencies"]):
        raise ValueError("dependency advisories remain")
    if read_json(app / "npm-audit.json")["metadata"]["vulnerabilities"]["total"]:
        raise ValueError("frontend dependency advisories remain")
    for name in [
        "iac-scan.json",
        "image-scan.json",
        "gateway-image-scan.json",
        "database-image-scan.json",
    ]:
        report = read_json(containers / name)
        for result in report.get("Results", []):
            if any(
                v.get("Severity") in {"HIGH", "CRITICAL"} and v.get("FixedVersion")
                for v in result.get("Vulnerabilities", [])
            ):
                raise ValueError("fixable high/critical image advisories remain")
            if any(
                v.get("Severity") in {"HIGH", "CRITICAL"}
                for v in result.get("Misconfigurations", [])
            ):
                raise ValueError("high/critical infrastructure misconfiguration remains")
    kubernetes = read_json(kube / "kubernetes-acceptance.json")
    container = read_json(containers / "container-acceptance.json")
    if (
        not kubernetes["real_kubernetes_audit"]
        or not kubernetes["real_cilium_packet_enforcement"]
        or not kubernetes["checkpoint"]["valid"]
    ):
        raise ValueError("real Kubernetes enforcement acceptance missing")
    if (
        kubernetes["baseline"]["reachable"] is not True
        or kubernetes["blocked"]["reachable"] is not False
        or kubernetes["restored"]["reachable"] is not True
    ):
        raise ValueError("Kubernetes baseline/deny/rollback measurements failed")
    if (
        any(
            kubernetes[phase].get("control_reachable") is not True
            for phase in ["baseline", "blocked", "restored"]
        )
        or kubernetes["blocked"].get("reason") != "timeout"
        or kubernetes["restored"].get("reason") != "http_200"
        or not kubernetes["containment"]["result"]["baseline"]["reachable"]
    ):
        raise ValueError("independent positive preflight/control evidence missing")
    if (
        container["containment"]["state"] != "verified"
        or container["rollback"]["state"] != "verified"
    ):
        raise ValueError("container response acceptance failed")
    index = {
        "tag": args.tag,
        "commit": commit,
        "synthetic_lab": True,
        "live_external_cloud_acceptance": False,
        "runs": {
            name: {"id": r["id"], "url": r["html_url"], "conclusion": r["conclusion"]}
            for name, r in latest.items()
        },
        "backend": backend,
        "browser": browser,
        "postgres": postgres,
        "backend_coverage_percent": coverage,
        "provider_contracts": 13,
        "kubernetes_packet_enforcement": True,
        "container_response_and_rollback": True,
        "security_review": {
            "revision": "6a6ed79f255d165c5d75f9084f0ad2e0d8833cb2",
            "pre_release_findings": {"medium": 1, "low": 1},
            "remediation": "session-isolated browser state and bounded database aggregates; regression tests required",
        },
    }
    (destination / "validation-index.json").write_text(json.dumps(index, indent=2) + "\n")
    command(
        "git",
        "archive",
        "--format=tar.gz",
        "--prefix=secopsmesh-" + args.tag + "/",
        "--output=" + str(destination / ("secopsmesh-" + args.tag + "-source.tar.gz")),
        "HEAD",
    )
    with tarfile.open(
        destination / ("secopsmesh-" + args.tag + "-validation.tar.gz"), "w:gz"
    ) as archive:
        archive.add(evidence, arcname="validation")
    shutil.copyfile(
        containers / "sbom.cdx.json", destination / ("secopsmesh-" + args.tag + "-sbom.cdx.json")
    )
    checksums = [
        hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.name
        for path in sorted(destination.iterdir())
        if path.name != "SHA256SUMS"
    ]
    (destination / "SHA256SUMS").write_text("\n".join(checksums) + "\n")
    notes = f"""Validated implementation at `{commit}`.

{backend["tests"]} backend tests; {postgres["tests"]} PostgreSQL tests; {browser["tests"]} browser workflows; {coverage:.2f}% measured backend statement coverage (85% threshold). CLI/provider-worker orchestration is outside that denominator and separately exercised by the demos/contracts.

Real Docker Compose/PostgreSQL containment and approved rollback passed. The disposable Kubernetes lab passed real audit ingestion, independent approval, Cilium packet blocking and authorized restoration. All lab intent and provider fixtures are synthetic; no external AWS/Azure/GCP/Wazuh/Claude live acceptance is claimed.

SAST, strict locked dependency audit, secret scanning, infrastructure validation and fixable high/critical scans of application, gateway and database images passed. The SBOM and complete machine-readable acceptance bundle are attached. Two pre-release source-review findings (one medium, one low) were fixed and regression-tested; residual production risks remain documented.

Validation: {latest["Validate SecOpsMesh"]["html_url"]}
Kubernetes: {latest["Kubernetes enforcement lab"]["html_url"]}

See README, docs/CONNECTORS.md for future environment connection, docs/SECURITY-REVIEW.md and docs/VALIDATION.md for scope and limits. Source/validation/SBOM assets have SHA-256 checksums and GitHub build-provenance attestations.
"""
    Path(".runtime/release-notes.md").write_text(notes)
    print(json.dumps(index))


if __name__ == "__main__":
    main()
