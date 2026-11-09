#!/usr/bin/env bash
set -euo pipefail
mkdir -p .runtime/tools reports
for spec in 'gitleaks/gitleaks v8.30.1 gitleaks_8.30.1_linux_x64.tar.gz gitleaks_8.30.1_checksums.txt gitleaks' 'aquasecurity/trivy v0.76.2 trivy_0.76.2_Linux-64bit.tar.gz trivy_0.76.2_checksums.txt trivy'; do
  read -r repository version archive checksums binary <<< "$spec"
  curl --fail --location --retry 3 --silent --show-error "https://github.com/$repository/releases/download/$version/$archive" --output ".runtime/tools/$archive"
  curl --fail --location --retry 3 --silent --show-error "https://github.com/$repository/releases/download/$version/$checksums" --output ".runtime/tools/$checksums"
  (cd .runtime/tools && sha256sum --check --ignore-missing "$checksums")
  tar -xzf ".runtime/tools/$archive" -C .runtime/tools "$binary"
done
.runtime/tools/gitleaks git --no-banner --redact --log-opts=-1 --report-format json --report-path reports/gitleaks.json
.runtime/tools/trivy config --exit-code 1 --severity HIGH,CRITICAL --format json --output reports/iac-scan.json Dockerfile compose.yaml deploy
.runtime/tools/trivy image --exit-code 1 --ignore-unfixed --severity HIGH,CRITICAL --format json --output reports/image-scan.json secopsmesh:local
.runtime/tools/trivy image --format cyclonedx --output reports/sbom.cdx.json secopsmesh:local
test -s reports/sbom.cdx.json
