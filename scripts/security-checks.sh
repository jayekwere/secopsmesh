#!/usr/bin/env bash
set -euo pipefail
mkdir -p .runtime/tools .runtime/iac reports
for spec in 'gitleaks/gitleaks v8.30.1 gitleaks_8.30.1_linux_x64.tar.gz gitleaks_8.30.1_checksums.txt gitleaks' 'aquasecurity/trivy v0.76.2 trivy_0.76.2_Linux-64bit.tar.gz trivy_0.76.2_checksums.txt trivy'; do
  read -r repository version archive checksums binary <<< "$spec"
  curl --fail --location --retry 3 --silent --show-error "https://github.com/$repository/releases/download/$version/$archive" --output ".runtime/tools/$archive"
  curl --fail --location --retry 3 --silent --show-error "https://github.com/$repository/releases/download/$version/$checksums" --output ".runtime/tools/$checksums"
  (cd .runtime/tools && sha256sum --check --ignore-missing "$checksums")
  tar -xzf ".runtime/tools/$archive" -C .runtime/tools "$binary"
done
.runtime/tools/gitleaks git --no-banner --redact --log-opts=-1 --report-format json --report-path reports/gitleaks.json
helm lint deploy/helm/secopsmesh --set-string image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000 --set databaseCidr=10.0.0.0/8
helm template secopsmesh deploy/helm/secopsmesh --set-string image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000 --set databaseCidr=10.0.0.0/8 > .runtime/iac/deployment.yaml
cp Dockerfile compose.yaml .runtime/iac/
.runtime/tools/trivy config --exit-code 1 --severity HIGH,CRITICAL --format json --output reports/iac-scan.json .runtime/iac
.runtime/tools/trivy image --format cyclonedx --output reports/sbom.cdx.json secopsmesh:local
test -s reports/sbom.cdx.json
.runtime/tools/trivy image --exit-code 1 --ignore-unfixed --severity HIGH,CRITICAL --format json --output reports/image-scan.json secopsmesh:local
.runtime/tools/trivy image --exit-code 1 --ignore-unfixed --severity HIGH,CRITICAL --format json --output reports/gateway-image-scan.json caddy:2-alpine@sha256:78bd35025c7ba85961dd149ae670315129954e77abe2383ac47c89106b35ade9
.runtime/tools/trivy image --exit-code 1 --ignore-unfixed --severity HIGH,CRITICAL --format json --output reports/database-image-scan.json postgres:17-alpine@sha256:3540c0362c809df084ffac0ae69fe794515f9de92692f02178bcdce0ef0302ac
