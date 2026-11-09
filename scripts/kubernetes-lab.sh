#!/usr/bin/env bash
set -euo pipefail
if [[ "${SECMESH_DISPOSABLE_KUBERNETES_LAB:-}" != "yes" ]]; then
  echo 'This script requires SECMESH_DISPOSABLE_KUBERNETES_LAB=yes and an isolated Linux Docker runner.' >&2
  exit 1
fi
mkdir -p .runtime/tools reports
export KUBECONFIG="$PWD/.runtime/kubeconfig"
curl --fail --location --retry 3 --silent --show-error https://kind.sigs.k8s.io/dl/v0.33.0/kind-linux-amd64 -o .runtime/tools/kind
curl --fail --location --retry 3 --silent --show-error https://kind.sigs.k8s.io/dl/v0.33.0/kind-linux-amd64.sha256sum -o .runtime/tools/kind.sha256sum
(cd .runtime/tools && sed 's/kind-linux-amd64/kind/' kind.sha256sum | sha256sum --check)
chmod +x .runtime/tools/kind
cat > .runtime/kind.yaml <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
nodes:
  - role: control-plane
    image: kindest/node:v1.34.11@sha256:44e222ee2132dab25ff87301682f89eb82c7880ea3a1bf543bfe9708fd08d67d
    kubeadmConfigPatches:
      - |
        kind: ClusterConfiguration
        apiServer:
          extraArgs:
            audit-log-path: /var/log/kubernetes/audit.log
            audit-policy-file: /etc/kubernetes/policies/audit-policy.yaml
            audit-log-mode: blocking
          extraVolumes:
            - name: audit-policy
              hostPath: /etc/kubernetes/policies
              mountPath: /etc/kubernetes/policies
              readOnly: true
              pathType: DirectoryOrCreate
            - name: audit-log
              hostPath: /var/log/kubernetes
              mountPath: /var/log/kubernetes
              readOnly: false
              pathType: DirectoryOrCreate
    extraMounts:
      - hostPath: $PWD/lab/audit-policy.yaml
        containerPath: /etc/kubernetes/policies/audit-policy.yaml
        readOnly: true
EOF
cleanup() {
  if [[ -n "${probe_pid:-}" ]]; then kill "$probe_pid" 2>/dev/null || true; fi
  .runtime/tools/kind delete cluster --name secopsmesh-lab
}
trap cleanup EXIT
.runtime/tools/kind create cluster --name secopsmesh-lab --config .runtime/kind.yaml --wait 90s
helm repo add cilium https://helm.cilium.io/
helm install cilium cilium/cilium --version 1.20.4 --namespace kube-system --set ipam.mode=kubernetes --set operator.replicas=1 --set kubeProxyReplacement=false --wait --timeout 6m
kubectl -n kube-system rollout status daemonset/cilium --timeout=180s
docker build -t secopsmesh:lab .
.runtime/tools/kind load docker-image --name secopsmesh-lab secopsmesh:lab
kubectl create namespace secopsmesh-lab
kubectl -n secopsmesh-lab create configmap packet-probe --from-file=probe.py=lab/probe.py
kubectl apply -f lab/workloads.yaml
kubectl -n secopsmesh-lab wait --for=condition=Ready pod/lab-workload pod/packet-probe pod/probe-control --timeout=180s
kubectl -n secopsmesh-lab port-forward service/packet-probe 18091:8080 > .runtime/probe-forward.log 2>&1 &
probe_pid=$!
# This fixed disposable-lab command creates a real pods/exec audit event; it is never an application remediation capability.
kubectl -n secopsmesh-lab exec lab-workload -- /bin/sh -c 'printf synthetic-lab-activity'
sleep 2
docker cp secopsmesh-lab-control-plane:/var/log/kubernetes/audit.log .runtime/kube-audit.jsonl
cp .runtime/kube-audit.jsonl reports/kubernetes-audit.jsonl
kubectl -n secopsmesh-lab create token mesh-responder --duration=15m > .runtime/kube-token
chmod 600 .runtime/kube-token
kubectl config view --raw --minify -o json > .runtime/kube-connection.json
chmod 600 .runtime/kube-connection.json
.venv/bin/python scripts/kubernetes-acceptance.py
kubectl -n secopsmesh-lab get ciliumnetworkpolicies -o json > reports/kubernetes-policies-after-rollback.json
