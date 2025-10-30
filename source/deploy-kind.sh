#!/bin/bash

set -e

CLUSTER_NAME="foo"
EXTERNAL_NET="external-network"
EXTERNAL_SUBNET="10.123.123.0/24"
KIND_BASE_IMAGE="kindest/node:v1.34.0"

echo "[INFO] Updating system and installing docker..."
sudo apt-get update

# 1. Install Docker

if ! command -v docker &>/dev/null; then
  echo "[INFO] Installing Docker..."
  sudo apt-get install -y ca-certificates curl gnupg lsb-release
  sudo mkdir -p /etc/apt/keyrings
  if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
    echo "[INFO] Downloading Docker GPG key..."
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  else
    echo "[INFO] Docker GPG key already exists, skipping download."
  fi
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
  sudo apt-get update
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
  sudo usermod -aG docker $USER
  echo "[INFO] Docker installed. Please log out and back in for group changes to take effect."
fi

# 2. Install kind 

if ! command -v kind &>/dev/null; then
  echo "[INFO] Installing kind..."
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64) ARCH=amd64 ;;
    aarch64) ARCH=arm64 ;;
    *) ARCH=$ARCH ;;
  esac
  OS=$(uname | tr '[:upper:]' '[:lower:]')
  curl -Lo ./kind "https://kind.sigs.k8s.io/dl/latest/kind-${OS}-${ARCH}"
  chmod +x ./kind
  sudo mv ./kind /usr/local/bin/kind
fi

# 3. Install kubectl (binary method with redirect support)
KUBECTL_VERSION=$(curl -sL https://dl.k8s.io/release/stable.txt)

if ! command -v kubectl &>/dev/null; then
  echo "[INFO] Installing kubectl binary..."
  curl -LO "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl"
  sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
fi

# 4. Create external VLAN network

if (docker network inspect $EXTERNAL_NET &>/dev/null); then
  echo "[INFO] Docker network '$EXTERNAL_NET' already exists. Skipping creation."
else
  echo "[INFO] Creating external VLAN network '$EXTERNAL_NET'..."
  docker network create --subnet=$EXTERNAL_SUBNET $EXTERNAL_NET
fi

# 5. Create kind cluster
echo "[INFO] Customizing kind base image with better tooling !"

# Build a custom kind node image (based on the kindest/node image for the kubectl version)

TMPDIR=$(mktemp -d)
cat > "$TMPDIR/Dockerfile" <<EOF
FROM ${KIND_BASE_IMAGE}
ENV DEBIAN_FRONTEND=noninteractive
USER root
RUN apt-get update \\
  && apt-get install -y --no-install-recommends tcpdump iproute2 iputils-ping curl net-tools dnsutils telnet \\
  && apt-get clean \\
  && rm -rf /var/lib/apt/lists/*
EOF

docker build -t "${KIND_BASE_IMAGE}-custom" "$TMPDIR"
rm -rf "$TMPDIR"

echo "[INFO] Custom kind node image built and tagged as ${KIND_BASE_IMAGE}"
echo "[INFO] Creating kind cluster with 3 nodes (node-[1..3])"

kind create cluster --name "$CLUSTER_NAME" --image "${KIND_BASE_IMAGE}-custom" --config - <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    kubeadmConfigPatches:
      - |
        kind: InitConfiguration
        nodeRegistration:
          name: node-1
  - role: worker
    kubeadmConfigPatches:
      - |
        kind: JoinConfiguration
        nodeRegistration:
          name: node-2
  - role: worker
    kubeadmConfigPatches:
      - |
        kind: JoinConfiguration
        nodeRegistration:
          name: node-3
EOF

# 6. Install MetalLB

echo "[INFO] Attaching External Network with IP address 10.123.123.node_ID"

docker network connect --ip 10.123.123.1 $EXTERNAL_NET $CLUSTER_NAME-control-plane || true

docker network connect --ip 10.123.123.2 $EXTERNAL_NET $CLUSTER_NAME-worker || true
 
docker network connect --ip 10.123.123.3 $EXTERNAL_NET $CLUSTER_NAME-worker2 || true

# 7. Install MetalLB

echo "[INFO] Installing MetalLB..."
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.13.12/config/manifests/metallb-native.yaml

echo "[INFO] Waiting for MetalLB pods..."
kubectl wait --namespace metallb-system --for=condition=Ready pods --all --timeout=120s

