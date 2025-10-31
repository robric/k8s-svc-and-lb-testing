#!/bin/bash

set -e

CLUSTER_NAME="foo"
EXTERNAL_NET="external-network"
EXTERNAL_SUBNET="10.123.123.0/24"
EXTERNAL_GATEWAY="10.123.123.254"
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

# Ensure Docker daemon is running before checking/creating the network.

if ! sudo systemctl is-active --quiet docker; then
  echo "[INFO] Docker daemon is not active. Attempting to start docker..."
  sudo systemctl start docker || true
fi

# Use docker's filter to check for an exact name match for external network

if sudo docker network ls -q -f "name=^${EXTERNAL_NET}$" | grep -q .; then
  echo "[INFO] Docker network '$EXTERNAL_NET' already exists. Skipping creation."
else
  echo "[INFO] Creating external VLAN network '$EXTERNAL_NET'..."
  sudo docker network create $EXTERNAL_NET --subnet=$EXTERNAL_SUBNET --gateway=$EXTERNAL_GATEWAY
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

sudo docker build -t "${KIND_BASE_IMAGE}-custom" "$TMPDIR"
rm -rf "$TMPDIR"

echo "[INFO] Custom kind node image built and tagged as ${KIND_BASE_IMAGE}"
echo "[INFO] Creating kind cluster with 3 nodes (node-[1..3])"

sudo kind create cluster --name "$CLUSTER_NAME" --image "${KIND_BASE_IMAGE}-custom" --config - <<EOF
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

echo "[INFO] Create kubeconfig for current user"

# Create the .kube directory if it doesn't exist
mkdir -p $HOME/.kube

# Copy the Kind config to the default kubectl location
sudo kind get kubeconfig --name "$CLUSTER_NAME" > $HOME/.kube/config

# Set correct permissions
sudo chmod 600 $HOME/.kube/config

# Set correct permissions
sudo kubectl taint nodes node-1 node-role.kubernetes.io/control-plane:NoSchedule-

echo "[INFO] Fixing bashrc to get aliases and kubectl completion"

echo 'source <(kubectl completion bash)' >> $HOME/.bashrc
# echo "alias node-1='docker exec -it foo-control-plane bash -c '\''export PS1=\"(node-1) \u@\h:\w\$ \"; exec bash'\'''" >> ~/.bashrc
# echo "alias node-2='docker exec -it foo-worker bash -c '\''export PS1=\"(node-2) \u@\h:\w\$ \"; exec bash'\'''" >> ~/.bashrc
# echo "alias node-3='docker exec -it foo-worker2 bash -c '\''export PS1=\"(node-3) \u@\h:\w\$ \"; exec bash'\'''" >> ~/.bashrc

# 6. Install MetalLB

echo "[INFO] Attaching External Network with IP address 10.123.123.node_ID"

sudo docker network connect --ip 10.123.123.1 $EXTERNAL_NET $CLUSTER_NAME-control-plane || true

sudo docker network connect --ip 10.123.123.2 $EXTERNAL_NET $CLUSTER_NAME-worker || true
 
sudo docker network connect --ip 10.123.123.3 $EXTERNAL_NET $CLUSTER_NAME-worker2 || true

# 7. Install MetalLB

echo "[INFO] Installing MetalLB..."
sudo kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.13.12/config/manifests/metallb-native.yaml

echo "[INFO] Waiting for MetalLB pods..."
sudo kubectl wait --namespace metallb-system --for=condition=Ready pods --all --timeout=120s

# 8. Create external client container
echo "[INFO] Creating external client container..."
sudo docker run -dit --name external --network $EXTERNAL_NET --ip 10.123.123.4 ubuntu:latest sh

echo "[INFO] Setup complete!"

echo "[INFO] Seploying nginx service..."

kubectl apply -f https://raw.githubusercontent.com/robric/k8s-svc-and-lb-testing/refs/heads/main/source/nginx-kick.yaml


