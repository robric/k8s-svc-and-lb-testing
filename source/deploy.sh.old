#!/bin/bash

# Create cloud-init.yaml

cat > cloud-init.yaml <<EOF
#cloud-config
users:
  - default
  - name: ubuntu
    ssh-authorized-keys:
      - $(cat ~/.ssh/id_rsa.pub)
runcmd:
 - echo 'source <(kubectl completion bash)' >> /home/ubuntu/.bashrc
EOF


# Define variable and launch VMs

NUM_NODES=3

for i in $(seq 1 $NUM_NODES); do
  multipass launch --name "vm$i" --mem 8G --disk 30G --cpus 4 jammy --cloud-init cloud-init.yaml
done

# Get IP address of the first node

echo "Waiting for IP address of the first node..."
while true; do
  FIRST_NODE_IP=$(multipass info vm1 | grep IPv4 | awk '{print $2}')
  if [ -n "$FIRST_NODE_IP" ]; then
    break
  fi
  sleep 5
done

# Install K3s on the first node

echo "Installing K3s on the first node..."
multipass exec vm1 -- bash -c 'curl -sfL https://get.k3s.io | K3S_TOKEN="12345678" K3S_KUBECONFIG_MODE="644" INSTALL_K3S_EXEC="server --disable servicelb" sh -'

echo "completed k3s install on first node ..."

# Wait for K3s server to be ready

echo "Waiting for K3s server to be ready..."
sleep 30

# Join other nodes to the cluster

for i in $(seq 2 $NUM_NODES); do
  echo "Joining vm$i to the cluster... "
  sleep 5
  multipass exec vm$i -- bash -c "curl -sfL https://get.k3s.io | K3S_TOKEN=\"12345678\" K3S_KUBECONFIG_MODE=\"644\" K3S_URL=https://$FIRST_NODE_IP:6443 sh -"
done

echo "Redundant K3s cluster deployment completed: vm1, vm2, vm3."

echo "Adding external VM for testings..."

multipass launch --name "vm-ext" --mem 2G --disk 30G --cpus 1 jammy --cloud-init cloud-init.yaml
multipass exec vm-ext -- sudo apt install lksctp-tools -y
multipass exec vm-ext -- bash -c 'curl -sfL https://get.k3s.io | K3S_KUBECONFIG_MODE="644" sh -'
multipass exec vm-ext -- sudo ip addr add 5.6.7.8/32 dev lo

echo "Defining aliases for quick access to vm (connvm1, connvm2, connvm3, connvm-ext)..."

# Aliases
alias1='alias connvm1="ssh ubuntu@10.123.123.1 -i .ssh/id_rsa"'
alias2='alias connvm2="ssh ubuntu@10.123.123.2 -i .ssh/id_rsa"'
alias3='alias connvm3="ssh ubuntu@10.123.123.3 -i .ssh/id_rsa"'
alias4='alias connvm4="ssh ubuntu@10.123.123.4 -i .ssh/id_rsa"'

# Check and add alias to .bashrc if not already present
grep -qxF "$alias1" ~/.bashrc || echo "$alias1" >> ~/.bashrc
grep -qxF "$alias2" ~/.bashrc || echo "$alias2" >> ~/.bashrc
grep -qxF "$alias3" ~/.bashrc || echo "$alias3" >> ~/.bashrc
grep -qxF "$alias4" ~/.bashrc || echo "$alias4" >> ~/.bashrc

# adding external network to the cluster

echo "Adding external network to the cluster..."

sudo ip link add link mpqemubr0 name mpqemubr0.100 type vlan id 100
sudo ip link set mpqemubr0.100 up
sudo ip addr add 10.123.123.254/24 dev mpqemubr0.100


# add vlan 100 on each vm inerface.

echo "Adding vlan 100 via interface ens3.100..."
multipass exec vm1 -- sudo ip link add link ens3 name ens3.100 type vlan id 100
multipass exec vm2 -- sudo ip link add link ens3 name ens3.100 type vlan id 100
multipass exec vm3 -- sudo ip link add link ens3 name ens3.100 type vlan id 100
multipass exec vm-ext -- sudo ip link add link ens3 name ens3.100 type vlan id 100

sleep 3

echo "Adding IP addresses..."
multipass exec vm1 -- sudo ip addr add 10.123.123.1/24 dev ens3.100
multipass exec vm2 -- sudo ip addr add 10.123.123.2/24 dev ens3.100
multipass exec vm3 -- sudo ip addr add 10.123.123.3/24 dev ens3.100
multipass exec vm-ext -- sudo ip addr add 10.123.123.4/24 dev ens3.100

sleep 3

echo "Bringing up interfaces..."
multipass exec vm1 -- sudo ip link set dev ens3.100 up
multipass exec vm2 -- sudo ip link set dev ens3.100 up
multipass exec vm3 -- sudo ip link set dev ens3.100 up
multipass exec vm-ext -- sudo ip link set dev ens3.100 up

echo "External network added to the cluster."