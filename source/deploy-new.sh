#!/bin/bash

# Create cloud-init.yaml

#!/bin/bash

NUM_NODES=3
VM_NAMES=("vm1" "vm2" "vm3" "vm-ext")

for i in ${!VM_NAMES[@]}; do
  IP="10.123.123.$((i + 1))"  # Assign IPs sequentially
  cloud_init_file="cloud-init-${VM_NAMES[$i]}.yaml"
  
  cat > $cloud_init_file << EOF
#cloud-config
users:
  - default
  - name: ubuntu
    ssh-authorized-keys:
      - ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDj3pd3Fs1G9AL0SluJPrLnrBZHxBkYuzu0hvqwa6NDFsubVlKyVk4NgDX7TYtwLQq77qUcnWc7vHB8tfcWJ1/YdRCoZuHEfCe9rZ81AEtSUDXaMYywO7umExFO+f9pptE3Coozd4JNsu0Z6aFyjlCqj8rUPqvn7BW3PBTQ3A9i7yIxnrNeJXba4YImmB9ugJdB13QG3vbR1IORbK3o65ePNC9iRBFksBnunxPxMop4Yvhvhm/PsPrUvClIH2PFy2w+3G3Id9ARk3pGg2/BwSNw2VHj8mj3CfxFxRIdm5sIYBcl3fXuREyZjIbzLJbla00sxgRnWbL1AnXt86wyeIGIZjH1D3NKcgX1yH/WjdBtFNeDQiBipnSpaA4uVviGPSAJQi5RCeZ1Zyg8E96YlrgWPKJfV98P2OuidtfzjwAmm91Tik16lArYqt3y7Hs2Rl49ueuz9tnVS81tjaHlpOHkhtlBohzWFNhv+fmuTe0qTJKshW6Dh7pbeQZfuzUhKPc= root@fiveg-host-24-node4
#cloud-config
network:
  config: disabled
write_files:
  - path: /etc/netplan/01-netcfg.yaml
    content: |
      network:
        version: 2
        ethernets:
          ens3:
            dhcp4: true
        vlans:
          ens3.100:
            id: 100
            link: ens3
            addresses:
              - $IP/24
runcmd:
  - echo 'source <(kubectl completion bash)' >> /home/ubuntu/.bashrc
  - rm -f /etc/netplan/50-cloud-init.yaml
  - netplan apply
EOF

  # Launch VM using the generated cloud-init file
  multipass launch --name "${VM_NAMES[$i]}" --mem 8G --disk 30G --cpus 4 jammy --cloud-init $cloud_init_file
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