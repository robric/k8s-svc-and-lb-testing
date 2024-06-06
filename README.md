# multipass-3-node-k8s

Create cloud init and 3 VMs on ubuntu host.

```
#!/bin/bash

# Create cloud-init.yaml

echo -e "#cloud-config\nusers:\n  - default\n  - name: ubuntu\n    ssh-authorized-keys:\n      - $(cat ~/.ssh/id_rsa.pub)\nwrite_files:\n  - path: /home/ubuntu/.bashrc\n    content: |\n      source <(kubectl completion bash)\n      alias k=kubectl\n " > cloud-init.yaml

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
multipass exec vm1 -- bash -c 'curl -sfL https://get.k3s.io | K3S_KUBECONFIG_MODE="644" INSTALL_K3S_EXEC="server --cluster-init --disable servicelb" sh -'

# Wait for K3s server to be ready

echo "Waiting for K3s server to be ready..."
sleep 30

TOKEN=$(multipass exec vm1 sudo cat /var/lib/rancher/k3s/server/node-token)

# Join other nodes to the cluster

for i in $(seq 2 $NUM_NODES); do
  echo "Joining vm$i to the cluster..."
  multipass exec vm$i -- bash -c "curl -sfL https://get.k3s.io | K3S_KUBECONFIG_MODE=\"644\" K3S_URL=https://$FIRST_NODE_IP:6443 K3S_TOKEN=$TOKEN sh -"
done

echo "K3s cluster deployment completed."
```

done

echo "K3s cluster deployment completed."
