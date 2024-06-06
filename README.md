# multipass-3-node-k8s

## Prerequisite:
- multipass installed (by default on ubuntu)
- have keypair in .ssh/ (id_rsa.pub)

## Cluster deployment

Just run the following command:
```
curl -sSL https://raw.githubusercontent.com/robric/multipass-3-node-k8s/main/deploy.sh | bash
```

This will create a multi-node cluster made up of 3VM based on k3s. 

```
kubectl apply -f https://raw.githubusercontent.com/robric/multipass-3-node-k8s/main/nginx-svc.yaml
```
