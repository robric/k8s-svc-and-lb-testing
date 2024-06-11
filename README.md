# multipass-3-node-k8s

This is both a personal cheat sheet for k8s and have concrete examples on how things work under the the hood. 

## Prerequisite:
- multipass installed (by default on ubuntu)
- have keypair in .ssh/ (id_rsa.pub)

## VM and Cluster deployment 

Just run the following command:
```
curl -sSL https://raw.githubusercontent.com/robric/multipass-3-node-k8s/main/deploy.sh | bash
```
## k8s basics

This will create a multi-node cluster made up of 3VM based on k3s. 

```
kubectl apply -f https://raw.githubusercontent.com/robric/multipass-3-node-k8s/main/nginx-svc.yaml
```
This how the iptables is dispatched.

```
ubuntu@vm1:~/ipsec-sctp-tests/helm-charts/server$ sudo iptables -t nat -v -L KUBE-SVC-NPX46M4PTMTKRN6Y
Chain KUBE-SVC-NPX46M4PTMTKRN6Y (1 references)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 KUBE-MARK-MASQ  tcp  --  any    any    !fiveg-host-24-node4/16  10.43.0.1            /* default/kubernetes:https cluster IP */ tcp dpt:https
   30  1800 KUBE-SEP-5MZSX7EQJ56C6NAG  all  --  any    any     anywhere             anywhere             /* default/kubernetes:https -> 10.65.94.238:6443 */
ubuntu@vm1:~/ipsec-sctp-tests/helm-charts/server$ sudo iptables -t nat -v -L KUBE-SVC-V2OKYYMBY3REGZOG
Chain KUBE-SVC-V2OKYYMBY3REGZOG (1 references)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 KUBE-MARK-MASQ  tcp  --  any    any    !fiveg-host-24-node4/16  10.43.180.238        /* default/nginx-service cluster IP */ tcp dpt:http
    0     0 KUBE-SEP-LNMZPQ2U2A5TEEGP  all  --  any    any     anywhere             anywhere             /* default/nginx-service -> 10.42.0.8:80 */ statistic mode random probability 0.33333333349
    0     0 KUBE-SEP-3Y75O4B4KDVD7TMA  all  --  any    any     anywhere             anywhere             /* default/nginx-service -> 10.42.1.2:80 */ statistic mode random probability 0.50000000000
    0     0 KUBE-SEP-Z33JJVRDNG7R4HVW  all  --  any    any     anywhere             anywhere             /* default/nginx-service -> 10.42.2.2:80 */
ubuntu@vm1:~/ipsec-sctp-tests/helm-charts/server$ ip route show
default via 10.65.94.1 dev ens3 proto dhcp src 10.65.94.238 metric 100 
10.42.0.0/24 dev cni0 proto kernel scope link src 10.42.0.1 
10.42.1.0/24 via 10.42.1.0 dev flannel.1 onlink 
10.42.2.0/24 via 10.42.2.0 dev flannel.1 onlink
```
