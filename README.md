# multipass-3-node-k8s

This page is:
- a quick copy-paste source for rapidly bringing up test scenarios.
- an educational source so I can quickly share how things work under the the hood when interfacing with diverse people... Indeed, few people actually understand the kubernetes networking logic.
- a personal cheat sheet for k8s for fast refresh.

## Prerequisite

I just start with an ubuntu server with:
- multipass installed (by default on ubuntu)
- a keypair in .ssh/ (id_rsa.pub) so we can simply access VMs

## VM and Cluster deployment 

Just run the following command:
```
curl -sSL https://raw.githubusercontent.com/robric/multipass-3-node-k8s/main/deploy.sh | bash
```
We'll get 3 VMs with kubernetes running.
```console
root@fiveg-host-24-node4:~# multipass list 
Name                    State             IPv4             Image
test-metalbv2           Running           10.65.94.106     Ubuntu 20.04 LTS
                                          10.42.0.0
                                          10.42.0.1
vm1                     Running           10.65.94.238     Ubuntu 22.04 LTS
                                          10.42.0.0
                                          10.42.0.1
vm2                     Running           10.65.94.199     Ubuntu 22.04 LTS
                                          10.42.1.0
                                          10.42.1.1
vm3                     Running           10.65.94.95      Ubuntu 22.04 LTS
                                          10.42.2.0
                                          10.42.2.1
root@fiveg-host-24-node4:~# multipass shell vm1
[...]
Last login: Tue Jun 11 01:57:04 2024 from 10.65.94.1
ubuntu@vm1:~$ kubectl get nodes
NAME   STATUS   ROLES                  AGE   VERSION
vm1    Ready    control-plane,master   22h   v1.29.5+k3s1
vm3    Ready    <none>                 22h   v1.29.5+k3s1
vm2    Ready    <none>                 22h   v1.29.5+k3s1
ubuntu@vm1:~$ 
```

## k8s basics

Let's start with the creation of a test pod netshoot (https://github.com/nicolaka/netshoot). This is a great troubleshooting container for exploring networking.
```
kubectl run test-pod --image=nicolaka/netshoot --command -- sleep infinity
```

Next let's start a with basic service (cluster IP). This will create a multi-node cluster made up of 3VM based on k3s. 

```
kubectl apply -f https://raw.githubusercontent.com/robric/multipass-3-node-k8s/main/nginx-svc.yaml
```

This is what we get:

```console
ubuntu@vm1:~$ kubectl get svc -o wide
NAME            TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)   AGE   SELECTOR
kubernetes      ClusterIP   10.43.0.1       <none>        443/TCP   22h   <none>
nginx-service   ClusterIP   10.43.180.238   <none>        80/TCP    22h   app=nginx
ubuntu@vm1:~$ kubectl get pods -o wide
NAME                                READY   STATUS    RESTARTS   AGE     IP          NODE   NOMINATED NODE   READINESS GATES
nginx-deployment-7c79c4bf97-gk7cj   1/1     Running   0          22h     10.42.0.8   vm1    <none>           <none>
nginx-deployment-7c79c4bf97-4fdl4   1/1     Running   0          22h     10.42.2.2   vm3    <none>           <none>
nginx-deployment-7c79c4bf97-5j5bv   1/1     Running   0          22h     10.42.1.2   vm2    <none>           <none>
test-pod                            1/1     Running   0          4m35s   10.42.1.4   vm2    <none>           <none>
ubuntu@vm1:~$
```
Now let's check what happens when a pods reaches a service. Here *test-pod* reaches the *nginx-service*.

```console
ubuntu@vm1:~$ kubectl  exec -it test-pod -- curl http://nginx-service:80/
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
ubuntu@vm1:~$ 
```
First the pod needs to resolve the URL http://nginx-service:80/ via DNS. So let's check DNS configuration for test-pod.  
```console
ubuntu@vm1:~$ kubectl  exec -it test-pod -- cat /etc/resolv.conf
search default.svc.cluster.local svc.cluster.local cluster.local multipass
nameserver 10.43.0.10
options ndots:5
ubuntu@vm1:~$
```
Which is the IP of the -how suprising !- kube-dns service. 
```
ubuntu@vm1:~$ kubectl get svc -A
NAMESPACE      NAME             TYPE           CLUSTER-IP      EXTERNAL-IP   PORT(S)                        AGE
[...]
kube-system    kube-dns         ClusterIP      10.43.0.10      <none>        53/UDP,53/TCP,9153/TCP         22h
```
Hence, before reaching any service, there is a request to the DNS service itself... the svc plumbing is cluster IP just like the nginx-service itself but for DNS trafic (UDP 53). 
```
```
This how the iptables is dispatched.

```
```

podA-----> SVC_IP =10.43.180.238 
```
ubuntu@vm1:~$ kubectl  get svc  -o wide
NAME            TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)   AGE   SELECTOR
kubernetes      ClusterIP   10.43.0.1       <none>        443/TCP   22h   <none>
nginx-service   ClusterIP   10.43.180.238   <none>        80/TCP    22h   app=nginx
ubuntu@vm1:~$
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
