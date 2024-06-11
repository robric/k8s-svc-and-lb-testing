# Playing around with 3-node kubernetes cluster

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
We'll get 3 VMs with kubernetes running (k3s inside)
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

### Service deployment and routing

#### bootstraping

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
#### how does a pod reaches a services ?
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
Hence, before reaching any service, there is a request to the DNS service itself... the svc plumbing is cluster IP just like the nginx-service itself but for DNS trafic (UDP 53). We'll see the deatils of how this works through iptables/NAT later. Ultimately the DNS requests reaches the coredns pod. So let's have a look at it to see how the service name resolution is enforced.
```
.----------.                                                   .---------.   
| test-pod |--(veth)---[kube-dns=10.43.0.10]----------(veth)---| coredns |
'----------'                                                   '---------'  
     |               
     |
+----------------------------------------------------------------                                                                  
|curl http://nginx-service:80/                                  |
|DNS REQUEST to 10.43.0.10: what is the IP for nginx-service ?  | 
|DNS RESPONSE from 10.43.0.10: This is IP address 10.43.180.238 |  
|                                                               |  
+----------------------------------------------------------------

TCPDUMP Traces from pod:

ubuntu@vm1:~$ kubectl  exec -it test-pod -- bash
test-pod:~# tcpdump -vni  eth0
#
# DNS REQUEST      ----   TEST-POD (10.42.1.4) TO DNS SERVICE (10.43.0.1)
#
13:09:28.510565 IP (tos 0x0, ttl 64, id 6023, offset 0, flags [DF], proto UDP (17), length 96)
    10.42.1.4.60609 > 10.43.0.10.53: 44890+ [1au] A? nginx-service.default.svc.cluster.local. (68)
13:09:28.510886 IP (tos 0x0, ttl 64, id 6024, offset 0, flags [DF], proto UDP (17), length 96)
    10.42.1.4.60609 > 10.43.0.10.53: 36406+ [1au] AAAA? nginx-service.default.svc.cluster.local. (68)
[...]
#
# DNS RESPONSE       ----  DNS SERVICE (10.43.0.1) TO TEST-POD (10.42.1.4)
#
13:09:28.512136 IP (tos 0x0, ttl 62, id 51894, offset 0, flags [DF], proto UDP (17), length 151)
    10.43.0.10.53 > 10.42.1.4.60609: 44890*- 1/0/1 nginx-service.default.svc.cluster.local. A 10.43.180.238 (123)
#
# Here we go now pod knows that nginx-service is at 10.43.180.238
#
```

#### a glance at coredns  
coredns is started via configmap which has the kube node IPs (here vm1-3). The service name resolution are not stored there since cm this would be highly unpractical: cm are ok for data that permits to start containers with appropriate parameters but not for data that requires to be updated at runtime. 

```console
ubuntu@vm1:~$ kubectl get pods -n kube-system 
NAME                                      READY   STATUS      RESTARTS   AGE
[...]
coredns-6799fbcd5-9ln42                   1/1     Running     0          23h
ubuntu@vm1:~$ kubectl get cm -n kube-system coredns  -o yaml
apiVersion: v1
data:
  Corefile: |
    .:53 {
        errors
        health
        ready
        kubernetes cluster.local in-addr.arpa ip6.arpa {
          pods insecure
          fallthrough in-addr.arpa ip6.arpa
        }
        hosts /etc/coredns/NodeHosts {
          ttl 60
          reload 15s
          fallthrough
        }
        prometheus :9153
        forward . /etc/resolv.conf
        cache 30
        loop
        reload
        loadbalance
        import /etc/coredns/custom/*.override
    }
    import /etc/coredns/custom/*.server
  NodeHosts: |
    10.65.94.95 vm3
    10.65.94.199 vm2
    10.65.94.238 vm1
ubuntu@vm1:~$ kubectl describe pod -n kube-system coredns-6799fbcd5-9ln42 | grep containerd
    Container ID:  containerd://f5499f73a98b24fbc08a2da797e44f4edd932ce838d3f6b3a5d76e4ce8a0d359

ubuntu@vm1:~$ sudo ctr c info f5499f73a98b24fbc08a2da797e44f4edd932ce838d3f6b3a5d76e4ce8a0d359
[...]
                "destination": "/etc/coredns",
                "type": "bind",
                "source": "/var/lib/kubelet/pods/05cc11a6-6aa4-4da9-b1db-e56cf20d222f/volumes/kubernetes.io~configmap/config-volume",
[...]
                "destination": "/etc/hosts",
                "type": "bind",
                "source": "/var/lib/kubelet/pods/05cc11a6-6aa4-4da9-b1db-e56cf20d222f/etc-hosts",
[...]
                "destination": "/etc/resolv.conf",
                "type": "bind",
                "source": "/var/lib/rancher/k3s/agent/containerd/io.containerd.grpc.v1.cri/sandboxes/0a3004680d3dd773b7ca99e7ec1b85c030bc96b0485f5420c20af9efdf3b3a1b/resolv.conf",
                "options": [
                    "rbind",
                    "rprivate",
                    "ro"
ubuntu@vm1:~$ sudo cat  /var/lib/kubelet/pods/05cc11a6-6aa4-4da9-b1db-e56cf20d222f/volumes/kubernetes.io~configmap/config-volume/Corefile
.:53 {
    errors
    health
    ready
    kubernetes cluster.local in-addr.arpa ip6.arpa {
      pods insecure
      fallthrough in-addr.arpa ip6.arpa
    }
    hosts /etc/coredns/NodeHosts {
      ttl 60
      reload 15s
      fallthrough
    }
    prometheus :9153
    forward . /etc/resolv.conf
    cache 30
    loop
    reload
    loadbalance
    import /etc/coredns/custom/*.override
}
import /etc/coredns/custom/*.server
ubuntu@vm1:~$ sudo cat  /var/lib/kubelet/pods/05cc11a6-6aa4-4da9-b1db-e56cf20d222f/etc-hosts
# Kubernetes-managed hosts file.
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
fe00::0 ip6-mcastprefix
fe00::1 ip6-allnodes
fe00::2 ip6-allrouters
10.42.0.2       coredns-6799fbcd5-9ln42
ubuntu@vm1:~$ sudo cat  /etc/resolv.conf
[...]
nameserver 127.0.0.53
options edns0 trust-ad
search multipass
ubuntu@vm1:~$ 
```
Service name resolution works as any kubernetes: the key/values are stored in the kube DB (e.g. etcd) and sent to coredns upon changes.

### Service Routing Details

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
