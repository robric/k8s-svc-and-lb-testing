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

Just run the following command.
```
curl -sSL https://raw.githubusercontent.com/robric/multipass-3-node-k8s/main/deploy.sh | sh
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

This section describes the logic for routing kubernetes services which is extensively based on NAT.
In summary:
- after name resolution, the trafic is sent by test-pod to the nginx-service IP address 10.43.180.238
- upon reception on veth interface at host side, DNAT is enforced to translate the service address to any of the pod IP.

This is demonstrated in the below diagram and capture (several attemps for TCPdump were necessary since there is load balancing :-)).
  
```
                                                                 deployment 3 pods
.----------.                                                       .---------.   
| test-pod |--(veth)--[host-vm1]--(routing)----[host-vm1]--(veth)--| nginx-1 | 10.42.0.8
'----------'               ^                 |                     '---------'            
         10.42.1.4         |                 |                     .---------.  
                        [ NAT ]              |-[host-vm3]--(veth)--| nginx-2 | 10.42.2.2  
                           |                 |                     '---------'
                           |                 |                     .---------.  
                           |                 |-[host-vm2]--(veth)--| nginx-3 | 10.42.1.2  
                                                                   '---------'
         iptables: NAT dest = nginx-service(10.43.180.238)

S=10.42.1.4, D=10.43.180.238 ----[NAT]---- S=10.42.1.4, D=10.42.0.8 
(this an example since DEST can be any of the nginx pods since they're loaded balanced)


#
# From test-pod:
#

test-pod:~# tcpdump -vni eth0 "tcp and port 80"

TCP SYN:
    10.42.1.4.49186 > 10.43.180.238.80: Flags [S]

TCP SYN-ACK:
    10.43.180.238.80 > 10.42.1.4.49186: Flags [S.]

#
#From host vm1 (veth interface on dest pod - nginx-1 -): 
#

ubuntu@vm1:~$ sudo tcpdump -vni veth39f5a18d

TCP SYN:
    10.42.1.4.49186 > 10.42.0.8.80: Flags [S]

TCP SYN-ACK:
    10.42.0.8.80 > 10.42.1.4.49186: Flags [S.]
```
*TIP: find out which veth is attached to a pod, since there is no such info kubectl describe.*
```
#
#  if not done: install brctl and net-tools
#

#
# Find your DMAC based on pod IP address that you get from "kubectl get pods -o wide" option.
# Herere 10.42.0.8 for pod nginx-1 = nginx-deployment-7c79c4bf97-gk7cj in vm1
#
ubuntu@vm1:~$ arp -na 
? (10.42.0.8) at 16:9b:6c:12:bd:34 [ether] on cni0
ubuntu@vm1:~$ brctl showmacs  cni0 | grep 16
  2     16:9b:6c:12:bd:34       no                 2.45
#
# First colum is the port number
#
ubuntu@vm1:~$ brctl show cni0
bridge name     bridge id               STP enabled     interfaces
cni0            8000.3e07f3337fda       no              veth06f7413c
                                                        veth39f5a18d <=========== This one is index=2 
```
OK so now let's explore how the NAT plumbing is enforced.
```
#
# First, find out the name of the rules that are involved in translation to service IP = 10.43.180.238 
# Then explore the set of rules that enforce NAT. This is ugly, but that's what iptables is.
# 
ubuntu@vm1:~$ sudo iptables-save | grep  10.43.180.238    
-A KUBE-SERVICES -d 10.43.180.238/32 -p tcp -m comment --comment "default/nginx-service cluster IP" -m tcp --dport 80 -j KUBE-SVC-V2OKYYMBY3REGZOG
-A KUBE-SVC-V2OKYYMBY3REGZOG ! -s 10.42.0.0/16 -d 10.43.180.238/32 -p tcp -m comment --comment "default/nginx-service cluster IP" -m tcp --dport 80 -j KUBE-MARK-MASQ
ubuntu@vm1:~$ sudo iptables-save | grep  KUBE-SVC-V2OKYYMBY3REGZOG
:KUBE-SVC-V2OKYYMBY3REGZOG - [0:0]
-A KUBE-SERVICES -d 10.43.180.238/32 -p tcp -m comment --comment "default/nginx-service cluster IP" -m tcp --dport 80 -j KUBE-SVC-V2OKYYMBY3REGZOG
-A KUBE-SVC-V2OKYYMBY3REGZOG ! -s 10.42.0.0/16 -d 10.43.180.238/32 -p tcp -m comment --comment "default/nginx-service cluster IP" -m tcp --dport 80 -j KUBE-MARK-MASQ
-A KUBE-SVC-V2OKYYMBY3REGZOG -m comment --comment "default/nginx-service -> 10.42.0.8:80" -m statistic --mode random --probability 0.33333333349 -j KUBE-SEP-LNMZPQ2U2A5TEEGP
-A KUBE-SVC-V2OKYYMBY3REGZOG -m comment --comment "default/nginx-service -> 10.42.1.2:80" -m statistic --mode random --probability 0.50000000000 -j KUBE-SEP-3Y75O4B4KDVD7TMA
-A KUBE-SVC-V2OKYYMBY3REGZOG -m comment --comment "default/nginx-service -> 10.42.2.2:80" -j KUBE-SEP-Z33JJVRDNG7R4HVW
ubuntu@vm1:~$ sudo iptables-save | grep  KUBE-SEP-LNMZPQ2U2A5TEEGP
:KUBE-SEP-LNMZPQ2U2A5TEEGP - [0:0]
-A KUBE-SEP-LNMZPQ2U2A5TEEGP -s 10.42.0.8/32 -m comment --comment "default/nginx-service" -j KUBE-MARK-MASQ
-A KUBE-SEP-LNMZPQ2U2A5TEEGP -p tcp -m comment --comment "default/nginx-service" -m tcp -j DNAT --to-destination 10.42.0.8:80
-A KUBE-SVC-V2OKYYMBY3REGZOG -m comment --comment "default/nginx-service -> 10.42.0.8:80" -m statistic --mode random --probability 0.33333333349 -j KUBE-SEP-LNMZPQ2U2A5TEEGP
ubuntu@vm1:~$ sudo iptables-save | grep  KUBE-SEP-3Y75O4B4KDVD7TMA
:KUBE-SEP-3Y75O4B4KDVD7TMA - [0:0]
-A KUBE-SEP-3Y75O4B4KDVD7TMA -s 10.42.1.2/32 -m comment --comment "default/nginx-service" -j KUBE-MARK-MASQ
-A KUBE-SEP-3Y75O4B4KDVD7TMA -p tcp -m comment --comment "default/nginx-service" -m tcp -j DNAT --to-destination 10.42.1.2:80
-A KUBE-SVC-V2OKYYMBY3REGZOG -m comment --comment "default/nginx-service -> 10.42.1.2:80" -m statistic --mode random --probability 0.50000000000 -j KUBE-SEP-3Y75O4B4KDVD7TMA
ubuntu@vm1:~$ sudo iptables-save | grep   KUBE-SEP-Z33JJVRDNG7R4HVW
:KUBE-SEP-Z33JJVRDNG7R4HVW - [0:0]
-A KUBE-SEP-Z33JJVRDNG7R4HVW -s 10.42.2.2/32 -m comment --comment "default/nginx-service" -j KUBE-MARK-MASQ
-A KUBE-SEP-Z33JJVRDNG7R4HVW -p tcp -m comment --comment "default/nginx-service" -m tcp -j DNAT --to-destination 10.42.2.2:80
-A KUBE-SVC-V2OKYYMBY3REGZOG -m comment --comment "default/nginx-service -> 10.42.2.2:80" -j KUBE-SEP-Z33JJVRDNG7R4HVW
ubuntu@vm1:~$  

#
# As expected the trafic is load balanced thanks to a set of rules in iptables which defines a separate entry for each target pod.
# Note that there is no SNAT and no need to do so since connection and brought up to services.
#
# KUBE-SERVICES -d 10.43.180.238/32 -m tcp --dport 80---> KUBE-SVC-V2OKYYMBY3REGZOG ----> KUBE-SEP-3Y75O4B4KDVD7TMA (DNAT  to 10.42.1.2:80)
#                                                                                   ----> KUBE-SEP-Z33JJVRDNG7R4HVW (DNAT to 10.42.2.2:80)
#                                                                                   ----> KUBE-SEP-LNMZPQ2U2A5TEEGP (DNAT to 10.42.0.8:80)
# 
```

### Nodeport 

Deploy nodeport service with:
- nodeport port: 30000
- svc port: 80
- container port: 8080
Note that nodeport has cluster IP since this is the same logic for intra-cluster communication (i.e. reaching the service from test-pod in previous section).

```
kubectl apply -f https://raw.githubusercontent.com/robric/multipass-3-node-k8s/main/nginx-np-svc.yaml
````
After deployment we have the following:
```console
ubuntu@vm1:~$ kubectl get svc -o wide
NAME               TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)        AGE   SELECTOR
kubernetes         ClusterIP   10.43.0.1       <none>        443/TCP        46h   <none>
nginx-service      ClusterIP   10.43.180.238   <none>        80/TCP         46h   app=nginx
nginx-np-service   NodePort    10.43.143.108   <none>        80:30000/TCP   20s   app=nginx-np
ubuntu@vm1:~$ 
```
We see that an additional port is now exposed (30000) for access via nodeport for external connectivity (although this is not recommended).
Now let's have a look at the iptables logic.
```
#
# standard definition of k8s service with Cluster IP  
#
ubuntu@vm1:~$ sudo iptables-save | grep  10.43.143.108 
-A KUBE-SERVICES -d 10.43.143.108/32 -p tcp -m comment --comment "default/nginx-np-service cluster IP" -m tcp --dport 80 -j KUBE-SVC-MUSBZEOMK5UKWKKU
-A KUBE-SVC-MUSBZEOMK5UKWKKU ! -s 10.42.0.0/16 -d 10.43.143.108/32 -p tcp -m comment --comment "default/nginx-np-service cluster IP" -m tcp --dport 80 -j KUBE-MARK-MASQ
ubuntu@vm1:~$ sudo iptables -S KUBE-SVC-MUSBZEOMK5UKWKKU -v
iptables v1.8.7 (nf_tables): chain `KUBE-SVC-MUSBZEOMK5UKWKKU' in table `filter' is incompatible, use 'nft' tool.

ubuntu@vm1:~$ sudo iptables -t nat -S KUBE-SVC-MUSBZEOMK5UKWKKU -v
-N KUBE-SVC-MUSBZEOMK5UKWKKU
-A KUBE-SVC-MUSBZEOMK5UKWKKU ! -s 10.42.0.0/16 -d 10.43.143.108/32 -p tcp -m comment --comment "default/nginx-np-service cluster IP" -m tcp --dport 80 -c 0 0 -j KUBE-MARK-MASQ
-A KUBE-SVC-MUSBZEOMK5UKWKKU -m comment --comment "default/nginx-np-service -> 10.42.0.10:8080" -m statistic --mode random --probability 0.33333333349 -c 0 0 -j KUBE-SEP-MQVY6GCMKDVFWQIB
-A KUBE-SVC-MUSBZEOMK5UKWKKU -m comment --comment "default/nginx-np-service -> 10.42.1.6:8080" -m statistic --mode random --probability 0.50000000000 -c 0 0 -j KUBE-SEP-6BQ3QHB6G4YIKPPI
-A KUBE-SVC-MUSBZEOMK5UKWKKU -m comment --comment "default/nginx-np-service -> 10.42.2.5:8080" -c 0 0 -j KUBE-SEP-746QLTYFWXTG2Q66
ubuntu@vm1:~$ 
#
# Nodeport 
#
ubuntu@vm1:~$ sudo iptables-save | grep  30000 
-A KUBE-ROUTER-INPUT -p tcp -m comment --comment "allow LOCAL TCP traffic to node ports - LR7XO7NXDBGQJD2M" -m addrtype --dst-type LOCAL -m multiport --dports 30000:32767 -j RETURN
-A KUBE-ROUTER-INPUT -p udp -m comment --comment "allow LOCAL UDP traffic to node ports - 76UCBPIZNGJNWNUZ" -m addrtype --dst-type LOCAL -m multiport --dports 30000:32767 -j RETURN
-A KUBE-NODEPORTS -p tcp -m comment --comment "default/nginx-np-service" -m tcp --dport 30000 -j KUBE-EXT-MUSBZEOMK5UKWKKU
ubuntu@vm1:~$ sudo iptables -t nat -L KUBE-EXT-MUSBZEOMK5UKWKKU -v
Chain KUBE-EXT-MUSBZEOMK5UKWKKU (1 references)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 KUBE-MARK-MASQ  all  --  any    any     anywhere             anywhere             /* masquerade traffic for default/nginx-np-service external destinations */
    0     0 KUBE-SVC-MUSBZEOMK5UKWKKU  all  --  any    any     anywhere             anywhere            
ubuntu@vm1:~$ 
#
# The nodeport points to the same "KUBE-SVC-MUSBZEOMK5UKWKKU" rule where NAT is enforced.
#
# KUBE-SERVICES -d 10.43.180.238/32 -m tcp --dport 80---> KUBE-SVC-MUSBZEOMK5UKWKKU -----> KUBE-SEP-MQVY6GCMKDVFWQIB (DNAT  to 10.42.0.10:8080)
#                                                     ^                              |---> KUBE-SEP-6BQ3QHB6G4YIKPPI (DNAT to 10.42.1.6:8080)
#                                                     |                              |---> KUBE-SEP-746QLTYFWXTG2Q66 (DNAT to 10.42.2.5:8080)
# KUBE-NODEPORTS -m tcp --dport 30000         ---------
#
```
Of course, all nodes have the same logic. Here is a capture from vm2.
```
ubuntu@vm2:~$ sudo iptables -t nat -L  KUBE-EXT-MUSBZEOMK5UKWKKU -v
Chain KUBE-EXT-MUSBZEOMK5UKWKKU (1 references)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 KUBE-MARK-MASQ  all  --  any    any     anywhere             anywhere             /* masquerade traffic for default/nginx-np-service external destinations */
    0     0 KUBE-SVC-MUSBZEOMK5UKWKKU  all  --  any    any     anywhere             anywhere            
ubuntu@vm2:~$ sudo iptables -t nat -L  KUBE-SVC-MUSBZEOMK5UKWKKU
Chain KUBE-SVC-MUSBZEOMK5UKWKKU (2 references)
target     prot opt source               destination         
KUBE-MARK-MASQ  tcp  -- !fiveg-host-24-node4/16  10.43.143.108        /* default/nginx-np-service cluster IP */ tcp dpt:http
KUBE-SEP-MQVY6GCMKDVFWQIB  all  --  anywhere             anywhere             /* default/nginx-np-service -> 10.42.0.10:8080 */ statistic mode random probability 0.33333333349
KUBE-SEP-6BQ3QHB6G4YIKPPI  all  --  anywhere             anywhere             /* default/nginx-np-service -> 10.42.1.6:8080 */ statistic mode random probability 0.50000000000
KUBE-SEP-746QLTYFWXTG2Q66  all  --  anywhere             anywhere             /* default/nginx-np-service -> 10.42.2.5:8080 */
ubuntu@vm2:~$ 
```




