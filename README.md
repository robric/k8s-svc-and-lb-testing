# Looking under the hood: clusterIP, nodeport and metallb

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
curl -sSL https://raw.githubusercontent.com/robric/multipass-3-node-k8s/main/source/deploy.sh | sh
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

##  K8s basic service deployment and routing analysis

### Bootstraping

Let's start with the creation of a test pod netshoot (https://github.com/nicolaka/netshoot). This is a great troubleshooting container for exploring networking.
```
kubectl run test-pod --image=nicolaka/netshoot --command -- sleep infinity
```

Next let's start a with basic service (cluster IP). This will create a multi-node cluster made up of 3VM based on k3s. 

```
kubectl apply -f https://raw.githubusercontent.com/robric/multipass-3-node-k8s/main/source/nginx-svc.yaml
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
### How does a pod reaches a services ?
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

### A glance at coredns  
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

In other KRM words, this is what we have:
```apiVersion: v1
kind: Service
metadata:
  name: nginx-np-service
spec:
  selector:
    app: nginx-np
  ports:
    - protocol: TCP
      port: 80
      targetPort: 8080
      nodePort: 30000
  type: NodePort
```
Let's start a new deployment with this nodeport:
```
kubectl apply -f https://raw.githubusercontent.com/robric/multipass-3-node-k8s/main/source/nginx-np-svc.yaml
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
Note that nodeport has cluster IP since this is the same logic for intra-cluster communication (i.e. reaching the service from test-pod in previous section).

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

The nodeport points to the same "KUBE-SVC-MUSBZEOMK5UKWKKU" rule where NAT is enforced.
```
Here is a diagram that summarizes the added logic of nodeports in iptables.
```

KUBE-SERVICES -d 10.43.180.238/32 -m tcp --dport 80---> KUBE-SVC-MUSBZEOMK5UKWKKU +---> KUBE-SEP-MQVY6GCMKDVFWQIB (DNAT  to 10.42.0.10:8080)
                                                        ^                         |---> KUBE-SEP-6BQ3QHB6G4YIKPPI (DNAT to 10.42.1.6:8080)
                                                        |                         |---> KUBE-SEP-746QLTYFWXTG2Q66 (DNAT to 10.42.2.5:8080)
                                            KUBE-EXT-MUSBZEOMK5UKWKKU
                                                        |                              
KUBE-NODEPORTS -m tcp --dport 30000         -------------

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
## Metalb Integration on 3 node cluster

### Target Design

We're now adding an external interface to the current networking thanks to a vlan (vlan 100).

```
            +----------------------------------------------+    
            |                   Cluster                    |    
            | +------------+ +------------+ +------------+ |   
            | |     vm1    | |    vm2     | |    vm3     | |    
            | +----ens3----+ +---ens3-----+ +---ens3-----+ |   
            |      |  |.1/24        |.2/24         |.3/24  |    
            +------|--|-------------|--------------|-------+    
                   |  |             |              |                     
                   |  |             |              |             
                   |  |             |              |              
                   |  |---------vlan 100 (external)-----
                   |              10.123.123.0/24   |              
                   |                                |     
                   |                          [mpqemubr0.100]          
                   |                         10.123.123.254/24          
                   |                                                                       
             ------|------ native vlan (internal)------
                        |         10.65.94.0/24        
                        |
                        |
                 [mpqemubr0]
                 10.65.94.1/24
```
On the host where VM are executed, execute the following script:

```
curl -sSL https://raw.githubusercontent.com/robric/multipass-3-node-k8s/main/source/external-net.sh | sh
```

### Metalb Deployment

We'll use info from https://metallb.universe.tf/installation. We also choose the k8s/FRR version because we're a bunch of network nerds.
To deploy metalb, just apply the following manifest in master (vm1):
``` 
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.14.5/config/manifests/metallb-frr-k8s.yaml
```

### Test in L2 mode

#### Deployment with 3 pods and Single VIP in the external network

We want to expose a dedicated load balancer IP=10.123.123.100 outside the cluster thanks to the external vlan.

```
           +-----------------------------------------------+    
            |                   Cluster                     |    
            | +------------+ +------------+  +------------+ |   
            | |   nginx-1  | |   nginx-2  |  |   nginx-3  | |
            | |            | |            |  |            | |
            | |    vm1     | |    vm2     |  |     vm3    | |
            | |            | |            |  |            | |
            | +----ens3.100+ +---ens3.100-+ +---ens3.100--+ |   
            |        |             |              |         |    
            +--------|-------------|--------------|---------+    
                     |             |              |  
                [ ========= VIP = 10.123.123.100:80 =========]                  
                     |             |              |             
                     |             |              |              
                  ---+--+------vlan 100 (external)+-----
                        |         10.123.123.0/24         
                        |
                        |
                 [mpqemubr0.100]
                 10.123.123.1/24
```
Deploy the metalb service in L2 mode. It will reach the same pods as the basic nginx service thanks to selector.

```
kubectl apply -f https://raw.githubusercontent.com/robric/multipass-3-node-k8s/main/source/nginx-mlb-svc.yaml
```
We're having now a new service of Type LoadBalancer which has an external IP.

```console
ubuntu@vm1:~$ kubectl  get svc -o wide
NAME                   TYPE           CLUSTER-IP      EXTERNAL-IP      PORT(S)        AGE    SELECTOR
kubernetes             ClusterIP      10.43.0.1       <none>           443/TCP        4d1h   <none>
nginx-service          ClusterIP      10.43.180.238   <none>           80/TCP         4d1h   app=nginx
nginx-np-service       NodePort       10.43.143.108   <none>           80:30000/TCP   2d3h   app=nginx-np
nginx-mlb-l2-service   LoadBalancer   10.43.159.55    10.123.123.100   80:30329/TCP   23h    app=nginx-lbl2

ubuntu@vm1:~$ kubectl  get pods -o wide | grep l2
nginx-lbl2-577c9489d-879qj             1/1     Running   0          23h    10.42.1.20   vm2    <none>           <none>
nginx-lbl2-577c9489d-fvk7g             1/1     Running   0          23h    10.42.1.21   vm2    <none>           <none>
nginx-lbl2-577c9489d-fclfn             1/1     Running   0          23h    10.42.0.25   vm1    <none>           <none>
ubuntu@vm1:~$ 

```
We can notice that this an extension of nodeport (a random 30329 port is chosen), the latter being an extension of cluster IP.
We can issue a few request, both from:
- vm1 (the master/worker node)
- An external endpoint such as the host (here fiveg-host-24-node4).
```console
ubuntu@vm1:~$ curl 10.123.123.100

 Welcome to NGINX! 
 This is the pod IP address: 10.42.1.21 
 
ubuntu@vm1:~$ curl 10.123.123.100

 Welcome to NGINX! 
 This is the pod IP address: 10.42.0.25 
 
ubuntu@vm1:~$ 
 
root@fiveg-host-24-node4:~# curl 10.123.123.100

 Welcome to NGINX! 
 This is the pod IP address: 10.42.1.20 
```
We can check the owner of the VIP thanks to mac inspection, we also see some side effect 
```
#
# From external host/gw:
#

root@fiveg-host-24-node4:~#  arp -na | grep .123.123
? (10.123.123.2) at 52:54:00:c0:87:a0 [ether] on mpqemubr0.100  <============= VIP
? (10.123.123.1) at 52:54:00:c0:87:a0 [ether] on mpqemubr0.100  <============== Whaaat vm1 IP has VM2 mac ???
? (10.123.123.100) at 52:54:00:c0:87:a0 [ether] on mpqemubr0.100 <============= VIP

#
# From vm2:
#

ubuntu@vm2:~$ ip link show dev ens3
2: ens3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether 52:54:00:c0:87:a0 brd ff:ff:ff:ff:ff:ff <========================= This is the mac
#
# If we ping from host to vm1 we see packets transiting via vm2:
#
ubuntu@vm2:~$ sudo tcpdump -evni ens3.100
tcpdump: listening on ens3.100, link-type EN10MB (Ethernet), snapshot length 262144 bytes
05:59:14.860278 52:54:00:e4:50:da > 52:54:00:c0:87:a0, ethertype IPv4 (0x0800), length 98: (tos 0x0, ttl 64, id 32968, offset 0, flags [DF], proto ICMP (1), length 84)
    10.123.123.254 > 10.123.123.1: ICMP echo request, id 240, seq 1, length 64
#
# We can check that proxy arp is disabled
#
ubuntu@vm2:~$ cat /proc/sys/net/ipv4/conf/ens3.100/proxy_arp
0
```
Here is the bulk of iptables for bookkeeping. Just look at the diagram right after: the lb is basically another branch to the external service associated with the nodeport.
```
ubuntu@vm1:~$ sudo iptables-save | grep  10.123.123.100
-A KUBE-SERVICES -d 10.123.123.100/32 -p tcp -m comment --comment "default/nginx-mlb-l2-service loadbalancer IP" -m tcp --dport 80 -j KUBE-EXT-W47NQ5DDJKUWFTVY
ubuntu@vm1:~$ sudo iptables-save | grep KUBE-EXT-W47NQ5DDJKUWFTVY
:KUBE-EXT-W47NQ5DDJKUWFTVY - [0:0]
-A KUBE-EXT-W47NQ5DDJKUWFTVY -m comment --comment "masquerade traffic for default/nginx-mlb-l2-service external destinations" -j KUBE-MARK-MASQ
-A KUBE-EXT-W47NQ5DDJKUWFTVY -j KUBE-SVC-W47NQ5DDJKUWFTVY
-A KUBE-NODEPORTS -p tcp -m comment --comment "default/nginx-mlb-l2-service" -m tcp --dport 30329 -j KUBE-EXT-W47NQ5DDJKUWFTVY
-A KUBE-SERVICES -d 10.123.123.100/32 -p tcp -m comment --comment "default/nginx-mlb-l2-service loadbalancer IP" -m tcp --dport 80 -j KUBE-EXT-W47NQ5DDJKUWFTVY
ubuntu@vm1:~$ sudo iptables-save | grep 10.43.159.55
-A KUBE-SERVICES -d 10.43.159.55/32 -p tcp -m comment --comment "default/nginx-mlb-l2-service cluster IP" -m tcp --dport 80 -j KUBE-SVC-W47NQ5DDJKUWFTVY
-A KUBE-SVC-W47NQ5DDJKUWFTVY ! -s 10.42.0.0/16 -d 10.43.159.55/32 -p tcp -m comment --comment "default/nginx-mlb-l2-service cluster IP" -m tcp --dport 80 -j KUBE-MARK-MASQ
ubuntu@vm1:~$ sudo iptables-save | grep KUBE-SVC-W47NQ5DDJKUWFTVY
:KUBE-SVC-W47NQ5DDJKUWFTVY - [0:0]
-A KUBE-EXT-W47NQ5DDJKUWFTVY -j KUBE-SVC-W47NQ5DDJKUWFTVY
-A KUBE-SERVICES -d 10.43.159.55/32 -p tcp -m comment --comment "default/nginx-mlb-l2-service cluster IP" -m tcp --dport 80 -j KUBE-SVC-W47NQ5DDJKUWFTVY
-A KUBE-SVC-W47NQ5DDJKUWFTVY ! -s 10.42.0.0/16 -d 10.43.159.55/32 -p tcp -m comment --comment "default/nginx-mlb-l2-service cluster IP" -m tcp --dport 80 -j KUBE-MARK-MASQ
-A KUBE-SVC-W47NQ5DDJKUWFTVY -m comment --comment "default/nginx-mlb-l2-service -> 10.42.0.25:8080" -m statistic --mode random --probability 0.33333333349 -j KUBE-SEP-H3SFLVALEZ5LECV3
-A KUBE-SVC-W47NQ5DDJKUWFTVY -m comment --comment "default/nginx-mlb-l2-service -> 10.42.1.20:8080" -m statistic --mode random --probability 0.50000000000 -j KUBE-SEP-U6NBO3SO7ES56QIU
-A KUBE-SVC-W47NQ5DDJKUWFTVY -m comment --comment "default/nginx-mlb-l2-service -> 10.42.1.21:8080" -j KUBE-SEP-UV3QYGUSRGNZ7JSO
ubuntu@vm1:~$ 
```
In more human-friendly ways:
```
KUBE-SERVICES -d 10.43.159.55/32 -p tcp --dport 80---> KUBE-SVC-W47NQ5DDJKUWFTVY +--> DNAT  to 10.42.0.25:8080 / KUBE-SEP-H3SFLVALEZ5LECV3 
                                                         ^                       |--> DNAT  to 10.42.1.20:8080 / KUBE-SEP-U6NBO3SO7ES56QIU
                                                         |                       |--> DNAT  to 10.42.1.21:8080 / KUBE-SEP-UV3QYGUSRGNZ7JSO
                                            KUBE-EXT-W47NQ5DDJKUWFTVY
                                                        ^   ^                              
KUBE-NODEPORTS -m tcp --dport 30329         ------------|   |
                                                            | 
                                                            | 
KUBE-SERVICES -d 10.123.123.100/32 -p tcp --dport 80 -------|
```


#### "in-cluster" trafic to external VIP 10.123.123.100

It is interesting to understand what happens when trafic is sent to the VIP from within the cluster.
Indeed vm1 has ARP entry 10.123.123.100 for vm2... So it is tempting to say that that the request may be sent to VM2... but no it won't !!! iptables will intercept it.

```
#
# From vm1:
#

ubuntu@vm1:~$ arp -na
? (10.123.123.100) at 52:54:00:c0:87:a0 [ether] on ens3.100  <=================== this is vm2 mac address

ubuntu@vm1:~$  curl 10.123.123.100

 Welcome to NGINX! 
 This is the pod IP address: 10.42.1.20 
 
#
#  Trace iptables activity in vm1 by checking the counter which increases from 7 to 8 packets (these are slow path packets -
#  there are more packets than that).
#  Use TCPdump on vm2 to trace packets with the VIP destination address 10.123.123.100 
#

ubuntu@vm1:~$ sudo nft  list table nat | grep 123.100
                meta l4proto tcp ip daddr 10.123.123.100  tcp dport 80 counter packets 7 bytes 420 jump KUBE-EXT-W47NQ5DDJKUWFTVY

ubuntu@vm1:~$ curl 10.123.123.100

 Welcome to NGINX! 
 This is the pod IP address: 10.42.1.21 
 
ubuntu@vm1:~$ sudo nft  list table nat | grep 123.100
                meta l4proto tcp ip daddr 10.123.123.100  tcp dport 80 counter packets 8 bytes 480 jump KUBE-EXT-W47NQ5DDJKUWFTVY


ubuntu@vm2:~$ sudo tcpdump -evni ens3 "tcp and host 10.123.123.100"
tcpdump: listening on ens3, link-type EN10MB (Ethernet), snapshot length 262144 bytes
^C
0 packets captured
0 packets received by filter
0 packets dropped by kernel
ubuntu@vm2:~$ 

#
# We can verify that this is the same for trafic from pods.
#

ubuntu@vm1:~$ kubectl exec -it test-pod -- curl 10.123.123.100

 Welcome to NGINX! 
 This is the pod IP address: 10.42.0.25 
 
```

#### Test of  "externalTrafficPolicy: Local" with 6 pods 

We're slightly changing the previous and add some replicas (6) so we can check the load balancing within a node.

```
apiVersion: v1
kind: Service
metadata:
  name: nginx-mlb-l2-service
[...]
spec:
  externalTrafficPolicy: Local
[...]
```

```console
ubuntu@vm1:~$  kubectl apply -f https://raw.githubusercontent.com/robric/multipass-3-node-k8s/main/source/nginx-mlb-svc-local.yaml
service/nginx-mlb-l2-service configured
ipaddresspool.metallb.io/external-pool unchanged
l2advertisement.metallb.io/l2-metalb unchanged
configmap/nginx-conf unchanged
deployment.apps/nginx-lbl2 configured
ubuntu@vm1:~$
ubuntu@vm1:~$ kubectl get pods -o wide 
NAME                                   READY   STATUS    RESTARTS   AGE    IP           NODE   NOMINATED NODE   READINESS GATES
[...]
nginx-lbl2-577c9489d-879qj             1/1     Running   0          26h    10.42.1.20   vm2    <none>           <none>
nginx-lbl2-577c9489d-fvk7g             1/1     Running   0          26h    10.42.1.21   vm2    <none>           <none>
nginx-lbl2-577c9489d-fclfn             1/1     Running   0          26h    10.42.0.25   vm1    <none>           <none>
nginx-lbl2-577c9489d-kjfdv             1/1     Running   0          30m    10.42.0.26   vm1    <none>           <none>
nginx-lbl2-577c9489d-w7dls             1/1     Running   0          30m    10.42.2.22   vm3    <none>           <none>
nginx-lbl2-577c9489d-bfj8v             1/1     Running   0          30m    10.42.2.21   vm3    <none>           <none>
```
We can verify that the trafic is dispatched solely to pods living in the same master server (vm2): 
 - 10.42.1.20   
 - 10.42.1.21   
```console
root@fiveg-host-24-node4:~# curl 10.123.123.100

 Welcome to NGINX! 
 This is the pod IP address: 10.42.1.21 
 
root@fiveg-host-24-node4:~# curl 10.123.123.100

 Welcome to NGINX! 
 This is the pod IP address: 10.42.1.20 
 
root@fiveg-host-24-node4:~# curl 10.123.123.100

 Welcome to NGINX! 
 This is the pod IP address: 10.42.1.20 
 
root@fiveg-host-24-node4:~# 
etc.
``` 
However, if we try from a pod in vm1... the trafic is dispatched anywhere. 
```console
ubuntu@vm1:~$ kubectl exec -it test-pod -- curl 10.123.123.100

 Welcome to NGINX! 
 This is the pod IP address: 10.42.0.25 
 
ubuntu@vm1:~$ kubectl exec -it test-pod -- curl 10.123.123.100
 
 Welcome to NGINX! 
 This is the pod IP address: 10.42.0.26 
 
...
```

Let's dig in the nat rules to understand what is happening. 

```console
#
# with externalTrafficPolicy: Cluster (default)
#
ubuntu@vm1:~$ sudo iptables -t nat -S KUBE-EXT-W47NQ5DDJKUWFTVY -v 
-N KUBE-EXT-W47NQ5DDJKUWFTVY
-A KUBE-EXT-W47NQ5DDJKUWFTVY -m comment --comment "masquerade traffic for default/nginx-mlb-l2-service external destinations" -c 0 0 -j KUBE-MARK-MASQ
-A KUBE-EXT-W47NQ5DDJKUWFTVY -c 0 0 -j KUBE-SVC-W47NQ5DDJKUWFTVY
#
# with externalTrafficPolicy: Local
#
ubuntu@vm1:~$ sudo iptables -t nat -S KUBE-EXT-W47NQ5DDJKUWFTVY -v 
-N KUBE-EXT-W47NQ5DDJKUWFTVY
-A KUBE-EXT-W47NQ5DDJKUWFTVY -s 10.42.0.0/16 -m comment --comment "pod traffic for default/nginx-mlb-l2-service external destinations" -c 0 0 -j KUBE-SVC-W47NQ5DDJKUWFTVY
-A KUBE-EXT-W47NQ5DDJKUWFTVY -m comment --comment "masquerade LOCAL traffic for default/nginx-mlb-l2-service external destinations" -m addrtype --src-type LOCAL -c 0 0 -j KUBE-MARK-MASQ
-A KUBE-EXT-W47NQ5DDJKUWFTVY -m comment --comment "route LOCAL traffic for default/nginx-mlb-l2-service external destinations" -m addrtype --src-type LOCAL -c 0 0 -j KUBE-SVC-W47NQ5DDJKUWFTVY
-A KUBE-EXT-W47NQ5DDJKUWFTVY -c 0 0 -j KUBE-SVL-W47NQ5DDJKUWFTVY

Two noticable changes in KUBE-EXT-W47NQ5DDJKUWFTVY
 - A test for source in 10.42.0.0.0/16 (= pod IPs) whic calls the KUBE-SVC-W47NQ5DDJKUWFTVY rule which has the 6 pods of the deployment. 
 - The default rule is changed to KUBE-SVL-W47NQ5DDJKUWFTVY which has the 2 local pods.

ubuntu@vm1:~$ sudo iptables -t nat -S KUBE-SVL-W47NQ5DDJKUWFTVY -v 
-N KUBE-SVL-W47NQ5DDJKUWFTVY
-A KUBE-SVL-W47NQ5DDJKUWFTVY -m comment --comment "default/nginx-mlb-l2-service -> 10.42.0.25:8080" -m statistic --mode random --probability 0.50000000000 -c 0 0 -j KUBE-SEP-H3SFLVALEZ5LECV3
-A KUBE-SVL-W47NQ5DDJKUWFTVY -m comment --comment "default/nginx-mlb-l2-service -> 10.42.0.26:8080" -c 0 0 -j KUBE-SEP-JIHH5JQABFO67SHN
ubuntu@vm1:~$ sudo iptables -t nat -S KUBE-SVC-W47NQ5DDJKUWFTVY -v 
-N KUBE-SVC-W47NQ5DDJKUWFTVY
-A KUBE-SVC-W47NQ5DDJKUWFTVY ! -s 10.42.0.0/16 -d 10.43.159.55/32 -p tcp -m comment --comment "default/nginx-mlb-l2-service cluster IP" -m tcp --dport 80 -c 0 0 -j KUBE-MARK-MASQ
-A KUBE-SVC-W47NQ5DDJKUWFTVY -m comment --comment "default/nginx-mlb-l2-service -> 10.42.0.25:8080" -m statistic --mode random --probability 0.16666666651 -c 0 0 -j KUBE-SEP-H3SFLVALEZ5LECV3
-A KUBE-SVC-W47NQ5DDJKUWFTVY -m comment --comment "default/nginx-mlb-l2-service -> 10.42.0.26:8080" -m statistic --mode random --probability 0.20000000019 -c 0 0 -j KUBE-SEP-JIHH5JQABFO67SHN
-A KUBE-SVC-W47NQ5DDJKUWFTVY -m comment --comment "default/nginx-mlb-l2-service -> 10.42.1.20:8080" -m statistic --mode random --probability 0.25000000000 -c 0 0 -j KUBE-SEP-U6NBO3SO7ES56QIU
-A KUBE-SVC-W47NQ5DDJKUWFTVY -m comment --comment "default/nginx-mlb-l2-service -> 10.42.1.21:8080" -m statistic --mode random --probability 0.33333333349 -c 0 0 -j KUBE-SEP-UV3QYGUSRGNZ7JSO
-A KUBE-SVC-W47NQ5DDJKUWFTVY -m comment --comment "default/nginx-mlb-l2-service -> 10.42.2.21:8080" -m statistic --mode random --probability 0.50000000000 -c 0 0 -j KUBE-SEP-5XVJDSQ32SUUTXIC
-A KUBE-SVC-W47NQ5DDJKUWFTVY -m comment --comment "default/nginx-mlb-l2-service -> 10.42.2.22:8080" -c 0 0 -j KUBE-SEP-DTKU7V2IJOC7TTKI
ubuntu@vm1:~$ 
```
Let's try to toggle the  nginx-mlb-l2-service with internalTrafficPolicy to Local.
```
kind: Service
metadata:
[...]
  name: nginx-mlb-l2-service
spec:
[...]
  externalTrafficPolicy: Local
  internalTrafficPolicy: Local              <======================== let's try that 
```
It does not work unfortunately.
```console
#
# The rule is unchanged: the pod subnet is still routed to the KUBE-SVC service (with 6 pods)
#
ubuntu@vm1:~$ sudo iptables -t nat -S KUBE-EXT-W47NQ5DDJKUWFTVY -v 
-N KUBE-EXT-W47NQ5DDJKUWFTVY
-A KUBE-EXT-W47NQ5DDJKUWFTVY -s 10.42.0.0/16 -m comment --comment "pod traffic for default/nginx-mlb-l2-service external destinations" -c 0 0 -j KUBE-SVC-W47NQ5DDJKUWFTVY
-A KUBE-EXT-W47NQ5DDJKUWFTVY -m comment --comment "masquerade LOCAL traffic for default/nginx-mlb-l2-service external destinations" -m addrtype --src-type LOCAL -c 0 0 -j KUBE-MARK-MASQ
-A KUBE-EXT-W47NQ5DDJKUWFTVY -m comment --comment "route LOCAL traffic for default/nginx-mlb-l2-service external destinations" -m addrtype --src-type LOCAL -c 0 0 -j KUBE-SVC-W47NQ5DDJKUWFTVY
-A KUBE-EXT-W47NQ5DDJKUWFTVY -c 0 0 -j KUBE-SVL-W47NQ5DDJKUWFTVY
ubuntu@vm1:~$
#
# There is no magic: curl requests are spread everywhere
#

ubuntu@vm1:~$ kubectl exec -it test-pod -- curl 10.123.123.100

 Welcome to NGINX! 
 This is the pod IP address: 10.42.0.25  <========================= vm1
 
ubuntu@vm1:~$ kubectl exec -it test-pod -- curl 10.123.123.100

 Welcome to NGINX! 
 This is the pod IP address: 10.42.2.21 <========================= vm2
 
ubuntu@vm1:~$
```

#### Source NAT (masquerade) enforcement for incoming trafic

There is a subtle behavior change when playing with externalTrafficPolicy related to the enforcment of SNAT:
- externalTrafficPolicy: Cluster (default)
Source NAT is enforced for incoming trafic from external sources 
- externalTrafficPolicy: Local 
Source NAT is NOT enforced for incoming trafic from external sources

```console
ubuntu@vm1:~$ kubectl get pods -o wide | grep vm2
[...]
nginx-lbl2-577c9489d-fvk7g             1/1     Running   0          5d20h   10.42.1.21   vm2    <none>           <none>
ubuntu@vm1:~$ kubectl debug -it nginx-lbl2-577c9489d-fvk7g --image nicolaka/netshoot
[...]

#
#   externalTrafficPolicy: Cluster -------> Source address of curl is Natted to  10.42.1.1
#

 nginx-lbl2-577c9489d-fvk7g  ~  tcpdump -ni eth0
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
09:49:45.535241 IP 10.42.1.1.27659 > 10.42.1.21.8080: Flags [S], seq 568611649, win 64240, options [mss 1460,sackOK,TS val 1343731101 ecr 0,nop,wscale 7], length 0
09:49:45.535298 IP 10.42.1.21.8080 > 10.42.1.1.27659: Flags [S.], seq 3912071880, ack 568611650, win 64308, options [mss 1410,sackOK,TS val 3484627024 ecr 1343731101,nop,wscale 7], length 0

#
#   externalTrafficPolicy: Local -------> Source address is Not Natted 10.123.123.100
#

09:50:54.098279 IP 10.123.123.254.38124 > 10.42.1.21.8080: Flags [S], seq 4011661290, win 64240, options [mss 1460,sackOK,TS val 1343799665 ecr 0,nop,wscale 7], length 0
09:50:54.098324 IP 10.42.1.21.8080 > 10.123.123.254.38124: Flags [S.], seq 1190145475, ack 4011661291, win 64308, options [mss 1410,sackOK,TS val 3766712946 ecr 1343799665,nop,wscale 7], length 0

``` 

This is due to masquerading (-j MASQ) configured in iptables for the EXT rule

```
#
#   externalTrafficPolicy: Cluster -------> rule KUBE-MARK-MASQ - which ultimately calls -j MASQ action - is matched (pkts 9)
#

ubuntu@vm2:~$ sudo iptables -t nat -L KUBE-EXT-W47NQ5DDJKUWFTVY -n -v
Chain KUBE-EXT-W47NQ5DDJKUWFTVY (2 references)
 pkts bytes target     prot opt in     out     source               destination         
--> 9   540 KUBE-MARK-MASQ  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* masquerade traffic for default/nginx-mlb-l2-service external destinations */
--> 9   540 KUBE-SVC-W47NQ5DDJKUWFTVY  all  --  *      *       0.0.0.0/0            0.0.0.0/0           
ubuntu@vm2:~$ 

#
#   externalTrafficPolicy: Local -------> KUBE-SVL-W47NQ5DDJKUWFTVY is called directly without checking KUBE-MARK-MASK 
#                                         Indeed, there is an extra condition "ADDRTYPE match src-type LOCAL" which 
#                                         checks whether source is local
#

ubuntu@vm2:~$ sudo iptables -t nat -L KUBE-EXT-W47NQ5DDJKUWFTVY -n -v
Chain KUBE-EXT-W47NQ5DDJKUWFTVY (2 references)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 KUBE-SVC-W47NQ5DDJKUWFTVY  all  --  *      *       10.42.0.0/16         0.0.0.0/0            /* pod traffic for default/nginx-mlb-l2-service external destinations */
    0     0 KUBE-MARK-MASQ  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* masquerade LOCAL traffic for default/nginx-mlb-l2-service external destinations */ ADDRTYPE match src-type LOCAL
    0     0 KUBE-SVC-W47NQ5DDJKUWFTVY  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* route LOCAL traffic for default/nginx-mlb-l2-service external destinations */ ADDRTYPE match src-type LOCAL
--> 2   120 KUBE-SVL-W47NQ5DDJKUWFTVY  all  --  *      *       0.0.0.0/0            0.0.0.0/0

ubuntu@vm2:~$ 

For fun, we can that if we use an IP that is local to the node (but external to the pod network), then the processing is different (use of masquerade and default cluster-wide KUBE-SVC instead of local KUBE-SVL)

ubuntu@vm2:~$ curl 10.123.123.100 --interface 10.65.94.199

 Welcome to NGINX! 
 This is the pod IP address: 10.42.2.22 
 
ubuntu@vm2:~$ sudo iptables -t nat -L KUBE-EXT-W47NQ5DDJKUWFTVY -n -v
Chain KUBE-EXT-W47NQ5DDJKUWFTVY (2 references)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 KUBE-SVC-W47NQ5DDJKUWFTVY  all  --  *      *       10.42.0.0/16         0.0.0.0/0            /* pod traffic for default/nginx-mlb-l2-service external destinations */
--> 1   120 KUBE-MARK-MASQ  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* masquerade LOCAL traffic for default/nginx-mlb-l2-service external destinations */ ADDRTYPE match src-type LOCAL
--> 1   120 KUBE-SVC-W47NQ5DDJKUWFTVY  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* route LOCAL traffic for default/nginx-mlb-l2-service external destinations */ ADDRTYPE match src-type LOCAL
    2   120 KUBE-SVL-W47NQ5DDJKUWFTVY  all  --  *      *       0.0.0.0/0            0.0.0.0/0           
ubuntu@vm2:~$  
``` 

#### External Routing from within pods

This is where things gets a bit more complicated: assume pod can be used to forward traffic (e.g. the pod terminates a Tunnel like IPSEC). We have sources, which raises concerns on how the trafic is routed back. 

We're using "externalTrafficPolicy: Cluster" which is the default mode. 
```
+-------------------------+ +----------+ +----------+     
|                         | |          | |          |     
|  +-------------------+  | |          | |          |     
|  |  test-pod-vm1     |  | |          | |          |     
|  | +--------------+  |  | |          | |          |     
|  | | br-inpod     |  |  | |          | |          |     
|  | |11.11.11.11/24|  |  | |          | |          |     
|  | +--------------+  |  | |          | |          |     
|  |      eth0         |  | |          | |          |     
|  +------+---+--------+  | |          | |          |     
|         |   |           | |          | |          |     
|         |   |           | |          | |          |     
|         |   |           | |          | |          |     
|         +---+           | |          | |          |     
|                         | |          | |          |     
|    +----------+         | |+--------+| |+--------+|     
|    |  nginx1  |         | || nginx2 || || nginx3 ||     
|    |          |         | ||        || ||        ||     
|    +----------+         | |+--------+| |+--------+|     
|                         | |          | |          |     
|                         | |          | |          |     
+-------------------------+ +----------+ +----------+     
           VM1                  VM2           VM3      
```
Spawn netshoot pod on vm1. 
```
kubectl apply -f https://raw.githubusercontent.com/robric/multipass-3-node-k8s/main/source/test-pod-vm1.yaml
```
And let's add an interface within this pod so we can generate "external request" from this pod to the metalb VIP.
```
ubuntu@vm1:~$ kubectl describe pod test-pod-vm1 | grep container
    Container ID:  containerd://87f8f7961ee33c3c2d439621aa88bf4a882ac2538bec7526039a5e21e494ee14

ubuntu@vm1:~$ sudo ctr c info  87f8f7961ee33c3c2d439621aa88bf4a882ac2538bec7526039a5e21e494ee14  |  grep -C 5 pid
                }
            },
            "cgroupsPath": "kubepods-besteffort-podbf227f8b_8058_49b8_be42_1b73feb8a803.slice:cri-containerd:87f8f7961ee33c3c2d439621aa88bf4a882ac2538bec7526039a5e21e494ee14",
            "namespaces": [
                {
                    "type": "pid"
                },
                {
                    "type": "ipc",
                    "path": "/proc/555560/ns/ipc"
                },
ubuntu@vm1:~$
ubuntu@vm1:~$ sudo nsenter -t 555560 -n
root@vm1:/home/ubuntu# ip link add br-inpod type bridge
root@vm1:/home/ubuntu# ip addr add 11.11.11.11/24 dev br-inpod 
root@vm1:/home/ubuntu# ip link set up dev br-inpod
root@vm1:/home/ubuntu# ip route show
default via 10.42.0.1 dev eth0 
10.42.0.0/24 dev eth0 proto kernel scope link src 10.42.0.27 
10.42.0.0/16 via 10.42.0.1 dev eth0 
11.11.11.0/24 dev br-inpod proto kernel scope link src 11.11.11.11 
root@vm1:/home/ubuntu# 

root@vm1:/home/ubuntu# curl 10.123.123.100

 Welcome to NGINX! 
 This is the pod IP address: 10.42.0.25 
 
root@vm1:/home/ubuntu# curl 10.123.123.100 --interface 11.11.11.11 
^C
root@vm1:/home/ubuntu# 

#
# This breaks -as expected- since there is no route back to 11.11.11.0/24 in the kernel
#

```

We can fix that provided that you have netadmin rights in default network ns - which is very bad  practice - (but that's just a test).

```

#
# add route to the pod for the br-inpod subnet
#
ubuntu@vm1:~$ kubectl get pods test-pod-vm1 -o wide
NAME           READY   STATUS    RESTARTS   AGE   IP           NODE   NOMINATED NODE   READINESS GATES
test-pod-vm1   1/1     Running   0          21h   10.42.0.27   vm1    <none>           <none>

ubuntu@vm1:~$ sudo ip route add 11.11.11.0/24 via 10.42.0.27 

#
# curl from pod works now
#

root@vm1:/home/ubuntu# curl 10.123.123.100 --interface 11.11.11.11 

 Welcome to NGINX! 
 This is the pod IP address: 10.42.0.25 
 
root@vm1:/home/ubuntu# 
```


#### metallb compliance with SCTP

Metallb works in conjunction with sctp (after this is a control plane)

First install SCTP tools on each VM and the host (this will take care of drivers and make it easy to test).
``` 
multipass exec vm1 -- sudo apt install lksctp-tools -y
multipass exec vm2 -- sudo apt install lksctp-tools -y
multipass exec vm3 -- sudo apt install lksctp-tools -y
sudo apt install lksctp-tools -y
```
Then launch the sctp service and deployment.
```
kubectl apply -f https://raw.githubusercontent.com/robric/multipass-3-node-k8s/main/source/sctp-mlb-svc.yaml
```

Now we can test from the host (i.e. external).

```
#
# That worked !!!
#
root@fiveg-host-24-node4:~# sctp_test -H 10.123.123.254 -h  10.123.123.101 -p 10000 -s
remote:addr=10.123.123.101, port=webmin, family=2
local:addr=10.123.123.254, port=0, family=2
seed = 1718815477

Starting tests...
        socket(SOCK_SEQPACKET, IPPROTO_SCTP)  ->  sk=3
        bind(sk=3, [a:10.123.123.254,p:0])  --  attempt 1/10
Client: Sending packets.(1/10)
        sendmsg(sk=3, assoc=0)    1 bytes.
          SNDRCV(stream=0 flags=0x1 ppid=1844700133
        sendmsg(sk=3, assoc=0)    1 bytes.
          SNDRCV(stream=0 flags=0x1 ppid=1188217067
        sendmsg(sk=3, assoc=0)    1 bytes.
          SNDRCV(stream=0 flags=0x1 ppid=1427423053
        sendmsg(sk=3, assoc=0)    1 bytes.
          SNDRCV(stream=0 flags=0x1 ppid=1690014943
[...]

#
# 
#
```



### Troubleshooting

Checks the logs of the speaker to track ownership of VIP. This is actually a daemonset that runs in the hostnetwork.

```
ubuntu@vm1:~$ kubectl get pods -o wide -n metallb-system 
NAME                                      READY   STATUS    RESTARTS   AGE    IP             NODE   NOMINATED NODE   READINESS GATES
frr-k8s-webhook-server-7d94b7b8d5-8pgd7   1/1     Running   0          7d4h   10.42.1.7      vm2    <none>           <none>
frr-k8s-daemon-t68fr                      6/6     Running   0          7d4h   10.65.94.199   vm2    <none>           <none>
controller-5f4fc66d9d-4j4h5               1/1     Running   0          7d4h   10.42.1.8      vm2    <none>           <none>
frr-k8s-daemon-q695g                      6/6     Running   0          7d4h   10.65.94.238   vm1    <none>           <none>
speaker-gq27n                             1/1     Running   0          7d4h   10.65.94.238   vm1    <none>           <none>
speaker-lklxw                             1/1     Running   0          7d4h   10.65.94.199   vm2    <none>           <none>
frr-k8s-daemon-h7rh6                      6/6     Running   0          7d4h   10.65.94.95    vm3    <none>           <none>
speaker-n9cbf                             1/1     Running   0          7d4h   10.65.94.95    vm3    <none>           <none>
ubuntu@vm1:~$ 


```
