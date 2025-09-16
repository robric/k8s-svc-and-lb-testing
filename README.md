# Looking under the hood of kubernetes network abstractions: clusterIP, nodeport, metallb and EgressIP 

This repo focuses on the integration of services in kubernetes from basic clusterIP to loadbalancers. More precisely the following items are covered:
-  basic k8s service custer and nodeport wiht inspection of iptables rules for comparison with more complex scenarios.
-  load balancer services: metallb for now. Maybe enhanced with additional (loxilb) 
-  IPSEC integration with metallb load balancer
-  Metallb and SCTP support
-  externaltrafficpolicy local/cluster knob for loadbalancer services
-  RHOCP integration

This page is also:
- a quick copy-paste source for rapidly bringing up test scenarios.
- an educational source to share how things work under the the hood when interfacing with diverse people... Indeed, kubernetes networking logic is actually not so well documented.
- a personal cheat sheet for k8s for fast refresh.

##  1. <a name='TableofContent'></a>Table of Content

<!-- vscode-markdown-toc -->
* 1. [Table of Content](#TableofContent)
* 2. [Prerequisites](#Prerequisites)
* 3. [VM and Cluster deployment](#VMandClusterdeployment)
* 4. [ K8s basic service deployment and routing analysis](#K8sbasicservicedeploymentandroutinganalysis)
	* 4.1. [Bootstraping](#Bootstraping)
	* 4.2. [How does a pod reaches a services ?](#Howdoesapodreachesaservices)
	* 4.3. [A glance at coredns](#Aglanceatcoredns)
	* 4.4. [Cluster IP Service Routing Details](#ClusterIPServiceRoutingDetails)
	* 4.5. [Nodeport Service Routing Details](#NodeportServiceRoutingDetails)
* 5. [Metalb Integration on 3 node cluster](#MetalbIntegrationon3nodecluster)
	* 5.1. [Target Design](#TargetDesign)
	* 5.2. [Metalb Deployment](#MetalbDeployment)
	* 5.3. [Test in L2 mode](#TestinL2mode)
		* 5.3.1. [Deployment with 3 pods and Single VIP in the external network](#Deploymentwith3podsandSingleVIPintheexternalnetwork)
		* 5.3.2. ["in-cluster" trafic to external VIP 10.123.123.100](#in-clustertrafictoexternalVIP10.123.123.100)
		* 5.3.3. [Test of  "externalTrafficPolicy: Local" with 6 pods](#TestofexternalTrafficPolicy:Localwith6pods)
		* 5.3.4. [metallb deployment in hostnetwork](#metallbdeploymentinhostnetwork)
		* 5.3.5. [Source NAT (masquerade) enforcement for incoming trafic in default mode](#SourceNATmasqueradeenforcementforincomingtraficindefaultmode)
		* 5.3.6. [External Routing from within pods](#ExternalRoutingfromwithinpods)
		* 5.3.7. [Non fate-sharing deployment with metallb and  multiple VIPs](#Nonfate-sharingdeploymentwithmetallbandmultipleVIPs)
		* 5.3.8. [Metallb compliance with SCTP](#MetallbcompliancewithSCTP)
		* 5.3.9. [Metallb with IPSEC (strongswan) and SCTP](#MetallbwithIPSECstrongswanandSCTP)
* 6. [Openshift Integration](#OpenshiftIntegration)
	* 6.1. [Background](#Background)
	* 6.2. [Setup Description](#SetupDescription)
	* 6.3. [Metallb Installation](#MetallbInstallation)
	* 6.4. [Metallb service instantiation](#Metallbserviceinstantiation)
		* 6.4.1. [Deployment with ExternalTraficPolicy Cluster](#DeploymentwithExternalTraficPolicyCluster)
		* 6.4.2. [RHCOP/OVN networking overview](#RHCOPOVNnetworkingoverview)
		* 6.4.3. [Inspect iptables during when a session to VIP is initiated from the external server -----> SRC=10.131.2.3.XXXXX DST=10.131.2.14.8080](#InspectiptablesduringwhenasessiontoVIPisinitiatedfromtheexternalserver-----SRC10.131.2.3.XXXXXDST10.131.2.14.8080)
		* 6.4.4. [2. Check packet transformation up to pod when transiting ovs-bridge br-ex -----> SRC=10.131.2.3.XXXXX DST=172.30.0.4.8080**](#Checkpackettransformationuptopodwhentransitingovs-bridgebr-ex-----SRC10.131.2.3.XXXXXDST172.30.0.4.8080)
		* 6.4.5. [4. Packet handling in br-ex](#Packethandlinginbr-ex)
* 7. [EgressIP  (openshift with OVNkubernetes only )](#EgressIPopenshiftwithOVNkubernetesonly)
	* 7.1. [Background](#Background-1)
	* 7.2. [Testing](#Testing)
		* 7.2.1. [Preparation of the Cluster](#PreparationoftheCluster)
		* 7.2.2. [Definition of EgressIP](#DefinitionofEgressIP)
* 8. [Ingress integration](#Ingressintegration)
	* 8.1. [Background](#Background-1)
	* 8.2. [Deployment](#Deployment)
	* 8.3. [Tests and observations](#Testsandobservations)
	* 8.4. [IngressRoute (traefik)](#IngressRoutetraefik)
* 9. [Linkerd](#Linkerd)
	* 9.1. [Installation](#Installation)
* 10. [Metallb Troubleshooting tips](#MetallbTroubleshootingtips)
	* 10.1. [Presentation](#Presentation)
	* 10.2. [Change log level](#Changeloglevel)
	* 10.3. [Trace VIP ownership](#TraceVIPownership)
	* 10.4. [ARP responder function](#ARPresponderfunction)
	* 10.5. [What happens in case of failure ?](#Whathappensincaseoffailure)
		* 10.5.1. [POD RUNNING but has no READY container](#PODRUNNINGbuthasnoREADYcontainer)
		* 10.5.2. [POD RUNNING but container transitions from READY to NOT READY](#PODRUNNINGbutcontainertransitionsfromREADYtoNOTREADY)

<!-- vscode-markdown-toc-config
	numbering=true
	autoSave=true
	/vscode-markdown-toc-config -->
<!-- /vscode-markdown-toc -->

##  2. <a name='Prerequisites'></a>Prerequisites

I just start with an ubuntu server with:
- multipass installed (by default on ubuntu)
- a keypair in .ssh/ (id_rsa.pub) so we can simply access VMs

##  3. <a name='VMandClusterdeployment'></a>VM and Cluster deployment 

The testings are based on a deployment of 4 VMs via multipass and additional networking.
- 1 Cluster made up of 3 vms (k3s).
- 1 external VM to run testings to reach the cluster in load balancer services.

The below diagram captures the main of characteristics of the lab topology.

```
Networks:
- native multipass on bridge mpqemubr0 10.65.94.0/24
- external network on vlan 100 (10.123.123.0/24). This is for the testings of
Load Balancers services.

Kubernetes Cluster VM:
- vm1: master/worker - External IP address = 10.123.123.1/24
- vm2: worker - External IP address = 10.123.123.2/24
- vm3: worker - External IP address = 10.123.123.3/24

External VM: 
- vm-ext: External IP address = 10.123.123.4/24

            +----------------------------------------------+    
            |                   Cluster                    |    
            |                                              |     
            |    MASTER                                    |
            |      +                                       |   External VM
            |     worker          worker        worker     |         
            | +------------+ +------------+ +------------+ | +------------+  
            | |     vm1    | |    vm2     | |    vm3     | | |     vm-ext |   
            | +----ens3----+ +---ens3-----+ +---ens3-----+ | +----ens3----+  
            |      :  |.1/24      :  |.2/24      :  |.3/24 |       :  |.4/24   
            +------:--|-----------:--|-----------:--|------+       :  |
                   :  |           :  |           :  |              :  |         
                   :  |           :  |           :  |              :  |    
                   :  |           :  |           :  |              :  |    
                   :  +=========vlan +100 (external)+=================+    
                   :              10.123.123.0/24:  |              :
                   :              :              :  |              :   
                   :              :              :  |              : 
                   :              :              :  |              : 
                   :              :              :  |              :                      
             ------+------ native +vlan(internal)+-----------------+               
                        :         10.65.94.0/24     |   
                        :                           |
                        :                           |
                 [mpqemubr0]                  [mpqemubr0.100]                         
                 10.65.94.1/24               10.123.123.254/24                          
                     host                          host
```
To deploy this, just run the following command. It will deploy the network plumbing and vms.
```
curl -sSL https://raw.githubusercontent.com/robric/multipass-3-node-k8s/main/source/deploy.sh | sh
```
You'll get the 4 VMs with kubernetes running (k3s inside)
```console
root@fiveg-host-24-node4:~# multipass list 
Name                    State             IPv4             Image
vm-ext                  Running           10.65.94.56      Ubuntu 22.04 LTS
                                          10.123.123.4
vm1                     Running           10.65.94.121     Ubuntu 22.04 LTS
                                          10.42.0.0
                                          10.42.0.1
                                          10.123.123.1
vm2                     Running           10.65.94.22      Ubuntu 22.04 LTS
                                          10.42.1.0
                                          10.123.123.2
vm3                     Running           10.65.94.156     Ubuntu 22.04 LTS
                                          10.42.2.0
                                          10.123.123.3
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

##  4. <a name='K8sbasicservicedeploymentandroutinganalysis'></a> K8s basic service deployment and routing analysis

###  4.1. <a name='Bootstraping'></a>Bootstraping

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
###  4.2. <a name='Howdoesapodreachesaservices'></a>How does a pod reaches a services ?
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

###  4.3. <a name='Aglanceatcoredns'></a>A glance at coredns  
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

###  4.4. <a name='ClusterIPServiceRoutingDetails'></a>Cluster IP Service Routing Details

This section describes the logic for routing kubernetes default services(Cluster IP) which is extensively based on NAT. The implementation is CNI-dependent: the description presented here applies for flannel (k3s default CNI). 
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

###  4.5. <a name='NodeportServiceRoutingDetails'></a>Nodeport Service Routing Details

This section describes the logic for the routing of a kubernetes nodeport service. The implementation is CNI-dependent: the description presented here applies for flannel (k3s default CNI). 

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
##  5. <a name='MetalbIntegrationon3nodecluster'></a>Metalb Integration on 3 node cluster

###  5.1. <a name='TargetDesign'></a>Target Design

We're now using the external interface to the current networking thanks to a vlan (vlan 100).

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
This should be there after deployment, but in case this has been lost (reboot), you may execute the following script:
```
curl -sSL https://raw.githubusercontent.com/robric/multipass-3-node-k8s/main/source/external-net.sh | sh
```

###  5.2. <a name='MetalbDeployment'></a>Metalb Deployment

We'll use info from https://metallb.universe.tf/installation. We also choose the k8s/FRR version because we're a bunch of network nerds.
To deploy metalb, just apply the following manifest in master (vm1):
``` 
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.14.5/config/manifests/metallb-frr-k8s.yaml
```

###  5.3. <a name='TestinL2mode'></a>Test in L2 mode

####  5.3.1. <a name='Deploymentwith3podsandSingleVIPintheexternalnetwork'></a>Deployment with 3 pods and Single VIP in the external network

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
- An external endpoint such as vm-ext or the host.
```console
ubuntu@vm1:~$ curl 10.123.123.100

 Welcome to NGINX! 
 This is the pod IP address: 10.42.1.21 
 
ubuntu@vm1:~$ curl 10.123.123.100

 Welcome to NGINX! 
 This is the pod IP address: 10.42.0.25 
 
ubuntu@vm-ext:~# curl 10.123.123.100

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
# We can check that proxy arp is disabled - the "speaker" pod from metallb is actually the one that is managing ARP. 
#
ubuntu@vm2:~$ cat /proc/sys/net/ipv4/conf/ens3.100/proxy_arp
0
# 
# The problem got fixed after changing the mask for the metallb VIP pool. This avoids any overlap with existing IP of VMs. 
#
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: external-pool
  namespace: metallb-system
spec:
  addresses:
  - 10.123.123.64/24  ==========>  Use 10.123.123.64/26 instead !!!!
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


####  5.3.2. <a name='in-clustertrafictoexternalVIP10.123.123.100'></a>"in-cluster" trafic to external VIP 10.123.123.100

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

####  5.3.3. <a name='TestofexternalTrafficPolicy:Localwith6pods'></a>Test of  "externalTrafficPolicy: Local" with 6 pods 

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
####  5.3.4. <a name='metallbdeploymentinhostnetwork'></a>metallb deployment in hostnetwork

The following manifest deploys 3 pods in hostnetwork, together with VIP 10.123.123.102 in the external network via metallb.

```
kubectl apply -f https://raw.githubusercontent.com/robric/multipass-3-node-k8s/main/source/nginx-mlb-svc-hostnetwork.yaml
```
This works as expected.
```
ubuntu@vm1:~$ kubectl get svc | grep 10.123.123.102
nginx-mlb-l2-hostnet   LoadBalancer   10.43.207.14    10.123.123.102   80:30733/TCP   6m56s
ubuntu@vm1:~$ 
ubuntu@vm1:~$ kubectl  get pods -o wide | grep net
nginx-lbl2-hostnet-6d7754d545-5g8r8    1/1     Running   0          3m22s   10.65.94.95    vm3    <none>           <none>
nginx-lbl2-hostnet-6d7754d545-59d6g    1/1     Running   0          3m22s   10.65.94.199   vm2    <none>           <none>
nginx-lbl2-hostnet-6d7754d545-69kxn    1/1     Running   0          3m22s   10.65.94.238   vm1    <none>           <none>
ubuntu@vm1:~$ 
root@fiveg-host-24-node4:~# curl 10.123.123.102

 Welcome to NGINX! 
 This is the pod IP address: 10.65.94.95 

root@fiveg-host-24-node4:~# curl 10.123.123.102

 Welcome to NGINX! 
 This is the pod IP address: 10.65.94.199 
 
root@fiveg-host-24-node4:~# 
```
There is not much change in NAT logic compared with 
```
ubuntu@vm1:~$ sudo iptables-save |grep 10.123.123.102
-A KUBE-SERVICES -d 10.123.123.102/32 -p tcp -m comment --comment "default/nginx-mlb-l2-hostnet loadbalancer IP" -m tcp --dport 80 -j KUBE-EXT-CDEB5OJ5KJNVMLM6
ubuntu@vm1:~$ sudo iptables -t nat -L KUBE-EXT-CDEB5OJ5KJNVMLM6 -n 
Chain KUBE-EXT-CDEB5OJ5KJNVMLM6 (2 references)
target     prot opt source               destination         
KUBE-MARK-MASQ  all  --  0.0.0.0/0            0.0.0.0/0            /* masquerade traffic for default/nginx-mlb-l2-hostnet external destinations */
KUBE-SVC-CDEB5OJ5KJNVMLM6  all  --  0.0.0.0/0            0.0.0.0/0           
ubuntu@vm1:~$ sudo iptables -t nat -L KUBE-SVC-CDEB5OJ5KJNVMLM6 -n 
Chain KUBE-SVC-CDEB5OJ5KJNVMLM6 (2 references)
target     prot opt source               destination         
KUBE-MARK-MASQ  tcp  -- !10.42.0.0/16         10.43.207.14         /* default/nginx-mlb-l2-hostnet cluster IP */ tcp dpt:80
KUBE-SEP-BRCASNC5D2TNKFYB  all  --  0.0.0.0/0            0.0.0.0/0            /* default/nginx-mlb-l2-hostnet -> 10.65.94.199:8080 */ statistic mode random probability 0.33333333349
KUBE-SEP-7VFNSJIQ2K6SELCJ  all  --  0.0.0.0/0            0.0.0.0/0            /* default/nginx-mlb-l2-hostnet -> 10.65.94.238:8080 */ statistic mode random probability 0.50000000000
KUBE-SEP-DYIL5FTYGTTVEK47  all  --  0.0.0.0/0            0.0.0.0/0            /* default/nginx-mlb-l2-hostnet -> 10.65.94.95:8080 */
ubuntu@vm1:~$ sudo iptables -t nat -L KUBE-SEP-BRCASNC5D2TNKFYB  -n 
Chain KUBE-SEP-BRCASNC5D2TNKFYB (1 references)
target     prot opt source               destination         
KUBE-MARK-MASQ  all  --  10.65.94.199         0.0.0.0/0            /* default/nginx-mlb-l2-hostnet */
DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            /* default/nginx-mlb-l2-hostnet */ tcp to:10.65.94.199:8080
ubuntu@vm1:~$ 
```

The change is related to KUBE-SEP instantiation with DNAT happens to node:8080 address -which is actually the pod address in the case of hostnetwork-. 
This is business as usual.


####  5.3.5. <a name='SourceNATmasqueradeenforcementforincomingtraficindefaultmode'></a>Source NAT (masquerade) enforcement for incoming trafic in default mode

There is a subtle behavior change when playing with externalTrafficPolicy related to the enforcment of SNAT:
- externalTrafficPolicy: Cluster (default)
Source NAT is enforced for incoming trafic from external sources. This configuration permits return trafic to be tromboned via the server -identified by SRC NAT IP address- that handles the VIP.   
- externalTrafficPolicy: Local 
Source NAT is NOT enforced for incoming trafic from external sources. In this case, since the server is the same there is no need for NAT.

(NOTE): This change of behavior is actually important since more complex integration work/won't work (see section [Metallb with IPSEC and SCTP](#Metallb-with-ipsec-strongswan-and-sctp))

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

####  5.3.6. <a name='ExternalRoutingfromwithinpods'></a>External Routing from within pods

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

####  5.3.7. <a name='Nonfate-sharingdeploymentwithmetallbandmultipleVIPs'></a>Non fate-sharing deployment with metallb and  multiple VIPs

Here we're deploying a slightly more complex setup to expose 2 Metalb VIPs, while making sure there is no zone sharing.
- Two zone labels for computes: vm1 and vm2 in zone1 and vm3 in zone2.
- Two independant deployments nginx-zone1/2 mapped to their respective zone (nodeselector affinity)
- Two distincts VIPs exposed via metalb: vip1=10.123.123.201 and vip=210.123.123.202, each mapped to distinct zone

The following drawing represents the test setup:

```
                                                 |                                                  
                                        zone 1   |   zone2                                          
                                                 |                                                  
                                                 |                                                  
           +-----------------+ +----------------+|+----------------+                                
           |                 | |                |||                |                                
           |                 | |                |||                |                                
           |   +----------+  | |   +---------+  |||   +---------+  |                                
           |   |  nginx1  |  | |   | nginx2  |  |||   | nginx3  |  |                                
           |   |  zone 1  |  | |   | zone1   |  |||   | zone2   |  |                                
           |   |          |  | |   |         |  |||   |         |  |                                
           |   +----------+  | |   +---------+  |||   +---------+  |                                
           |                 | |                |||                |                                
           |                 | |                |||                |                                
           |                 | |                |||                |                                
           |                 | |                |||                |                                
           |      zone1      | |    zone1       |||   zone2        |                                
           |                 | |                |||                |                                
           |                 | |                |||                |                                
           |                 | |                |||                |                                
           |VM1              | |VM2             ||| VM3            |                                
           +-----------------+ +----------------+|+----------------+                                
                                                 |                                                  
                                                 |                                                  
            <------        VIP1     --------->   | <-   VIP2   ->                                   
                      10.123.123.201             |  10.123.123.202    

```
To achieve this, nodes are labelled based on two distincts zones:  
```
kubectl label nodes vm1 zone=zone1
kubectl label nodes vm2 zone=zone1
kubectl label nodes vm3 zone=zone2
```

Apply the manifest for metallb service and app deployments

```
kubectl apply -f https://raw.githubusercontent.com/robric/multipass-3-node-k8s/main/source/nginx-mlb-2-vips.yaml
```

For the sake of simplicity here what is defined in service/metalb - only zone1 displayed for simplicity -.

```
#
# Define a first service nginx-zone1 with selector nginx-zone1 (app deployment steered to zone1)
#
apiVersion: v1
kind: Service
metadata:
  name: nginx-mlb-l2-zone1
  annotations:
    metallb.universe.tf/address-pool: external-pool-zone1
spec:
  selector:
    app: nginx-zone1
  ports:
    - protocol: TCP
      port: 80
      targetPort: 8080
  type: LoadBalancer
---


#
# Define a pool for zone1 (ipaddresspool) with vip 10.123.123.201
#

apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: external-pool-zone1
  namespace: metallb-system
spec:
  addresses:
  - 10.123.123.201/32
---

#
# Use an L2advertisement CRD to control the management of the VIP. 
# This maps with the ip pool for zone1 (external-pool-zone1) together with a nodeselector to zone1.
#

apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: l2-metalb-zone1
  namespace: metallb-system
spec:
  ipAddressPools:
  - external-pool-zone1
  interfaces:
  - ens3.100
  nodeSelectors:
  - matchLabels:
      zone: "zone1"
```

After configuration, we can see 3 pods, services and deployments mapped to appropriate zones.

```console
ubuntu@vm1:~$ kubectl get pods -o wide | grep zone
nginx-zone2-7f8b84d998-s4g75           1/1     Running   0          3h2m    10.42.2.36   vm3    <none>           <none>
nginx-zone1-58ccdbd4b8-p49gv           1/1     Running   0          3h2m    10.42.0.37   vm1    <none>           <none>
nginx-zone1-58ccdbd4b8-5m5fh           1/1     Running   0          3h2m    10.42.1.35   vm2    <none>           <none>
ubuntu@vm1:~$ kubectl get svc -o wide | grep zone
nginx-mlb-l2-zone2     LoadBalancer   10.43.3.184     10.123.123.202   80:31405/TCP   3h3m    app=nginx-zone2
nginx-mlb-l2-zone1     LoadBalancer   10.43.165.8     10.123.123.201   80:30980/TCP   3h3m    app=nginx-zone1
ubuntu@vm1:~$ kubectl get deployments.apps -o wide | grep zone
nginx-zone2           1/1     1            1           3h3m    nginx        nginx:latest   app=nginx-zone2
nginx-zone1           2/2     2            2           3h3m    nginx        nginx:latest   app=nginx-zone1
ubuntu@vm1:~$
```

The requests to each VIPs are properly directed to the correct zone.

```console
root@fiveg-host-24-node4:~# curl 10.123.123.201 ------------> request to VIP zone 1

 Welcome to NGINX! 
 Here are the IP address:port tuples for:
  - nginx server => 10.42.1.35:8080             ------------> pod in vm2 / zone1
  - http client  => 10.42.0.0:51172 

root@fiveg-host-24-node4:~# curl 10.123.123.201 ------------> request to VIP zone 1

 Welcome to NGINX! 
 Here are the IP address:port tuples for:
  - nginx server => 10.42.0.37:8080            ------------> pod in vm1 / zone1 
  - http client  => 10.42.0.1:18972 

root@fiveg-host-24-node4:~# curl 10.123.123.202 ------------> request to VIP zone 2

 Welcome to NGINX! 
 Here are the IP address:port tuples for:
  - nginx server => 10.42.2.36:8080             ------------> pod in vm3 / zone2
  - http client  => 10.42.0.0:3152 

```
If we investigate each VIP, we can see that both VIPs are managed by the same host (hence same zone).
This does not seem correct considering the nodeselector mapping attached to L2advertisement.
```console
root@fiveg-host-24-node4:~# arp -na | grep 10.123
? (10.123.123.2) at 52:54:00:c0:87:a0 [ether] on mpqemubr0.100
? (10.123.123.1) at 52:54:00:e2:c3:ec [ether] on mpqemubr0.100
? (10.123.123.202) at 52:54:00:e2:c3:ec [ether] on mpqemubr0.100
? (10.123.123.201) at 52:54:00:e2:c3:ec [ether] on mpqemubr0.100
? (10.123.123.3) at 52:54:00:db:2b:ce [ether] on mpqemubr0.100
root@fiveg-host-24-node4:~# 

#
#     We see that 10.123.123.201 and 10.123.123.202 are bound to the same MAC 52:54:00:e2:c3:ec,
#     which is VM1. This does not look right !
#

```
Let's see what happens if we update the services with "externalTraficPolicy = local" since landing on vm1 for zone2 would not allow forwarding to vm3 in zone2.
```
kubectl apply -f https://raw.githubusercontent.com/robric/multipass-3-node-k8s/main/source/nginx-mlb-2-vips-local.yaml
```

It actually works as expected. We can achieve non fate-sharing deployments:
- vip 10.123.123.201 is handled by 52:54:00:e2:c3:ec = vm1 in zone1
- vip 10.123.123.202 is handled by 52:54:00:db:2b:ce = vm3 in zone2

```console
root@fiveg-host-24-node4:~# curl 10.123.123.202 ------------> request to VIP zone 2

 Welcome to NGINX! 
 Here are the IP address:port tuples for:
  - nginx server => 10.42.2.36:8080            ------------> pod in vm3 / zone2
  - http client  => 10.123.123.254:44492 

root@fiveg-host-24-node4:~# curl 10.123.123.201 ------------> request to VIP zone 1

 Welcome to NGINX! 
 Here are the IP address:port tuples for:
  - nginx server => 10.42.0.37:8080             ------------> pod in vm1 / zone1
  - http client  => 10.123.123.254:34188 

root@fiveg-host-24-node4:~# arp -na | grep 10.123

? (10.123.123.202) at 52:54:00:db:2b:ce [ether] on mpqemubr0.100
? (10.123.123.201) at 52:54:00:e2:c3:ec [ether] on mpqemubr0.100
root@fiveg-host-24-node4:~# 

```

####  5.3.8. <a name='MetallbcompliancewithSCTP'></a>Metallb compliance with SCTP

Metallb works in conjunction with sctp (after this is a control plane)

First install SCTP tools on each VM and the host (this will take care of drivers and make it easy to test).
``` 
multipass exec vm1 -- sudo apt install lksctp-tools -y
multipass exec vm2 -- sudo apt install lksctp-tools -y
multipass exec vm3 -- sudo apt install lksctp-tools -y
multipass exec vm-ext -- sudo apt install lksctp-tools -y
sudo apt install lksctp-tools -y
```
Then launch the deployment of the sctp service and load balancer (VIP 10.123.123.101 port 10000).
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

We can use conntrack command to inspect sctp translations / events, while running multiple sctp connection test (previous command).

```
#
# First you need to understand which VM is carrying the VIP. This is where nat is enforced.
#

root@fiveg-host-24-node4:~# arp -na | grep 123.101
? (10.123.123.101) at 52:54:00:db:2b:ce [ether] on mpqemubr0.100
root@fiveg-host-24-node4:~# arp -na | grep  52:54:00:db:2b:ce
? (10.65.94.95) at 52:54:00:db:2b:ce [ether] on mpqemubr0
? (10.123.123.101) at 52:54:00:db:2b:ce [ether] on mpqemubr0.100
? (10.123.123.202) at 52:54:00:db:2b:ce [ether] on mpqemubr0.100
? (10.123.123.3) at 52:54:00:db:2b:ce [ether] on mpqemubr0.100 <--------- This VM3 !
root@fiveg-host-24-node4:~# 

#
# Let's inspect what is happening at vm3  
#

ubuntu@vm3:~$ sudo apt install conntrack
Reading package lists... Done
Building dependency tree... Done
[...]
ubuntu@vm3:~$ sudo conntrack -L -p sctp
sctp     132 6 CLOSED src=10.123.123.254 dst=10.123.123.101 sport=38211 dport=10000 src=10.42.2.37 dst=10.42.2.1 sport=9999 dport=1387 [ASSURED] mark=0 use=1
conntrack v1.4.6 (conntrack-tools): 1 flow entries have been shown.
ubuntu@vm3:~$ 
ubuntu@vm3:~$ sudo conntrack -E -p sctp
    [NEW] sctp     132 10 CLOSED src=10.123.123.254 dst=10.123.123.101 sport=49035 dport=10000 [UNREPLIED] src=10.42.1.36 dst=10.42.2.0 sport=9999 dport=36208
 [UPDATE] sctp     132 3 COOKIE_WAIT src=10.123.123.254 dst=10.123.123.101 sport=49035 dport=10000 src=10.42.1.36 dst=10.42.2.0 sport=9999 dport=36208
 [UPDATE] sctp     132 3 COOKIE_ECHOED src=10.123.123.254 dst=10.123.123.101 sport=49035 dport=10000 src=10.42.1.36 dst=10.42.2.0 sport=9999 dport=36208
 [UPDATE] sctp     132 210 ESTABLISHED src=10.123.123.254 dst=10.123.123.101 sport=49035 dport=10000 src=10.42.1.36 dst=10.42.2.0 sport=9999 dport=36208 [ASSURED]
 [UPDATE] sctp     132 3 SHUTDOWN_SENT src=10.123.123.254 dst=10.123.123.101 sport=49035 dport=10000 src=10.42.1.36 dst=10.42.2.0 sport=9999 dport=36208 [ASSURED]
 [UPDATE] sctp     132 3 SHUTDOWN_ACK_SENT src=10.123.123.254 dst=10.123.123.101 sport=49035 dport=10000 src=10.42.1.36 dst=10.42.2.0 sport=9999 dport=36208 [ASSURED]
 [UPDATE] sctp     132 10 CLOSED src=10.123.123.254 dst=10.123.123.101 sport=49035 dport=10000 src=10.42.1.36 dst=10.42.2.0 sport=9999 dport=36208 [ASSURED]
....

#
# We can see that sctp relies on random ports.
#
```

Let's inspect if sessions are load balanced.
For this purpose, we run a loop of 1000 sctp tests. For some reason, we get only 977 entries in conntrack... no big deal, that's good enough to do some stats.

From the external server (fiveg-host-24-node4): 
``` 
for ((i = 1; i <= 1000; i++)); do     sctp_test -H 10.123.123.254 -h 10.123.123.101 -p 10000 -s -x 1; done
```
Trace new entries (NEW status) on vm3 (=VIP owner) and count for each pod. The file is actually in the log folder of this repo. 
```
ubuntu@vm3:~$ sudo conntrack -E -p sctp -e new > test-1000-sessions.log
ubuntu@vm3:~$

#
# A rapid inspect of the file shows 3 pods IPs: 10.42.1.36, 10.42.2.37 and 10.42.0.38
#

#
# We can simply count each entry to check how load balancing worked.
#
ubuntu@vm3:~$ cat test-1000-sessions.log | wc
    977   13678  155189
ubuntu@vm3:~$ cat test-1000-sessions.log | grep 10.42.2.37 |  wc
    316    4424   50194
ubuntu@vm3:~$ cat test-1000-sessions.log | grep 10.42.0.38 |  wc
    338    4732   53696
ubuntu@vm3:~$ cat test-1000-sessions.log | grep 10.42.1.36 |  wc
    323    4522   51299
ubuntu@vm3:~$

```

CONCLUSION: *We're getting decent statistical distribution of the session on all pods.* . It seems we're not using ipvs (looks like a complex change in k3s unfortunately :-(), since ipvs can do round robin. 


####  5.3.9. <a name='MetallbwithIPSECstrongswanandSCTP'></a>Metallb with IPSEC (strongswan) and SCTP

##### TLDR - Test Results Summary

Long story short, there is a conflict between CNI NAT translation and IPSEC policies. This can be worked around with route-based VPN, which introduces more configuration complexity (interface definition and routes).

The below list summarizes the test results:
-  IPSEC-SCTP-1: IPSEC policy-based forwarding in hostnetwork  + sctp server pod HostNetwork: False + externalTrafficPolicy: Local   ===> FAILED
-  IPSEC-SCTP-2: IPSEC policy-based forwarding in hostnetwork  + sctp server pod HostNetwork: False + externalTrafficPolicy: Cluster ===> FAILED
-  IPSEC-SCTP-3: IPSEC policy-based forwarding in hostnetwork  + sctp server pod HostNetwork: True + externalTrafficPolicy: Local    ===> PASS
-  IPSEC-SCTP-4: IPSEC policy-based forwarding in hostnetwork  + sctp server pod HostNetwork: True + externalTrafficPolicy: Cluster  ===> PASS
-  IPSEC-SCTP-5: IPSEC route-based VPN (vti-based) in hostnetwork  + sctp server pod HostNetwork: False  ===> FAILED
-  IPSEC-SCTP-6: IPSEC route-based VPN (xfrmi-based) in hostnetwork  + sctp server pod HostNetwork: False  ===> PASS
- IPSEC-SCTP-7: Single pod for IPSEC and SCTP + HostNetwork: False ===> PASS
- IPSEC-SCTP-8: IPSEC policy-based forwarding with hostnetwork  False + sctp server pod with HostNetwork: False + SNAT ===> FAIL
- IPSEC-SCTP-9: IPSEC route-based VPN with hostnetwork  False + sctp server pod with HostNetwork: False + SNAT ===> PASS

##### Test Setup Installation

In this section, we're testing a more complex integration with dual Metallb services:
- A VIP exposes an external IP for IPSEC termination
- A VIP exposes an external IP for SCTP termination. The SCTP traffic is encrypted via IPSEC in tunnel mode.

The IPSEC is managed by strongswan running in hostnetwork, where tunnel are terminated. This approach simplifies the routing/ipsec policies (ip xfrm policy) back to the remote subnets.

The pod logic is as follow:
- 3 pods for IPSEC control plane (actually daemonset running on each server). 
- 6 pods for the SCTP servers so we can test local LB (2 per servers for testing ExternalTrafficPolicy: Local) 

The external VM (vm-ext) is a remote client for SCTP over IPSEC.

This logic is implemented thanks to two Metallb services:
- ipsec-vip with a virtual IP 10.123.123.200 in the external LAN  10.123.123.0/24. This service must be configured with   "externalTrafficPolicy: Local" to prevent any load balancing in IPSEC, which results in inconsistent synchronization between IPSEC  control and data plane. 
- sctp-server-vip1234 with a VIP 1.2.3.4/32. This VIP is somehow internal to the host and attached to no LAN since it is reachable via IPSEC. Depending on the requirements, this service can be configured with externalTrafficPolicy set to "Local or Cluster".

The following diagram summarizes this setup:

```                                          
                                                                  
         vm1                   vm2                   vm3          
+-------------------+ +-------------------+ +-------------------+ 
|                   | |                   | |                   | 
| +------+ +------+ | | +------+ +------+ | | +------+ +------+ | 
| | sctp | | sctp | | | | sctp | | sctp | | | | sctp | | sctp | | 
| | pod1 | | pod2 | | | | pod3 | | pod4 | | | | pod5 | | pod6 | | 
| +------+ +------+ | | +------+ +------+ | | +------+ +------+ | 
|    +-----------------------------------------------------+    | 
|    |                   SCTP VIP 1.2.3.4                  |    | 
|    +-----------------------------------------------------+    | 
|                   | |                   | |                   | 
|  +-------------+  | |  +-------------+  | |  +-------------+  | 
|  |  ipsec ds   |  | |  |  ipsec ds   |  | |  |  ipsec ds   |  | 
|  | hostnetwork |  | |  | hostnetwork |  | |  | hostnetwork |  | 
|  +-------------+  | |  +-------------+  | |  +-------------+  | 
+---------|---------+ +----------|--------+ +---------|---------+ 
  ens3.100|.1            ens3.100|            ens3.100|           
          |                      |                    |           
          |                      |                    |           
     +----------------------------------------------------+       
     |               IPSEC VIP 10.123.123.200             |       
     +----------------------------------------------------+       
          |                      |                    |           
          ---------------------------------------------           
                        vlan external network                     
                           10.123.123.0/24                        
                                 |                                
                                 |.4                              
                +---------------------------------+               
                |                                 |               
                |  SCTP over IPSEC:               |               
                |                                 |               
                |  SCTP SRC=5.6.7.8/32            |               
                |  SCTP DEST=1.2.3.4/32           |               
                |                                 |               
                |  IPSEC SRC=10.123.123.4         |               
                |  IPSEC DEST=10.123.123.200      |               
                |                                 |               
                +---------------------------------+               
                              vm-ext                              
                                                         
```

In the Kubernetes Cluster (vm1), launch the sctp service and deployment and the IPSEC daemonset:
```
kubectl apply -f https://raw.githubusercontent.com/robric/multipass-3-node-k8s/main/source/sctp-mlb-vip1234.yaml
kubectl apply -f https://raw.githubusercontent.com/robric/multipass-3-node-k8s/main/source/strongswan-daemonset.yaml
```

Here is what we get:

```
ubuntu@vm1:~$ kubectl get svc -o wide
NAME                  TYPE           CLUSTER-IP      EXTERNAL-IP      PORT(S)                        AGE   SELECTOR
ipsec-vip             LoadBalancer   10.43.149.137   10.123.123.200   500:31815/UDP,4500:30285/UDP   40h   app=strongswan
kubernetes            ClusterIP      10.43.0.1       <none>           443/TCP                        44h   <none>
sctp-server-vip1234   LoadBalancer   10.43.212.209   1.2.3.4          10000:30711/SCTP               15h   app=sctp-server-ipsec
ubuntu@vm1:~$ kubectl get pods -o wide
NAME                                 READY   STATUS    RESTARTS   AGE   IP             NODE   NOMINATED NODE   READINESS GATES
ipsec-ds-5lvxc                       1/1     Running   0          21h   10.65.94.22    vm2    <none>           <none>
ipsec-ds-qf8r8                       1/1     Running   0          21h   10.65.94.156   vm3    <none>           <none>
ipsec-ds-ql2nz                       1/1     Running   0          21h   10.65.94.121   vm1    <none>           <none>
sctp-server-ipsec-78c66f958b-4hl9r   1/1     Running   0          15h   10.42.0.38     vm1    <none>           <none>
sctp-server-ipsec-78c66f958b-92zz9   1/1     Running   0          15h   10.42.1.34     vm2    <none>           <none>
sctp-server-ipsec-78c66f958b-cjk4k   1/1     Running   0          15h   10.42.2.33     vm3    <none>           <none>
sctp-server-ipsec-78c66f958b-lppdm   1/1     Running   0          15h   10.42.2.34     vm3    <none>           <none>
sctp-server-ipsec-78c66f958b-qm2w9   1/1     Running   0          15h   10.42.0.39     vm1    <none>           <none>
sctp-server-ipsec-78c66f958b-wlwsg   1/1     Running   0          15h   10.42.1.33     vm2    <none>           <none>
ubuntu@vm1:~$ 
```

Next, to test connectivity of IPSEC/SCTP, use the VM (vm-ext) with the following manifest (it will deploy an IPSEC client with tunnel destination=10.123.123.200 -IPSEC VIP- and SA 5.6.7.8-1.2.3.4):

```
kubectl apply -f https://raw.githubusercontent.com/robric/multipass-3-node-k8s/main/source/strongswan-client.yaml
```

##### Test IPSEC-SCTP-1: IPSEC policy-based forwarding (default) + externalTrafficPolicy: Cluster == FAILED

- The IPSEC pods runs in kernel network namespace (hostnetwork:true)


Although, things seems to work, since the client ultimately get an answer thanks to restransmissions, we're actually having packet drops: **[RESULT = FAILED]**:

```
#
# This is the result externalTrafficPolicy: Cluster
#

#
# SCTP is actually broken, reaching the VIP 1.2.3.4 (sctp-server-vip1234) 
# However, there are some issues since return trafic to local pods is lost !!!! 
#

ubuntu@vm-ext:~$ sctp_test -H 5.6.7.8  -h 1.2.3.4 -p 10000 -s 
remote:addr=1.2.3.4, port=webmin, family=2
local:addr=5.6.7.8, port=0, family=2
seed = 1720175250

Starting tests...
        socket(SOCK_SEQPACKET, IPPROTO_SCTP)  ->  sk=3
        bind(sk=3, [a:5.6.7.8,p:0])  --  attempt 1/10
Client: Sending packets.(1/10)
        sendmsg(sk=3, assoc=0)    1 bytes.
          SNDRCV(stream=0 flags=0x1 ppid=880700277
        sendmsg(sk=3, assoc=0)    1 bytes.
          SNDRCV(stream=0 flags=0x1 ppid=1633539134
        sendmsg(sk=3, assoc=0)    1 bytes.
          SNDRCV(stream=0 flags=0x1 ppid=1373293174
        sendmsg(sk=3, assoc=0)    1 bytes.
          SNDRCV(stream=0 flags=0x1 ppid=410525908
        sendmsg(sk=3, assoc=0)    1 bytes.
          SNDRCV(stream=0 flags=0x1 ppid=682680410
        sendmsg(sk=3, assoc=0)    1 bytes.
          SNDRCV(stream=0 flags=0x1 ppid=1349506881
        sendmsg(sk=3, assoc=0)    1 bytes.
          SNDRCV(stream=0 flags=0x1 ppid=871858936
[...] 
#
# When running multiple trials, we can see that trafic if sent to any pod the cluster.
# 

# 1/ Find which server owns the VIP 10.123.123.200 by inspecting mac address:

ubuntu@vm-ext:~$ arp -na | grep 123.200
? (10.123.123.200) at 52:54:00:fd:51:52 [ether] on ens3.100
ubuntu@vm-ext:~$ arp -na | grep 52:54:00:fd:51:52
? (10.123.123.200) at 52:54:00:fd:51:52 [ether] on ens3.100
? (10.123.123.1) at 52:54:00:fd:51:52 [ether] on ens3.100  <----- That's vm1

#
# 2/ Connect to vm1 and run conntrack (sudo apt install conntrack) to inspect NAT contexts and check the src 
# of returning traffic (10.42.x.y). 
#
# We can see that the tests are unresponsive when the target pod 
# is running on vm1. These are actually packet drops (see next section for more traces). 
#

#
# This is the result externalTrafficPolicy: Cluster
#

ubuntu@vm1:~$ sudo conntrack -E -p sctp -e NEW
    [NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=34322 dport=10000 [UNREPLIED] src=10.42.2.34 dst=10.42.0.0 sport=9999 dport=28758
    [NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=34863 dport=10000 [UNREPLIED] src=10.42.0.39 dst=10.42.0.1 sport=9999 dport=24858
    [NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=34863 dport=10000 [UNREPLIED] src=10.42.2.33 dst=10.42.0.0 sport=9999 dport=16351
    [NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=58650 dport=10000 [UNREPLIED] src=10.42.1.34 dst=10.42.0.0 sport=9999 dport=27008
    [NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=58028 dport=10000 [UNREPLIED] src=10.42.0.39 dst=10.42.0.1 sport=9999 dport=32527
    [NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=58028 dport=10000 [UNREPLIED] src=10.42.1.34 dst=10.42.0.0 sport=9999 dport=14823
    [NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=44320 dport=10000 [UNREPLIED] src=10.42.1.34 dst=10.42.0.0 sport=9999 dport=31059
    [NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=53050 dport=10000 [UNREPLIED] src=10.42.0.39 dst=10.42.0.1 sport=9999 dport=33676
    [NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=53050 dport=10000 [UNREPLIED] src=10.42.2.34 dst=10.42.0.0 sport=9999 dport=17806
    [NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=49258 dport=10000 [UNREPLIED] src=10.42.2.34 dst=10.42.0.0 sport=9999 dport=44852
    [NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=51474 dport=10000 [UNREPLIED] src=10.42.2.34 dst=10.42.0.0 sport=9999 dport=39112
    [NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=32998 dport=10000 [UNREPLIED] src=10.42.2.33 dst=10.42.0.0 sport=9999 dport=38159
    [NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=38233 dport=10000 [UNREPLIED] src=10.42.0.38 dst=10.42.0.1 sport=9999 dport=12800
    [NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=38233 dport=10000 [UNREPLIED] src=10.42.1.34 dst=10.42.0.0 sport=9999 dport=39258

```
After investigations, we can see that
- E/W packets from vm1 to vm2/vm3 pods are OK
- local packets to VM1 pods are KO (dropped).

##### Test IPSEC-SCTP-2: IPSEC policy-based forwarding (default) + externalTrafficPolicy: Local == FAILED

Now let's toggle externalTrafficPolicy to "Local" (kubectl edit ...). As we can expect from the previous test, all packets are dropped.

```
#
# Use Kubectl edit svc sctp-server-vip1234 to toggle  
#  externalTrafficPolicy: Cluster -> Local
#


#
#        RESULT ==== It does not work at all !!!
# 

ubuntu@vm-ext:~$ sctp_test -H 5.6.7.8  -h 1.2.3.4 -p 10000 -s
remote:addr=1.2.3.4, port=webmin, family=2
local:addr=5.6.7.8, port=0, family=2
seed = 1720195042

Starting tests...
        socket(SOCK_SEQPACKET, IPPROTO_SCTP)  ->  sk=3
        bind(sk=3, [a:5.6.7.8,p:0])  --  attempt 1/10
Client: Sending packets.(1/10)
        sendmsg(sk=3, assoc=0)    1 bytes.
          SNDRCV(stream=0 flags=0x1 ppid=2055574450
^C
ubuntu@vm-ext:~$ 
#
#[...] NO RESPONSE
#

#
# NAT context are toward local pods (.40 and .41 in this trial):
#
ubuntu@vm1:~$ sudo conntrack -E -p sctp -e NEW
[NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=51396 dport=10000 [UNREPLIED] src=10.42.0.40 dst=5.6.7.8 sport=9999 dport=51396
[NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=51396 dport=10000 [UNREPLIED] src=10.42.0.41 dst=5.6.7.8 sport=9999 dport=51396
[NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=51396 dport=10000 [UNREPLIED] src=10.42.0.41 dst=5.6.7.8 sport=9999 dport=51396

Check pods .40 and .41.
ubuntu@vm1:~$ kubectl  get pods -o wide |grep vm1
[...]
sctp-server-ipsec-78c66f958b-2w62z   1/1     Running   0          28m    10.42.0.41     vm1    <none>           <none>
sctp-server-ipsec-78c66f958b-cwsf5   1/1     Running   0          28m    10.42.0.40     vm1    <none>           <none>
ubuntu@vm1:~$ 

#
# If we inspect at cni0 interface (flannel) where pods are living we see
# that SCTP responses are sent back [INIT ACK].
# 

ubuntu@vm1:~$ sudo tcpdump -vni cni0 "sctp"
tcpdump: listening on cni0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
09:01:15.457601 IP (tos 0x2,ECT(0), ttl 63, id 0, offset 0, flags [DF], proto SCTP (132), length 68)
    5.6.7.8.46020 > 10.42.0.40.9999: sctp (1) [INIT] [init tag: 2450773484] [rwnd: 106496] [OS: 10] [MIS: 65535] [init TSN: 1691014945] 
09:01:15.457960 IP (tos 0x2,ECT(0), ttl 64, id 0, offset 0, flags [DF], proto SCTP (132), length 292)
    10.42.0.40.9999 > 5.6.7.8.46020: sctp (1) [INIT ACK] [init tag: 2794367529] [rwnd: 106496] [OS: 10] [MIS: 10] [init TSN: 3101944263] 
09:01:18.522178 IP (tos 0x2,ECT(0), ttl 63, id 0, offset 0, flags [DF], proto SCTP (132), length 68)
 [...]

#
# But packets never reach properly the ens3.100 interface as if the IPSEC policy was ignored. 
# Only [INIT] packets - two attemps here - 
#

ubuntu@vm1:~$ sudo tcpdump -evni ens3.100 "sctp"
tcpdump: listening on ens3.100, link-type EN10MB (Ethernet), snapshot length 262144 bytes
09:03:23.888239 52:54:00:96:9d:ef > 52:54:00:fd:51:52, ethertype IPv4 (0x0800), length 82: (tos 0x2,ECT(0), ttl 64, id 0, offset 0, flags [DF], proto SCTP (132), length 68)
    5.6.7.8.46020 > 1.2.3.4.10000: sctp (1) [INIT] [init tag: 2714382025] [rwnd: 106496] [OS: 10] [MIS: 65535] [init TSN: 3715017747] 
09:03:27.033937 52:54:00:96:9d:ef > 52:54:00:fd:51:52, ethertype IPv4 (0x0800), length 82: (tos 0x2,ECT(0), ttl 64, id 0, offset 0, flags [DF], proto SCTP (132), length 68)
    5.6.7.8.57282 > 1.2.3.4.10000: sctp (1) [INIT] [init tag: 2714382025] [rwnd: 106496] [OS: 10] [MIS: 65535] [init TSN: 3715017747] 


#
# It looks like we're having some conflicts between IPSEC policies and Netfilter.
#
# Let's just "hack and see" and see if there is a quick win.
#

ubuntu@vm1:~$ sudo sysctl -w net.bridge.bridge-nf-call-iptables=0
net.bridge.bridge-nf-call-iptables = 0
ubuntu@vm1:~$ 

#
#   ===> no luck that did not help (observing packet drops)
#

```
##### Test IPSEC-SCTP-3 / IPSEC-SCTP-4  : IPSEC policy-based forwarding (default) + use of Hostnetwork + external network local/cluster == PASS/PASS

If we deploy sctp server pods in the hostnetwork, we're having a much simpler datapath with no interaction with the CNI.
Either update previous deployment or delete current/apply the following manifest. It will deploy the sctp servers in the hostnetwork with "externalTrafficPolicy: Local".

```
kubectl apply -f https://raw.githubusercontent.com/robric/multipass-3-node-k8s/main/source/sctp-mlb-svc-vip1234-hostnetwork-local.yaml
```

As we can expect, only 1 pod per node can be deployed since there is conflict with the nodeport. So this option does not allow scale-out.

```
ubuntu@vm1:~$ kubectl get pods --selector app=sctp-server-ipsec -o wide
NAME                                 READY   STATUS    RESTARTS   AGE    IP             NODE     NOMINATED NODE   READINESS GATES
sctp-server-ipsec-7697554b65-2z6wm   0/1     Pending   0          110s   <none>         <none>   <none>           <none>
sctp-server-ipsec-7697554b65-6lwx9   1/1     Running   0          110s   10.65.94.22    vm2      <none>           <none>
sctp-server-ipsec-7697554b65-7mpj6   0/1     Pending   0          110s   <none>         <none>   <none>           <none>
sctp-server-ipsec-7697554b65-7xbnb   0/1     Pending   0          110s   <none>         <none>   <none>           <none>
sctp-server-ipsec-7697554b65-r2f5g   1/1     Running   0          110s   10.65.94.156   vm3      <none>           <none>
sctp-server-ipsec-7697554b65-v8slk   1/1     Running   0          110s   10.65.94.121   vm1      <none>           <none>
ubuntu@vm1:~$ 
```

A test from the external SCTP/IPSEC client confirms that this works flawlessly.

```
ubuntu@vm-ext:~$ sctp_test -H 5.6.7.8  -h 1.2.3.4 -p 10000 -s
remote:addr=1.2.3.4, port=webmin, family=2
local:addr=5.6.7.8, port=0, family=2
seed = 1720861856

Starting tests...
        socket(SOCK_SEQPACKET, IPPROTO_SCTP)  ->  sk=3
        bind(sk=3, [a:5.6.7.8,p:0])  --  attempt 1/10
Client: Sending packets.(1/10)
        sendmsg(sk=3, assoc=0)    1 bytes.
          SNDRCV(stream=0 flags=0x1 ppid=1227113623
        sendmsg(sk=3, assoc=0)    1 bytes.
          SNDRCV(stream=0 flags=0x1 ppid=67657223
        sendmsg(sk=3, assoc=0)    1 bytes.
          SNDRCV(stream=0 flags=0x1 ppid=48650977
        sendmsg(sk=3, assoc=0)    1 bytes.
          SNDRCV(stream=0 flags=0x1 ppid=780993105
        sendmsg(sk=3, assoc=0)    1 bytes.
          SNDRCV(stream=0 flags=0x1 ppid=253104860
        sendmsg(sk=3, assoc=0)    1 bytes.
          SNDRCV(stream=0 flags=0x1 ppid=355882517
        sendmsg(sk=3, assoc=0)    1 bytes.
          SNDRCV(stream=0 flags=0x1 ppid=1128917297
        sendmsg(sk=3, assoc=0)    1 bytes.
          SNDRCV(stream=0 flags=0x1 ppid=1206479562
        sendmsg(sk=3, assoc=0)    1 bytes.
          SNDRCV(stream=0 flags=0x1 ppid=56642195
        sendmsg(sk=3, assoc=0)    1 bytes.
          SNDRCV(stream=0 flags=0x1 ppid=1180223014```
[...]
```

```
#
#   conntrack traces confirms that "externalTrafficPolicy: Local" is properly honored:
#             - IPSEC VIP master (here vm2) forwards trafic to local nodeport 10.65.94.22 (see kubectl get pods -o wide above).

    [NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=44662 dport=10000 [UNREPLIED] src=10.65.94.22 dst=5.6.7.8 sport=9999 dport=44662
    [NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=41286 dport=10000 [UNREPLIED] src=10.65.94.22 dst=5.6.7.8 sport=9999 dport=41286
    [NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=60827 dport=10000 [UNREPLIED] src=10.65.94.22 dst=5.6.7.8 sport=9999 dport=60827
    [NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=60073 dport=10000 [UNREPLIED] src=10.65.94.22 dst=5.6.7.8 sport=9999 dport=60073
    [NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=38883 dport=10000 [UNREPLIED] src=10.65.94.22 dst=5.6.7.8 sport=9999 dport=38883
    [NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=51788 dport=10000 [UNREPLIED] src=10.65.94.22 dst=5.6.7.8 sport=9999 dport=51788
```

We can change the service configuration to externalTrafficPolicy: Cluster to verify if load balancing works properly.

```

#
# Run multiple tests with from the client side:
#

ubuntu@vm-ext:~$ sctp_test -H 5.6.7.8  -h 1.2.3.4 -p 10000 -s
remote:addr=1.2.3.4, port=webmin, family=2
local:addr=5.6.7.8, port=0, family=2
seed = 1720862539

Starting tests...
        socket(SOCK_SEQPACKET, IPPROTO_SCTP)  ->  sk=3
        bind(sk=3, [a:5.6.7.8,p:0])  --  attempt 1/10
Client: Sending packets.(1/10)
[...]

#
# Check the result of NAT translation in conntrack and look at the src= for nodeports IP (target SCTP server hooks).
# Note also the enforcement of SNAT with the IPSEC VIP owner nodeport IP (dst=10.65.94.22)
#

ubuntu@vm2:~$ sudo conntrack -E -p sctp -e NEW
    [NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=40375 dport=10000 [UNREPLIED] src=10.65.94.22 dst=5.6.7.8 sport=9999 dport=40375
    [NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=50512 dport=10000 [UNREPLIED] src=10.65.94.22 dst=5.6.7.8 sport=9999 dport=50512
    [NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=35412 dport=10000 [UNREPLIED] src=10.65.94.121 dst=10.65.94.22 sport=9999 dport=50422
    [NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=46142 dport=10000 [UNREPLIED] src=10.65.94.121 dst=10.65.94.22 sport=9999 dport=8137
    [NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=46735 dport=10000 [UNREPLIED] src=10.65.94.121 dst=10.65.94.22 sport=9999 dport=8345
    [NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=60532 dport=10000 [UNREPLIED] src=10.65.94.156 dst=10.65.94.22 sport=9999 dport=43488
    [NEW] sctp     132 10 CLOSED src=5.6.7.8 dst=1.2.3.4 sport=52803 dport=10000 [UNREPLIED] src=10.65.94.156 dst=10.65.94.22 sport=9999 dport=1521
```

#####  IPSEC-SCTP-5: IPSEC route-based VPN (vti-based) + HostNetwork: False  ===> FAILED

I was not able to have IPSEC configuration based on vti interfaces working using the legacy configuration mode for strongswan (aka stroke).
This is based on the configuration of vti interface matching a mark (100) in the IPSEC tunnel configuration.

Tested and NOT working:
- configuration installpolicy: yes and no
- cleaning of ip xfrm states in between tests 
- no use of VIP at all to simplify troubleshooting: overlay trafic between 5.6.7.8 (loopback on vm-ext) and 11.12.13.14 (loopback on vm1) / underlay IPSEC 10.123.123.4 (vm-ext) and 10.123.123.1 (vm1) with basic ping: ubuntu@vm-ext:~$ ping 11.12.13.14 -I 5.6.7.8


Strongswan configuration
```
###################  vm-ext

ipsec.conf:
----
config setup
    charondebug="ike 2, knl 2, cfg 2"

conn mytunnel
    authby=secret
    left=10.123.123.4
    leftid=@myclient
    leftsubnet=5.6.7.8/32
    right=10.123.123.1
    rightid=@myserver
    rightsubnet=1.2.3.4/32,11.12.13.14/32
    auto=start
    mark=100
    type=tunnel
    dpdaction=restart
    closeaction=restart
    #installpolicy=no
    dpddelay=10s
    dpdtimeout=30s

###################  vm1

ipsec.conf:
----
config setup
    charondebug="ike 2, knl 2, cfg 2"

conn mytunnel
    authby=secret
    left=%any
    leftid=@myserver
    leftsubnet=0.0.0.0/0
    right=%any
    rightid=%any
    rightsubnet=0.0.0.0/0
    auto=start
    aggressive=no
    type=tunnel
    dpddelay=10s
    dpdtimeout=30s
    keyexchange=ikev2
    mark=100
    reauth=no
    dpdaction=restart
    closeaction=restart
    #installpolicy=no
    compress=no
    mobike=yes
```

vti interface configuration:

```
vm-ext:

sudo ip link add vti100 type vti key 100 remote 10.123.123.4 local 10.123.123.1
sudo ip link set vti100 up
sudo ip addr add 77.77.77.2/24 remote 77.77.77.1/24 dev vti100
sudo sysctl -w "net.ipv4.conf.vti100.disable_policy=1"

vm1:

sudo ip link add vti100 type vti key 100 remote 10.123.123.1 local 10.123.123.4
sudo ip link set vti100 up
sudo ip addr add 77.77.77.1/24 remote 77.77.77.2/24 dev vti100
sudo sysctl -w "net.ipv4.conf.vti100.disable_policy=1"
```

RESULT:

Different type of failure:
- packets not transmitted at all over IPSEC (tcpdump)
- when transmitted, we get errors at vti interface (ip -s link show dev vti100)
- configuration of "mark" in the ipsec.conf is the trigger for dropping packets

#####  IPSEC-SCTP-6: IPSEC route-based VPN (xfrmi-based) + HostNetwork: False  ===> PASS

When using XFRM interfaces for route-based VPN together with swanctl-based configuration mode, things just work like a charm. There is no more packet drop. There might be a solution with the legacy ipsec.conf config (but I could not make it work at all).

The following manifest will install Strongswan with route-based VPN in the cluster together with a metallb VIP (10.123.123.200). A start script takes care of configuring the xfrm interface. 
```
cluster:

kubectl apply -f https://raw.githubusercontent.com/robric/k8s-svc-and-lb-testing/main/source/strongswan-daemonset-route-based-vpn.yaml

client (vm-ext):

kubectl apply -f https://raw.githubusercontent.com/robric/k8s-svc-and-lb-testing/main/source/strongswan-client-v2.yaml
```
Next, the same manifest for the SCTP servers (6) as in IPSEC-SCTP-1 is used for testing SCTP.
```
kubectl apply -f https://raw.githubusercontent.com/robric/multipass-3-node-k8s/main/source/sctp-mlb-vip1234.yaml
```

For conveniency, IPSEC configuration are displayed below. Only vm1 is based on latest swanctl configuration (swanctl.conf file), where the binding with xfrm interface happens thanks to the f_id_out/in identifiers, which must map with the xfrm interface identifier (123 in our case).

```
vm-ext (client): ipsec.conf (legacy)

config setup
    charondebug="ike 2, knl 2, cfg 2"
conn mytunnel
    authby=secret
    left=10.123.123.4
    leftid=@myclient
    leftsubnet=5.6.7.8/32
    right=10.123.123.200
    rightid=@myserver
    rightsubnet=1.2.3.4/32,11.12.13.14/32
    auto=start
    type=tunnel
    dpdaction=restart
    closeaction=restart
    #installpolicy=no
    dpddelay=10s
    dpdtimeout=30s
    #mark=123

vm1 (server) swanctl.conf:

connections {
  tunnel-accept-any {
    local_addrs  = %any
    remote_addrs = %any
    local {
      auth = psk
      id = myserver
    }
    remote {
      auth = psk
      id = myclient
    }
    children {
      net-net {
        if_id_out = 123
        if_id_in = 123
        mode = tunnel
        local_ts  = 0.0.0.0/0
        remote_ts = 0.0.0.0/0
        esp_proposals = aes128gcm128
        start_action = start
      }
    }
    version = 2
    mobike = no
    reauth_time = 10800
    proposals = aes128-sha256-modp3072
  }
}
secrets {
  ike-1 {
    id-1 = myserver
    id-2 = myclient
    secret = "verysecure"
  }
}
```

The interface Configuration for route-based VPN is the following:

```
###### 123 is the xfrm  identifier, which appears in swanctl config if_id_in/out variables.

sudo ip link add ipsec0 type xfrm if_id 123
sudo ip link set ipsec0 up
sudo ip route add 5.6.7.8/32 dev ipsec0
```

#####  IPSEC-SCTP-7: Single pod for IPSEC and SCTP + HostNetwork: False ===> PASS

**Description**

This test is just a variation with a pod combining both IPSEC (strongswan) and the sctp server (sctp_test). 

The definition VIP logic is working as follow:
- the VIP for IPSEC relies on metallg (unchanged)
- the VIP for SCTP is based on adding an address to the eth0 pod interface (no metallb).

The diagram below describes the design:

```
         vm1                   vm2                   vm3          
+-------------------+ +-------------------+ +-------------------+ 
|  +-------------+  | |  +-------------+  | |  +-------------+  | 
|  |     pod     |  | |  |     pod     |  | |  |     pod     |  | 
|  | ipsec+sctp  |  | |  | ipsec+sctp  |  | |  | ipsec+sctp  |  | 
|  |   server    |  | |  |   server    |  | |  |   server    |  | 
|  |             |  | |  |             |  | |  |             |  | 
|  |             |  | |  |             |  | |  |             |  | 
|  |    eth0     |  | |  |    eth0     |  | |  |    eth0     |  | 
|  |  1.2.3.4/32 |  | |  |  1.2.3.4/32 |  | |  |  1.2.3.4/32 |  | 
|  +------|------+  | |  +------|------+  | |  +------|------+  | 
|         |         | |         |         | |         |         | 
|       (cni)       | |       (cni)       | |       (cni)       | 
|                   | |                   | |                   | 
|                   | |                   | |                   | 
+---------|---------+ +----------|--------+ +---------|---------+ 
  ens3.100|.1            ens3.100|            ens3.100|           
          |                      |                    |           
          |                      |                    |           
     +----------------------------------------------------+       
     |               IPSEC VIP 10.123.123.200             |       
     +----------------------------------------------------+       
          |                      |                    |           
          ---------------------------------------------           
                        vlan external network                     
                           10.123.123.0/24                        
                                 |                                
                                 |.4                              
                +---------------------------------+               
                |                                 |               
                |  SCTP over IPSEC:               |               
                |                                 |               
                |  SCTP SRC=5.6.7.8/32            |               
                |  SCTP DEST=1.2.3.4/32           |               
                |                                 |               
                |  IPSEC SRC=10.123.123.4         |               
                |  IPSEC DEST=10.123.123.200      |               
                |                                 |               
                +---------------------------------+               
                              vm-ext      
```
This is clearly hacky (and requires NET_ADMIN), however this approach has some benefits:
- Relies on dedicated pod with  use of hostnetwork
- IPSEC working with policies with no need for route orchestration

The manifest can be found [here](source/sctpserver-with-ipsec.yaml). Here is the copy-paste for direct application in kubernetes.

```
kubectl apply -f https://raw.githubusercontent.com/robric/k8s-svc-and-lb-testing/refs/heads/main/source/sctpserver-with-ipsec.yaml
```

**Test Results**

SCTP and pings from external VM just work fine.

```(console)
ubuntu@vm-ext:~$ ping 1.2.3.4 -I 5.6.7.8
PING 1.2.3.4 (1.2.3.4) from 5.6.7.8 : 56(84) bytes of data.
64 bytes from 1.2.3.4: icmp_seq=1 ttl=64 time=0.439 ms
64 bytes from 1.2.3.4: icmp_seq=2 ttl=64 time=0.347 ms
64 bytes from 1.2.3.4: icmp_seq=3 ttl=64 time=0.386 ms
ubuntu@vm-ext:~$ sctp_test -H 5.6.7.8  -h 1.2.3.4 -p 10000 -s -x1
remote:addr=1.2.3.4, port=webmin, family=2
local:addr=5.6.7.8, port=0, family=2
seed = 1730986431

Starting tests...
        socket(SOCK_SEQPACKET, IPPROTO_SCTP)  ->  sk=3
        bind(sk=3, [a:5.6.7.8,p:0])  --  attempt 1/10
Client: Sending packets.(1/1)
        sendmsg(sk=3, assoc=0)    1 bytes.
          SNDRCV(stream=0 flags=0x1 ppid=728983727
        sendmsg(sk=3, assoc=0)    1 bytes.
          SNDRCV(stream=0 flags=0x1 ppid=1425489239
        sendmsg(sk=3, assoc=0)    1 bytes.
          SNDRCV(stream=0 flags=0x1 ppid=357345221
        sendmsg(sk=3, assoc=0)    1 bytes.
          SNDRCV(stream=0 flags=0x1 ppid=561134118
        sendmsg(sk=3, assoc=0)    1 bytes.
          SNDRCV(stream=0 flags=0x1 ppid=108735489
        sendmsg(sk=3, assoc=0)    1 bytes.
          SNDRCV(stream=0 flags=0x1 ppid=1090803534
        sendmsg(sk=3, assoc=0)    1 bytes.
```
#####  IPSEC-SCTP-8: IPSEC policy-based forwarding + HostNetwork: False + SNAT ===> FAIL

In this option, we use independant pods for IPSEC (pod network) and SCTP Server.
- IPSEC Tunnels are terminated in the pod network (hostnetwork: false). The IPSEC pod is created via Daemonset so we have a single pod per server. IPSEC MUST work with externaltrafficpolicy local to make sure there is no load balancing for IPSEC
- SNAT is enforced within the IPSEC pod with pod IP (aka. masquerade) to allow SCTP session to be routed back to the pod.
- SCTP server runs in a separate pod. We're reusing the same manifest as before.

```
         vm1                   vm2                   vm3          
+-------------------+ +-------------------+ +-------------------+ 
|                   | |                   | |                   | 
| +------+ +------+ | | +------+ +------+ | | +------+ +------+ | 
| | sctp | | sctp | | | | sctp | | sctp | | | | sctp | | sctp | | 
| | pod1 | | pod2 | | | | pod3 | | pod4 | | | | pod5 | | pod6 | | 
| |      | |      | | | |      | |      | | | |      | |      | | 
| | eth0 | | eth0 | | | | eth0 | | eth0 | | | | eth0 | | eth0 | | 
| +--||--+ +--||--+ | | +--||--+ +--||--+ | | +--||--+ +--||--+ | 
|                   | |                   | |                   | 
|                   | |                   | |                   | 
|    +-----------------------------------------------------+    | 
|    |                   SCTP VIP 1.2.3.4                  |    | 
|    +-----------------------------------------------------+    | 
|                   | |                   | |                   | 
|  +-------------+  | |  +-------------+  | |  +-------------+  | 
|  |  ipsec ds   |  | |  |  ipsec ds   |  | |  |  ipsec ds   |  | 
|  |     pod     |  | |  |     pod     |  | |  |     pod     |  | 
|  |             |  | |  |             |  | |  |             |  | 
|  |             |  | |  |             |  | |  |             |  | 
|  |   [SNAT]    |  | |  |   [SNAT]    |  | |  |   [SNAT]    |  | 
|  |    eth0     |  | |  |    eth0     |  | |  |    eth0     |  | 
|  +-----||------+  | |  +-----||------+  | |  +-----||------+  | 
|                   | |                   | |                   | 
|                   | |                   | |                   | 
+---------|---------+ +----------|--------+ +---------|---------+ 
  ens3.100|.1            ens3.100|.2          ens3.100|.3           
          |                      |                    |           
          |                      |                    |           
     +----------------------------------------------------+       
     |               IPSEC VIP 10.123.123.200             |       
     +----------------------------------------------------+       
          |                      |                    |           
          ---------------------------------------------           
                        vlan external network                     
                           10.123.123.0/24                        
                                 |                                
                                 |.4                              
                +---------------------------------+               
                |                                 |               
                |  SCTP over IPSEC:               |               
                |                                 |               
                |  SCTP SRC=5.6.7.8/32            |               
                |  SCTP DEST=1.2.3.4/32           |               
                |                                 |               
                |  IPSEC SRC=10.123.123.4         |               
                |  IPSEC DEST=10.123.123.200      |               
                |                                 |               
                +---------------------------------+               
                              vm-ext         
```
The deployment is achieved thanks to two manifests.
```
kubectl apply -f  https://raw.githubusercontent.com/robric/k8s-svc-and-lb-testing/refs/heads/main/source/sctp-mlb-svc-vip1234.yaml

kubectl apply -f  https://raw.githubusercontent.com/robric/k8s-svc-and-lb-testing/refs/heads/main/source/strongswan-ipsec-with-SNAT.yaml
```
**Test Results**

Unfortunately, SCTP packets are dropped in the same way than tests IPSEC-SCTP-3 and IPSEC-SCTP-4. The IPSEC policy seems to be conflicting with CNI/NAT enforcement. 
Concretely:
-  if metallb/SCTP load-balancing sends packets to a pod in a different server, things work
-  if metallb/SCTP load-balancing sends packets to a local pod, packets get dropped.

#####  IPSEC-SCTP-9: IPSEC route-based VPN + HostNetwork: False + SNAT ===> PASS

This test mixes techniques from IPSEC-SCTP-6 and IPSEC-SCTP-8 to overcome the problem of IPSEC policy-based forwarding and CNI. We're basically taking IPSEC-SCTP-8 deployment and use the route-based VPN configuration defined in IPSEC-SCTP-6.

```
         vm1                   vm2                   vm3          
+-------------------+ +-------------------+ +-------------------+ 
|                   | |                   | |                   | 
| +------+ +------+ | | +------+ +------+ | | +------+ +------+ | 
| | sctp | | sctp | | | | sctp | | sctp | | | | sctp | | sctp | | 
| | pod1 | | pod2 | | | | pod3 | | pod4 | | | | pod5 | | pod6 | | 
| |      | |      | | | |      | |      | | | |      | |      | | 
| | eth0 | | eth0 | | | | eth0 | | eth0 | | | | eth0 | | eth0 | | 
| +--||--+ +--||--+ | | +--||--+ +--||--+ | | +--||--+ +--||--+ | 
|                   | |                   | |                   | 
|                   | |                   | |                   | 
|    +-----------------------------------------------------+    | 
|    |                   SCTP VIP 1.2.3.4                  |    | 
|    +-----------------------------------------------------+    | 
|                   | |                   | |                   | 
|  +-------------+  | |  +-------------+  | |  +-------------+  | 
|  |  ipsec ds   |  | |  |  ipsec ds   |  | |  |  ipsec ds   |  | 
|  |             |  | |  |             |  | |  |             |  | 
|  |[ route     ]|  | |  |[ route     ]|  | |  |[ route     ]|  |
|  |[ 5.6.7.8/32]|  | |  |[ 5.6.7.8/32]|  | |  |[ 5.6.7.8/32]|  |
|  |[ via       ]|  | |  |[ via       ]|  | |  |[ via       ]|  |
|  |[ ipsec0    ]|  | |  |[ ipsec0    ]|  | |  |[ ipsec0    ]|  |
|  |             |  | |  |             |  | |  |             |  | 
|  | (dev ipsec0)|  | |  | (dev ipsec0)|  | |  | (dev ipsec0)|  | 
|  |   [SNAT]    |  | |  |   [SNAT]    |  | |  |   [SNAT]    |  | 
|  |    eth0     |  | |  |    eth0     |  | |  |    eth0     |  | 
|  +-----||------+  | |  +-----||------+  | |  +-----||------+  | 
|                   | |                   | |                   | 
|                   | |                   | |                   | 
+---------|---------+ +----------|--------+ +---------|---------+ 
  ens3.100|.1            ens3.100|.2          ens3.100|.3           
          |                      |                    |           
          |                      |                    |           
     +----------------------------------------------------+       
     |               IPSEC VIP 10.123.123.200             |       
     +----------------------------------------------------+       
          |                      |                    |           
          ---------------------------------------------           
                        vlan external network                     
                           10.123.123.0/24                        
                                 |                                
                                 |.4                              
                +---------------------------------+               
                |                                 |               
                |  SCTP over IPSEC:               |               
                |                                 |               
                |  SCTP SRC=5.6.7.8/32            |               
                |  SCTP DEST=1.2.3.4/32           |               
                |                                 |               
                |  IPSEC SRC=10.123.123.4         |               
                |  IPSEC DEST=10.123.123.200      |               
                |                                 |               
                +---------------------------------+               
                              vm-ext         
```

The deployment is achieved thanks to two manifests.

```
kubectl apply -f  https://raw.githubusercontent.com/robric/k8s-svc-and-lb-testing/refs/heads/main/source/sctp-mlb-svc-vip1234.yaml

kubectl apply -f  https://raw.githubusercontent.com/robric/k8s-svc-and-lb-testing/refs/heads/main/source/strongswan-ipsec-with-SNAT-route-based-VPN.yaml
```
You get these pods and svc:
```
ubuntu@vm1:~$ kubectl get pods -o wide
NAME                           READY   STATUS    RESTARTS   AGE     IP           NODE   NOMINATED NODE   READINESS GATES
ipsec-ds-jwrls                 1/1     Running   0          4m45s   10.42.1.66   vm2    <none>           <none>
ipsec-ds-kgrjg                 1/1     Running   0          4m45s   10.42.0.81   vm1    <none>           <none>
ipsec-ds-zkdfz                 1/1     Running   0          4m45s   10.42.2.64   vm3    <none>           <none>
sctp-server-78c66f958b-6hcl7   1/1     Running   0          3m27s   10.42.1.67   vm2    <none>           <none>
sctp-server-78c66f958b-gvp74   1/1     Running   0          3m27s   10.42.0.82   vm1    <none>           <none>
sctp-server-78c66f958b-j7wrh   1/1     Running   0          3m27s   10.42.2.66   vm3    <none>           <none>
sctp-server-78c66f958b-lzjk6   1/1     Running   0          3m27s   10.42.2.65   vm3    <none>           <none>
sctp-server-78c66f958b-tt8s4   1/1     Running   0          3m27s   10.42.1.68   vm2    <none>           <none>
sctp-server-78c66f958b-vnx4q   1/1     Running   0          3m27s   10.42.0.83   vm1    <none>           <none>
ubuntu@vm1:~$ 
ubuntu@vm1:~$ kubectl  get svc
NAME                  TYPE           CLUSTER-IP      EXTERNAL-IP      PORT(S)                        AGE
ipsec-vip             LoadBalancer   10.43.7.21      10.123.123.200   500:31727/UDP,4500:32569/UDP   7d1h
kubernetes            ClusterIP      10.43.0.1       <none>           443/TCP                        7d2h
sctp-server-vip1234   LoadBalancer   10.43.202.101   1.2.3.4          10000:32587/SCTP               7d1h
ubuntu@vm1:~$ 
```
CAVEAT:

**Just like in previous test (IPSEC-SCTP-7), the load balancing for SCTP happens cluster-wide since trafic is seen as cluster-internal (pod to pod).**

**Test Results**

This works ! There are no more drops observed in IPSEC-SCTP-7.

```
#
# Get ips from all pods for sctp server
# 

ubuntu@vm1:~$ kubectl get pods -o wide | grep sctp
sctp-server-78c66f958b-6hcl7   1/1     Running   0          6m17s   10.42.1.67   vm2    <none>           <none>
sctp-server-78c66f958b-gvp74   1/1     Running   0          6m17s   10.42.0.82   vm1    <none>           <none>
sctp-server-78c66f958b-j7wrh   1/1     Running   0          6m17s   10.42.2.66   vm3    <none>           <none>
sctp-server-78c66f958b-lzjk6   1/1     Running   0          6m17s   10.42.2.65   vm3    <none>           <none>
sctp-server-78c66f958b-tt8s4   1/1     Running   0          6m17s   10.42.1.68   vm2    <none>           <none>
sctp-server-78c66f958b-vnx4q   1/1     Running   0          6m17s   10.42.0.83   vm1    <none>           <none>

#
# Make sure we have Load balancing working to each of the pods (e.g. make sure local forwarding works since it was failing with policy)
# 

ubuntu@vm1:~$ sudo conntrack -E -e NEW -p sctp
    [NEW] sctp     132 10 CLOSED src=10.42.0.81 dst=1.2.3.4 sport=49194 dport=10000 [UNREPLIED] src=10.42.2.65 dst=10.42.0.0 sport=9999 dport=6721
    [NEW] sctp     132 10 CLOSED src=10.42.0.81 dst=1.2.3.4 sport=52841 dport=10000 [UNREPLIED] src=10.42.1.68 dst=10.42.0.0 sport=9999 dport=21766
    [NEW] sctp     132 10 CLOSED src=10.42.0.81 dst=1.2.3.4 sport=47027 dport=10000 [UNREPLIED] src=10.42.0.83 dst=10.42.0.1 sport=9999 dport=42700
    [NEW] sctp     132 10 CLOSED src=10.42.0.81 dst=1.2.3.4 sport=43233 dport=10000 [UNREPLIED] src=10.42.2.66 dst=10.42.0.0 sport=9999 dport=58046
    [NEW] sctp     132 10 CLOSED src=10.42.0.81 dst=1.2.3.4 sport=50469 dport=10000 [UNREPLIED] src=10.42.2.66 dst=10.42.0.0 sport=9999 dport=44253
    [NEW] sctp     132 10 CLOSED src=10.42.0.81 dst=1.2.3.4 sport=60397 dport=10000 [UNREPLIED] src=10.42.1.68 dst=10.42.0.0 sport=9999 dport=61726
    [NEW] sctp     132 10 CLOSED src=10.42.0.81 dst=1.2.3.4 sport=60582 dport=10000 [UNREPLIED] src=10.42.2.65 dst=10.42.0.0 sport=9999 dport=52108
    [NEW] sctp     132 10 CLOSED src=10.42.0.81 dst=1.2.3.4 sport=44875 dport=10000 [UNREPLIED] src=10.42.2.65 dst=10.42.0.0 sport=9999 dport=6425
    [NEW] sctp     132 10 CLOSED src=10.42.0.81 dst=1.2.3.4 sport=52146 dport=10000 [UNREPLIED] src=10.42.1.67 dst=10.42.0.0 sport=9999 dport=3980
```

##  6. <a name='OpenshiftIntegration'></a>Openshift Integration

###  6.1. <a name='Background'></a>Background

This section focuses on openshift, which has specific OVN-dependencies for setting up NAT translations.

###  6.2. <a name='SetupDescription'></a>Setup Description

The setup is made up 3 nodes and an external server:
- cluster nodes: fiveg-host-21-nodeX with X={1,3,4}
- external server: eksa-cluster . This server is used to reach metallb VIP (curl).

Each server is connected to:
- default k8s network with subnet 10.87.104.0/25)
- external network with subnet 10.131.2.0/24 
For more details on networking, see the "Interface, Routing and subnetting overview" section.

```
            +----------------------------------------------+    
            |                                              |
            |                   RHOCP                      |  
            |                  Cluster                     |    
            |                                              |   External VM
            |                                              |   (curl to VIP)
            | +------------+ +------------+ +------------+ | +------------+
            | |   host21-  | |   host21-  | |  host21-   | | |   eksa-    | 
            | |    node1   | |    node3   | |   node4    | | |  cluster   | 
            | +------------+ +------------+ +------------+ | +------------+
            | [k8s-if]  |     [k8s-if] |    [k8s-if]  |    |       :  |
            |   .21     |      .23     |      .24     |    |       :  |  
            |    :  [ext-if]    :   [ext-if]   :  [ext-if] |       :  |  
            |    :     .2       :     .3       :     .4    |       : .1  
            |    :      |       :      |       :      |    |       :  |   
            |    :      |       :      |       :      |    |       :  |  
            +----:------|-------:------|-------:------|----+       :  |
                 :      |       :      |           :  |            :  |  
                 :      |       :      |           :  |            :  |  
                 :      |       :      |           :  |            :  |   
                 :      +=========vlan 3002 (external)+===============+    
                 :              :  10.131.2.0/24  :                :
                 :              :                 :                :   
                 :              :                 :                : 
                 :              :                 :                : 
                 :              :                 :                :  
                 +---------  k8s  network    --+-------------------+ 
                              10.87.104.0/25       

Convention external interface:
[ext-if] =  ens1f1np1.3002 (vlan on additional NIC)
[k8s-if] =  br-ex (ovs bridge)
```

```
ec2-user@eksa-cluster:~$ oc get nodes -o wide
NAME                  STATUS   ROLES                         AGE   VERSION            INTERNAL-IP    EXTERNAL-IP   OS-IMAGE                                                       KERNEL-VERSION                 CONTAINER-RUNTIME
fiveg-host-21-node1   Ready    control-plane,master,worker   71d   v1.27.14+95b99ee   10.87.104.21   <none>        Red Hat Enterprise Linux CoreOS 414.92.202405282322-0 (Plow)   5.14.0-284.67.1.el9_2.x86_64   cri-o://1.27.6-5.rhaos4.14.gitbd7f4e0.el9
fiveg-host-21-node3   Ready    control-plane,master,worker   71d   v1.27.14+95b99ee   10.87.104.23   <none>        Red Hat Enterprise Linux CoreOS 414.92.202405282322-0 (Plow)   5.14.0-284.67.1.el9_2.x86_64   cri-o://1.27.6-5.rhaos4.14.gitbd7f4e0.el9
fiveg-host-21-node4   Ready    control-plane,master,worker   71d   v1.27.14+95b99ee   10.87.104.24   <none>        Red Hat Enterprise Linux CoreOS 414.92.202405282322-0 (Plow)   5.14.0-284.67.1.el9_2.x86_64   cri-o://1.27.6-5.rhaos4.14.gitbd7f4e0.el9
ec2-user@eksa-cluster:~$ 
```

Interface, Routing and subnetting overview:

- Openshifts sets-up the kubernetes routing a bridge interface: br-ex, where each node gets an IP from subnet 10.87.104.0/25. br-ex is an ovs-bridge that contains the phyiscal NIC used for the cluster and indirect connectivity to pods (details later).
- We created an additional network: 10.131.2.0/24 on interface ens1f1np1.3002 (vlan 3002) in which the metallb VIP is defined. 
- Pod network CIDR is 10.128.0.0/23, with a /25 subnet for each server (e.g. 10.128.0.128/25 in the trace below).
- Kubernetes service network CIDR is 172.30.0.0/25

```
[core@fiveg-host-21-node4 ~]$ ip route show 
default via 10.87.104.126 dev br-ex proto dhcp src 10.87.104.24 metric 48 
10.87.104.0/25 dev br-ex proto kernel scope link src 10.87.104.24 metric 48 
10.128.0.0/23 via 10.128.0.129 dev ovn-k8s-mp0 
10.128.0.128/25 dev ovn-k8s-mp0 proto kernel scope link src 10.128.0.130 
10.131.2.0/24 dev ens1f1np1.3002 proto kernel scope link src 10.131.2.4 metric 400 
169.254.169.0/29 dev br-ex proto kernel scope link src 169.254.169.2 
169.254.169.1 dev br-ex src 10.87.104.24 
169.254.169.3 via 10.128.0.129 dev ovn-k8s-mp0 
172.30.0.0/25 via 169.254.169.4 dev br-ex mtu 1400 
[core@fiveg-host-21-node4 ~]$ 

[core@fiveg-host-21-node4 ~]$ ip -d link show dev br-ex
18: br-ex: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/ether 84:16:0c:ad:e1:fc brd ff:ff:ff:ff:ff:ff promiscuity 1 minmtu 68 maxmtu 65535 
    openvswitch addrgenmode none numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 65536 tso_max_segs 65535 gro_max_size 65536 

```

###  6.3. <a name='MetallbInstallation'></a>Metallb Installation

Metallb can be installed following [IBM guidelines](https://docs.redhat.com/en/documentation/openshift_container_platform/4.14/html/networking/load-balancing-with-metallb#metallb-operator-install). There is nothing special to mention outside this:

*IMPORTANT: IpForwarding configuration setting since OCP 4.14*

To have metallb working with external networks, the cluster must be configured with "ipForwarding: Global". Without this, the VIP is not reachable from any external server.

```
ec2-user@eksa-cluster:~$ oc get network.operator.openshift.io cluster -o yaml
apiVersion: operator.openshift.io/v1
kind: Network
[...]
spec:
  clusterNetwork:
  - cidr: 10.128.0.0/23
    hostPrefix: 25
  defaultNetwork:
    ovnKubernetesConfig:
      egressIPConfig: {}
      gatewayConfig:
        ipForwarding: Global  <============================= VERY IMPORTANT !
[...]
```

More information on this configuration can be found in this [redhat link](https://docs.openshift.com/container-platform/4.14/networking/cluster-network-operator.html?extIdCarryOver=true&sc_cid=701f2000001Css5AAC#nw-operator-cr-cno-object_cluster-network-operator:~:text=host%20networking%20stack.-,ipForwarding,-object)


###  6.4. <a name='Metallbserviceinstantiation'></a>Metallb service instantiation

####  6.4.1. <a name='DeploymentwithExternalTraficPolicyCluster'></a>Deployment with ExternalTraficPolicy Cluster

The following manifest deploys the topology described below

```
kubectl apply -f https://raw.githubusercontent.com/robric/k8s-svc-and-lb-testing/main/source/nginx-mlb-svc-rhocp.yaml
```
```
            +----------------------------------------------+    
            |                                              |
            |                   RHOCP                      |  
            |                  Cluster                     |    
            |                                              |   External VM
            |                                              |   (curl to VIP)
            | +------------+ +------------+ +------------+ | 
            | |   nginx    | |   nginx    | |   nginx    | |
            | |    pod     | |    pod     | |    pod     | | +------------+
            | |            | |            | |            | | |            | 
            | |   host21-  | |   host21-  | |  host21-   | | |   eksa-    | 
            | |    node1   | |    node3   | |   node4    | | |  cluster   | 
            | +------------+ +------------+ +------------+ | +------------+
            | [k8s-if]  |     [k8s-if] |    [k8s-if]  |    |         |
            |   .21     |      .23     |      .24     |    |         |  
            |       [ext-if]        [ext-if]      [ext-if] |         |  
            |          .2             .3             .4    |        .1  
            |           |              |              |    |         |   
            |           |              |              |    |         |  
            +-----------|--------------|--------------|----+         |
                        |              |              |              |  
                        |              |              |              | 
                        |              |              |              | 
                   [ ****** VIP = 10.131.2.14:8080 ****** ]          |
                        |              |              |              |  
                        |              |              |              |   
                        +=========vlan 3002 (external)+===============+    
                                   10.131.2.0/24          
```

The service topology is as follow:
- 3 nginx pods in the cluster (ip addresses displayed below)
- a metallb load balancer server with VIP 10.131.2.14 (externaltrafficpolicy: Cluster)
- The services also is configured with 172.30.0.4 to cluster IP and port 32529 for nodeport

The pod and service details are the following:
```
ec2-user@eksa-cluster:~$ kubectl get pods -o wide | grep l2
nginx-lbl2-68879b7cdd-fz8xd       1/1     Running     1          4d4h   10.128.0.22    fiveg-host-21-node1   <none>           <none>
nginx-lbl2-68879b7cdd-nlgph       1/1     Running     0          27h    10.128.0.205   fiveg-host-21-node4   <none>           <none>
nginx-lbl2-68879b7cdd-nqdwk       1/1     Running     1          4d4h   10.128.0.219   fiveg-host-21-node4   <none>           <none>
ec2-user@eksa-cluster:~$ 
ec2-user@eksa-cluster:~$ kubectl get svc
NAME                                 TYPE           CLUSTER-IP     EXTERNAL-IP                            PORT(S)                      AGE
nginx-mlb-l2-service                 LoadBalancer   172.30.0.4     10.131.2.14                            8080:32529/TCP               4d4h
```

Let's now inspect the processing of the IP packet. As we will see, OVN behaves differently compared with flannel (previous sections).

####  6.4.2. <a name='RHCOPOVNnetworkingoverview'></a>RHCOP/OVN networking overview

Let's understand precisely how networking is handled in RHOCP.

First, the packets towads the Cluster IP pool 172.30.0.4 is forwarded  br-ex, which is an ovs bridge.

```
[core@fiveg-host-21-node4 ~]$ ip route
[...]
172.30.0.0/25 via 169.254.169.4 dev br-ex mtu 1400
```
This all starts with br-ex which has two ports:
- eno12399: this is the physical NIC
- patch-br-ex_fiveg-host-21-node4-to-br-int: this is a connection to another ovs bridge named br-int.

br-int is where most the bridge plumbing happens with: 
- pod interfaces (e.g. cf857e90ed06295 where backend nginx pods is deployed )
- Overlay Endpoint (e.g. ovn-577f3e-0 which connects to 10.87.104.21 - host-21-node1 via GENEVE)
- patch-br-int-to-br-ex_fiveg-host-21-node4: the connectino to br-ex

```
#
# trace logic networking plumbing logic
#

[core@fiveg-host-21-node4 ~]$ sudo ovs-vsctl  list-ports br-ex
eno12399
patch-br-ex_fiveg-host-21-node4-to-br-int
[core@fiveg-host-21-node4 ~]$ sudo ovs-vsctl  list-ifaces br-int
[...] list of all pod interfaces
cf857e90ed06295
[...]
ovn-577f3e-0
ovn-6ffbf2-0
ovn-k8s-mp0
patch-br-int-to-br-ex_fiveg-host-21-node4
[core@fiveg-host-21-node4 ~]$ sudo ovs-vsctl  show
[...]
        Port cf857e90ed06295
            Interface cf857e90ed06295
[...]
        Port patch-br-int-to-br-ex_fiveg-host-21-node4
            Interface patch-br-int-to-br-ex_fiveg-host-21-node4
                type: patch
                options: {peer=patch-br-ex_fiveg-host-21-node4-to-br-int}
[...]
        Port ovn-577f3e-0
            Interface ovn-577f3e-0
                type: geneve
                options: {csum="true", key=flow, remote_ip="10.87.104.21"}

#
# note that pod interfaces are ovs-defined veth 
#

[core@fiveg-host-21-node4 ~]$ sudo ip -d  link show dev cf857e90ed06295
203: cf857e90ed06295@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1400 qdisc noqueue master ovs-system state UP mode DEFAULT group default 
    link/ether 32:b4:21:2e:72:f3 brd ff:ff:ff:ff:ff:ff link-netns 091755c5-bb3f-45b5-a7d7-29382bc25b25 promiscuity 1 minmtu 68 maxmtu 65535 
    veth 
    openvswitch_slave addrgenmode eui64 numtxqueues 48 numrxqueues 48 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536

#
# 
#

```
The following drawing summarizes the findings:
- Two servers are shown with pods on each server. pod-to-pod reachability between servers is provided by OVN (Openshift SDN). 
- br-ex for external connectivity to the cluster and physical NIC
- br-int for cluster-internal connectivity 

```                                                                       
                                            SERVER host-21-node4       
            +--------------------------------------------------+       
   |        |                                                  |       
   |----------10.131.2.4          [br-ex]                      |       
external    |                       |                          |       
network     |                       |                          |       
   |        |             +------------|-----------+           |       
            |             |                        |           |       
            |[eno12399]   |       ovs-bridge       |           |       
      |-------------------+         br-ex          +------     |       
      |     | 10.87.104.24|                        |     |     |       
      |     |             |                        |     |     |       
      |     |             +------------------------+     |     |       
      |     |                                            |     |       
      |     |               +------------+               |     |       
      |     |               | nginx pod  |               |     |       
      |     |                10.128.0.205             [patch]  |       
      |     |               +------------+               |     |       
      |     |                  [eth0]                    |     |       
      |     |                     |                      |     |       
      |     |                     | veth                 |     |       
      |     |                     |                      |     |       
  underlay  |              [cf857e90ed06295]             |     |       
 networking |                     |                      |     |       
      |     |              +------|--------------+       |     |       
      |     |              |                     |       |     |       
      |     |[ovn-577f3e-0]|   ovs-bridge        |       |     |       
      |     |      |--------     br-int          ---------     |       
      |     |      |       |                     |             |       
      |     |      |       |                     |             |       
      |     |      |       +---------------------+             |       
      |     +------|-------------------------------------------+   
      |            |                                                
      |     GENEVE overlay                                                
      |       networking                    SERVER host-21-node1       
      |     +------|-------------------------------------------+       
      |     |      |       +--------------+                    |       
      -------------|-------|  ovs-bridge  ------|              |       
            |      |       |    br-ex     |     |              |       
            |      |       +--------------+  [patch]           |       
            |      |       +--------------+     |              |       
            |      ---------  ovs-bridge  |     |              |       
            |[ovn-xxxxxxxx]|    br-int    ------|              |       
            |              +-----|--------+                    |       
            |                    |                             |       
            |              +-----|-----+                       |       
            |              | nginx pod |                       |       
            |               10.128.0.22                        |       
            |              +-----------+                       |       
            +--------------------------------------------------+       
 [patch] = patch-br-int-to-br-ex_fiveg-host-21-node4  
```


####  6.4.3. <a name='InspectiptablesduringwhenasessiontoVIPisinitiatedfromtheexternalserver-----SRC10.131.2.3.XXXXXDST10.131.2.14.8080'></a>Inspect iptables during when a session to VIP is initiated from the external server -----> SRC=10.131.2.3.XXXXX DST=10.131.2.14.8080


Find the VIP owner by looking at mac address from the external server

```
##### From an external server check mac 

ec2-user@eksa-cluster:~$ arp -na | grep 131.2
? (10.131.2.3) at 84:16:0c:e1:e1:11 [ether] on v.3002
? (10.131.2.2) at 84:16:0c:e7:0d:c1 [ether] on v.3002
? (10.131.2.4) at 84:16:0c:e7:3e:f1 [ether] on v.3002
? (10.131.2.14) at 84:16:0c:e7:3e:f1 [ether] on v.3002
ec2-user@eksa-cluster:~$ 

#    ===> so this is 84:16:0c:e7:3e:f1 which belongs to 10.131.2.4 === fiveg-host-21-node4 
#    Let's sssh to this server to run iptables traces now
#
```

Now let's have a look iptable trace during test from external server "curl 10.131.2.14:8080".

```

[core@fiveg-host-21-node4 ~]$ sudo iptables -t raw -A PREROUTING -p tcp -m tcp --dport 8080 -j TRACE
[core@fiveg-host-21-node4 ~]$ sudo nft monitor
trace id 552cb577 ip raw PREROUTING packet: iif "ens1f1np1.3002" ether saddr 84:16:0c:e7:45:a1 ether daddr 84:16:0c:e7:3e:f1 vlan pcp 0 vlan dei 0 vlan id 3002 ip saddr 10.131.2.1 ip daddr 10.131.2.14 ip dscp 0x04 ip ecn not-ect ip ttl 64 ip id 6310 ip length 60 tcp sport 46368 tcp dport 8080 tcp flags == syn tcp window 64240 
trace id 552cb577 ip raw PREROUTING rule tcp dport 8080 counter packets 394 bytes 24141 meta nftrace set 1 (verdict continue)
trace id 552cb577 ip raw PREROUTING verdict continue 
trace id 552cb577 ip raw PREROUTING policy accept 
trace id 552cb577 ip nat PREROUTING packet: iif "ens1f1np1.3002" ether saddr 84:16:0c:e7:45:a1 ether daddr 84:16:0c:e7:3e:f1 vlan pcp 0 vlan dei 0 vlan id 3002 ip saddr 10.131.2.1 ip daddr 10.131.2.14 ip dscp 0x04 ip ecn not-ect ip ttl 64 ip id 6310 ip length 60 tcp sport 46368 tcp dport 8080 tcp flags == syn tcp window 64240 
trace id 552cb577 ip nat PREROUTING rule counter packets 1138501 bytes 69191411 jump OVN-KUBE-ETP (verdict jump OVN-KUBE-ETP)
trace id 552cb577 ip nat OVN-KUBE-ETP verdict continue 
trace id 552cb577 ip nat PREROUTING rule counter packets 1138480 bytes 69190151 jump OVN-KUBE-EXTERNALIP (verdict jump OVN-KUBE-EXTERNALIP)
trace id 552cb577 ip nat OVN-KUBE-EXTERNALIP rule ip daddr 10.131.2.14 tcp dport 8080 counter packets 44 bytes 2592 dnat to 172.30.0.4:8080 (verdict accept)
trace id 552cb577 ip filter FORWARD packet: iif "ens1f1np1.3002" oif "br-ex" ether saddr 84:16:0c:e7:45:a1 ether daddr 84:16:0c:e7:3e:f1 vlan pcp 0 vlan dei 0 vlan id 3002 ip saddr 10.131.2.1 ip daddr 172.30.0.4 ip dscp 0x04 ip ecn not-ect ip ttl 63 ip id 6310 ip length 60 tcp sport 46368 tcp dport 8080 tcp flags == syn tcp window 64240 
trace id 552cb577 ip filter FORWARD rule ip daddr 172.30.0.0/25 counter packets 179 bytes 11369 accept (verdict accept)
trace id 552cb577 ip nat POSTROUTING packet: iif "ens1f1np1.3002" oif "br-ex" ether saddr 84:16:0c:e7:45:a1 ether daddr 84:16:0c:e7:3e:f1 vlan pcp 0 vlan dei 0 vlan id 3002 ip saddr 10.131.2.1 ip daddr 172.30.0.4 ip dscp 0x04 ip ecn not-ect ip ttl 63 ip id 6310 ip length 60 tcp sport 46368 tcp dport 8080 tcp flags == syn tcp window 64240 
trace id 552cb577 ip nat POSTROUTING rule counter packets 5777353 bytes 347484587 jump OVN-KUBE-EGRESS-IP-MULTI-NIC (verdict jump OVN-KUBE-EGRESS-IP-MULTI-NIC)
trace id 552cb577 ip nat OVN-KUBE-EGRESS-IP-MULTI-NIC verdict continue 
trace id 552cb577 ip nat POSTROUTING rule counter packets 5777356 bytes 347484763 jump OVN-KUBE-EGRESS-SVC (verdict jump OVN-KUBE-EGRESS-SVC)
trace id 552cb577 ip nat OVN-KUBE-EGRESS-SVC verdict continue 
trace id 552cb577 ip nat POSTROUTING rule  ct status dnat counter packets 174 bytes 10392 jump CRIO-HOSTPORTS-MASQ (verdict jump CRIO-HOSTPORTS-MASQ)
trace id 552cb577 ip nat CRIO-HOSTPORTS-MASQ rule  counter packets 174 bytes 10392 jump CRIO-MASQ-C2WD6IWOV6PO2R2J (verdict jump CRIO-MASQ-C2WD6IWOV6PO2R2J)
trace id 552cb577 ip nat CRIO-MASQ-C2WD6IWOV6PO2R2J verdict continue 
trace id 552cb577 ip nat CRIO-HOSTPORTS-MASQ verdict continue 
trace id 552cb577 ip nat POSTROUTING verdict continue 
trace id 552cb577 ip nat POSTROUTING policy accept 

#
#     We can notice that:
#   - initial packet 10.131.2.1->10.131.2.1:8080 it DNatted to 10.131.2.1->172.30.0.4:8080, which is the
#     Cluster IP address 
#   - packets are properly forwarded to br-ex interface (see ip route) 
#

#  A summary of nat iptables inspection confirms the NAT action visible in the trace. 

[core@fiveg-host-21-node4 ~]$ sudo iptables -t nat -L -v
Chain PREROUTING (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         
 4958  298K REDIRECT   tcp  --  any    any     anywhere             fiveg-host-21-node4  tcp dpt:sun-sr-https /* OCP_API_LB_REDIRECT */ redir ports 9445
1140K   69M OVN-KUBE-ETP  all  --  any    any     anywhere             anywhere            
1140K   69M OVN-KUBE-EXTERNALIP  all  --  any    any     anywhere             anywhere            

Chain OVN-KUBE-EXTERNALIP (2 references)
 pkts bytes target     prot opt in     out     source               destination         
[...]
   45  2652 DNAT       tcp  --  any    any     anywhere             10.131.2.14          tcp dpt:webcache to:172.30.0.4:8080
```

We also can see after NAT to the service IP, the packets are forwarded to a link local address 169.254.169.4 on br-ex (ovs-bridge). We'll inspect this later.

```
[core@fiveg-host-21-node4 ~]$ ip route
[...]
172.30.0.0/25 via 169.254.169.4 dev br-ex mtu 1400
```

####  6.4.4. <a name='Checkpackettransformationuptopodwhentransitingovs-bridgebr-ex-----SRC10.131.2.3.XXXXXDST172.30.0.4.8080'></a>2. Check packet transformation up to pod when transiting ovs-bridge br-ex -----> SRC=10.131.2.3.XXXXX DST=172.30.0.4.8080**

After iptables DNAT, the packet is now  SRC=10.131.2.3.XXXXX DST=172.30.0.4.8080

Before starting, let's first have a look at how packets get transformed when hitting the backend pods by comparing with tcpdump.

```

# i) Find the interface of a backend pod for tcpdump

#
# Let's take a pod on node4  and run some tcpdump from there. 
# from oc api client - find a pod on node4 and pick one - => - nginx-lbl2-68879b7cdd-nlgph with ip address 10.128.0.205 -
#

ec2-user@eksa-cluster:~$ kubectl get pods -o wide | grep node4
nginx-lbl2-68879b7cdd-nlgph            1/1     Running     0          2d1h    10.128.0.205   fiveg-host-21-node4   <none>           <none>
nginx-lbl2-68879b7cdd-nqdwk            1/1     Running     1          5d2h    10.128.0.219   fiveg-host-21-node4   <none>           <none>
ec2-user@eksa-cluster:~$ 

#
# Find a container id running in this pod  => 0e82ab8e90aee
#

[core@fiveg-host-21-node4 ~]$ sudo crictl ps | grep nginx-lbl2-68879b7cdd-nlgph
0e82ab8e90aee       docker.io/library/nginx@sha256:447a8665cc1dab95b1ca778e162215839ccbb9189104c79d7ec3a81e14577add                                              2 days ago          Running             nginx                                         0                   cf857e90ed062       nginx-lbl2-68879b7cdd-nlgph
[core@fiveg-host-21-node4 ~]$ 

#
# Find which namespace it binds to => 091755c5-bb3f-45b5-a7d7-29382bc25b25
#

[core@fiveg-host-21-node4 ~]$ sudo crictl inspect 0e82ab8e90aee | grep -C 1 network
          {
            "type": "network",
            "path": "/var/run/netns/091755c5-bb3f-45b5-a7d7-29382bc25b25"
[core@fiveg-host-21-node4 ~]$ 

#
# Now find the interface that connects to the pod => cf857e90ed06295
#

[core@fiveg-host-21-node4 ~]$ ip -o  link show | grep 091755c5-bb3f-45b5-a7d7-29382bc25b25
203: cf857e90ed06295@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1400 qdisc noqueue master ovs-system state UP mode DEFAULT group default \    link/ether 32:b4:21:2e:72:f3 brd ff:ff:ff:ff:ff:ff link-netns 091755c5-bb3f-45b5-a7d7-29382bc25b25
[core@fiveg-host-21-node4 ~]$ 

ii) Run TCPdump sessions and compare

#
# Run two sessions of TCPDUMP:
#   - a session on br-ex
#   - a session on the pod interface cf857e90ed06295
#

#
# TCPdump excludes some  endpoints since 8080 is in use ---- yes that was a poor choice of port ---
#

[root@fiveg-host-21-node4 /]# tcpdump -evni  any "port 8080 and not host 10.128.0.130 and not host 10.128.0.142 and not host 10.128.0.216 and not host 10.128.0.133 and not host 10.128.0.215"  

-> initial interface ens1f1np1.3002

12:47:13.941249 ens1f1np1.3002 In  ifindex 12 84:16:0c:e7:45:a1 ethertype IPv4 (0x0800), length 80: (tos 0x10, ttl 64, id 20723, offset 0, flags [DF], proto TCP (6), length 60)
    10.131.2.1.51136 > 10.131.2.14.webcache: Flags [S], cksum 0x53a4 (correct), seq 1000475908, win 64240, options [mss 1460,sackOK,TS val 410818531 ecr 0,nop,wscale 7], length 0

-> intermediate interface br-ex

12:47:13.941281 br-ex Out ifindex 18 84:16:0c:ad:e1:fc ethertype IPv4 (0x0800), length 80: (tos 0x10, ttl 63, id 20723, offset 0, flags [DF], proto TCP (6), length 60)
    10.131.2.1.51136 > 172.30.0.4.webcache: Flags [S], cksum 0xb412 (correct), seq 1000475908, win 64240, options [mss 1460,sackOK,TS val 410818531 ecr 0,nop,wscale 7], length 0

-> target cf857e90ed06295 (confirmed --- ok we might have just trust tcpdump too :-) -- )

12:47:13.942351 cf857e90ed06295 Out ifindex 203 0a:58:0a:80:00:81 ethertype IPv4 (0x0800), length 80: (tos 0x10, ttl 61, id 20723, offset 0, flags [DF], proto TCP (6), length 60)
    100.64.0.4.51136 > 10.128.0.205.webcache: Flags [S], cksum 0xfd27 (correct), seq 1000475908, win 64240, options [mss 1460,sackOK,TS val 410818531 ecr 0,nop,wscale 7], length 0
```

All in all, we have a new round of translation with both SNAT and DNAT
- initial packet to VIP:         10.131.2.1.51136 > 10.131.2.14.8080
- br-ex to Cluster IP:           10.131.2.1.51136 > 172.30.0.4.8080
- interface to POD:              100.64.0.4.51136 > 10.128.0.205.8080

The pool for SNAT that is in OCP is actually defined in [RFC 6598 - IANA-Reserved IPv4 Prefix for Shared Address Space](https://www.rfc-editor.org/rfc/rfc6598.html). This is the official pool for CGNAT.


####  6.4.5. <a name='Packethandlinginbr-ex'></a>4. Packet handling in br-ex

After iptables translation, packets Enter the br-ex bridge thanks to the following route:

```
[core@fiveg-host-21-node4 ~]$ sudo ip route show 
172.30.0.0/25 via 169.254.169.4 dev br-ex mtu 1400 
```
We can find the mac address associated with this route
```
[core@fiveg-host-21-node4 ~]$ arp -na | grep 169.254.169.4
? (169.254.169.4) at 0a:58:a9:fe:a9:04 [ether] PERM on br-ex
[core@fiveg-host-21-node4 ~]$ 
``` 

```
sh-5.1# ovn-nbctl list Static_MAC_Binding
_uuid               : bd1b8111-2356-429c-9b69-3750c83a354a
ip                  : "169.254.169.4"
logical_port        : rtoe-GR_fiveg-host-21-node4
mac                 : "0a:58:a9:fe:a9:04"
override_dynamic_mac: true
sh-5.1#  
sh-5.1#  ovn-nbctl list Logical_Router_Port
[...]
_uuid               : 3c9cf92e-712e-431b-b435-d4b0dfbb34c1
enabled             : []
external_ids        : {gateway-physical-ip=yes}
gateway_chassis     : []
ha_chassis_group    : []
ipv6_prefix         : []
ipv6_ra_configs     : {}
mac                 : "84:16:0c:ad:e1:fc"
name                : rtoe-GR_fiveg-host-21-node4
networks            : ["10.87.104.24/25"]
options             : {}
peer                : []
status              : {}
```

```
_uuid               : 010cc856-69c7-45f8-9f42-65302807639e
external_ids        : {"k8s.ovn.org/kind"=Service, "k8s.ovn.org/owner"="default/nginx-mlb-l2-service"}
health_check        : []
ip_port_mappings    : {}
name                : "Service_default/nginx-mlb-l2-service_TCP_cluster"
options             : {event="false", hairpin_snat_ip="169.254.169.5 fd69::5", neighbor_responder=none, reject="true", skip_snat="false"}
protocol            : tcp
selection_fields    : []
vips                : {"10.131.2.14:8080"="10.128.0.205:8080,10.128.0.219:8080,10.128.0.22:8080", "172.30.0.4:8080"="10.128.0.205:8080,10.128.0.219:8080,10.128.0.22:8080"}

sh-5.1#  ovn-nbctl lr-route-list af13f28e-e34b-427c-80b7-7e5ce1ff71e4
IPv4 Routes
Route Table <main>:
         169.254.169.0/29             169.254.169.4 dst-ip rtoe-GR_fiveg-host-21-node4
            10.128.0.0/23                100.64.0.1 dst-ip
                0.0.0.0/0             10.87.104.126 dst-ip rtoe-GR_fiveg-host-21-node4
sh-5.1#  ovn-nbctl lr-route-list b6bb5c79-f347-42ea-a604-a4f54ab8216c 
IPv4 Routes
Route Table <main>:
               100.64.0.2                100.88.0.2 dst-ip
               100.64.0.3                100.88.0.3 dst-ip
               100.64.0.4                100.64.0.4 dst-ip
            10.128.0.0/25                100.88.0.2 dst-ip
            10.128.1.0/25                100.88.0.3 dst-ip
            10.128.0.0/23                100.64.0.4 src-ip
sh-5.1# 

```
```
[core@fiveg-host-21-node4 ~]$ sudo ovs-dpctl  dump-flows | grep  8080
recirc_id(0x1ac),in_port(5),ct_state(+new-rel+trk),eth(),eth_type(0x0800),ipv4(dst=172.30.0.4,proto=6,frag=no),tcp(dst=8080), packets:0, bytes:0, used:never, actions:hash(l4(0)),recirc(0xdedf4)
recirc_id(0xdf0a5),dp_hash(0xd/0xf),in_port(5),eth(),eth_type(0x0800),ipv4(frag=no), packets:0, bytes:0, used:never, actions:ct(commit,zone=14,mark=0xa/0xa,nat(dst=10.128.0.219:8080)),recirc(0xdf09c)

```

##  7. <a name='EgressIPopenshiftwithOVNkubernetesonly'></a>EgressIP  (openshift with OVNkubernetes only )

###  7.1. <a name='Background-1'></a>Background 

Metalb permits to expose external VIPs for Ingress Traffic by DNATtting traffic (note: we saw earlier that there can be also some SNAT as well during the NAT process).
For egress, traffic EgressIP permits to SNAT traffic in order to expose stable VIP to extrenal servers when initating connection from the kubernetes cluster.

There is actually a good YT video from Franck that explains egressIP as well as plenty of other things that are covered here: 
[MetalLB 201 - Advanced traffic steering](https://www.youtube.com/watch?v=AE50Gt54e4I).

*Note: the configuration and tests described in this section  applies to the OVNKubernetes CNI only. This does not apply to Openshift SDN.*

###  7.2. <a name='Testing'></a>Testing

####  7.2.1. <a name='PreparationoftheCluster'></a>Preparation of the Cluster

From openshift 4.14.  using OVNKubernetes CNI, the gatewaymode and hostrouting must be switched if we want EgressIP for *external networks* . This is controlled thanks to the network operator with the following parameters in spec.defaultnetwork.ovnKubernetesConfig.gatewayConfig:  
- ipForwarding: Global
- routingViaHost: true

So you ultimately get something like that:
```
ec2-user@eksa-cluster:~$ oc get network.operator cluster -o yaml
apiVersion: operator.openshift.io/v1
kind: Network
spec:
[...]
  defaultNetwork:
    ovnKubernetesConfig:
      egressIPConfig: {}
      gatewayConfig:
        ipForwarding: Global
        routingViaHost: true
```

Next, once this is done, label nodes where you want egressIP (SNAT) to be managed.

```
ec2-user@eksa-cluster:~$ oc get nodes -o wide
NAME      STATUS   ROLES                         AGE    VERSION            INTERNAL-IP    EXTERNAL-IP   OS-IMAGE                                                       KERNEL-VERSION                 CONTAINER-RUNTIME
master1   Ready    control-plane,master,worker   136d   v1.27.16+e826056   10.87.104.21   <none>        Red Hat Enterprise  [...]
master2   Ready    control-plane,master,worker   136d   v1.27.16+e826056   10.87.104.23   <none>        Red Hat Enterprise  [...]
master3   Ready    control-plane,master,worker   136d   v1.27.16+e826056   10.87.104.24   <none>        Red Hat Enterprise  [...]

ec2-user@eksa-cluster:~$ 
ec2-user@eksa-cluster:~$ oc label nodes master1 k8s.ovn.org/egress-assignable=""
ec2-user@eksa-cluster:~$ oc label nodes master2 k8s.ovn.org/egress-assignable=""
ec2-user@eksa-cluster:~$ oc label nodes master3 k8s.ovn.org/egress-assignable=""
```

####  7.2.2. <a name='DefinitionofEgressIP'></a>Definition of EgressIP

The you can define your EgressIP - in this example 10.131.2.15 -, which an external network (cf oc get nodes with primary IPs in 10.87.104.0/24).
We have two selectors for granular application of the EgressIP
- namespace selector: select the namespace with label affiinity.
- pod selector: select the pods/apps which you want to use this EgressIP. This option permits to have several EgressIP on different vlans (e.g. management, internal, dataplane... )  and maps these to specific egress trafic.

In our case,  we launch a test pod in namespace test-ns-egressip 

```
kubectl run  test-pod --namespace test-ns-egressip  --image=nicolaka/netshoot --command -- sleep infinity
```

This result in the deployment is a pod  with appropriate labels which are used in the definition of the EgressIP.

```
ec2-user@eksa-cluster:~$ kubectl  get pods test-pod -n test-ns-egressip -o yaml
apiVersion: v1
kind: Pod
metadata:
[...]
  labels:
    run: test-pod
ec2-user@eksa-cluster:~$ kubectl  get ns test-ns-egressip -o yaml
apiVersion: v1
kind: Namespace
metadata:
[...]
  labels:
    kubernetes.io/metadata.name: test-ns-egressip
```

Next define the  egress IP  10.131.2.15  in an external network -here 10.131.2.0/-. 

```
ec2-user@eksa-cluster:~$ kubectl get egressIP -o yaml
apiVersion: v1
items:
- apiVersion: k8s.ovn.org/v1
  kind: EgressIP
  spec:
    egressIPs:
    - 10.131.2.15
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: test-ns-egressip
    podSelector:
      matchLabels:
        run: test-pod
```

After applying the egressIP, we can verify which server has ownership by checking the status. In this case master2 has ownership.

```
ec2-user@eksa-cluster:~$ kubectl get EgressIP egressips-prod 
NAME             EGRESSIPS     ASSIGNED NODE   ASSIGNED EGRESSIPS
egressips-prod   10.131.2.15   master2         10.131.2.15

ec2-user@eksa-cluster:~$ kubectl get EgressIP egressips-prod -o yaml
apiVersion: k8s.ovn.org/v1
kind: EgressIP
metadata:
[...]
  egressIPs:
  - 10.131.2.15
  namespaceSelector:
    matchLabels:
      kubernetes.io/metadata.name: test-ns-egressip
  podSelector:
    matchLabels:
      run: test-pod
status:
  items:
  - egressIP: 10.131.2.15
    node: master2
```

```
# Generate external trafic from pod by ssh the local gateway 

ec2-user@eksa-cluster:~$ oc exec -ti -n test-ns-egressip test-pod -- ssh 10.131.2.1
root@10.131.2.1's password: 

ec2-user@eksa-cluster:~$ sudo tcpdump -vni  external 
tcpdump: listening on stc.external, link-type EN10MB (Ethernet), capture size 262144 bytes
17:39:15.661324 IP (tos 0x48, ttl 62, id 19403, offset 0, flags [DF], proto TCP (6), length 60)
    10.131.2.4.38242 > 10.131.2.1.22: Flags [S], cksum 0xb376 (correct), seq 3857734338, win 65280, options [mss 1360,sackOK,TS val 924479388 ecr 0,nop,wscale 7], length 0

``` 

But heck ? according to TCPDUMP the source IP is not the EgressIP (10.131.2..15) but instead it relies on the server IP on which the pod is running !!! 

So this does not work ?

Well actually, let's rather initiate traffic to an IP that is not local to the subnet (1.2.4.3 here).

```
ec2-user@eksa-cluster:~$ oc exec -ti -n test-ns-egressip test-pod -- ssh 1.2.3.4
The authenticity of host '1.2.3.4 (1.2.3.4)' can't be established.
ED25519 key fingerprint is SHA256:vnqkuF8LISjPOTCB2p/zrXiLE2KYad9BtpuaIxchEr0.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:1: 10.131.2.1
Are you sure you want to continue connecting (yes/no/[fingerprint])? ^Ccommand terminated with exit code 130

ec2-user@eksa-cluster:~$ sudo tcpdump -vni  external 
17:43:47.591945 IP (tos 0x48, ttl 61, id 38570, offset 0, flags [DF], proto TCP (6), length 60)
    10.131.2.15.54812 > 1.2.3.4.22: Flags [S], cksum 0xd8db (correct), seq 2909976524, win 65280, options [mss 1360,sackOK,TS val 1737342192 ecr 0,nop,wscale 7], length 0
```

That's better !!! but what happened ?  Simply, the master for egressIP is on a different server than the test pod (resp. master2 and master3). However, since the destination is on the local LAN, the server will directly send trafic to the LAN without tromboning via the EgressIP master. If the pod were  on the same server as the EgressIP, we would actually see SNAT enforced with EgressIP. 

This is not a big deal, but this behavior is worth to be aware of .

##  8. <a name='Ingressintegration'></a>Ingress integration

###  8.1. <a name='Background-1'></a>Background

Ingress permits to add L7 Load balancing on top of metallb. Note that this setup relies on k3S where traefik is already integrated.

###  8.2. <a name='Deployment'></a>Deployment 

The following manifest deployes a topology for testing an ingress controller exposing an external IP via metallb.
```console
kubectl apply -f https://raw.githubusercontent.com/robric/k8s-svc-and-lb-testing/refs/heads/main/source/nginx-dep-3-rep-2-apps.yaml
```
This results in the following elements
- Two applications app1 and app2 (nginx) with the associated service.
- An ingress routing to app1 based on the hostname.
- Metallb configuration: mlb is actually integrated in k3s so no need to define the service.
 
```
         vm1                   vm2                   vm3          
+-------------------+ +-------------------+ +-------------------+ 
|  +-------------+  | |  +-------------+  | |  +-------------+  | 
|  |  pod app1   |  | |  |  pod app1   |  | |  |  pod app1   |  | 
|  +------|------+  | |  +------|------+  | |  +------|------+  |
|       <------------------ svc app1 ------------------->       |
|                   | |                   | |                   | 
|                   | |                   | |                   |
|  +-------------+  | |  +-------------+  | |  +-------------+  | 
|  |  pod app2   |  | |  |  pod app2   |  | |  |  pod app2   |  | 
|  +------|------+  | |  +------|------+  | |  +------|------+  | 
|       <------------------ svc app2 ------------------->       |
|                   | |                   | |                   |  
|                   | |                   | |                   |  
|    +----------------------------------------------------+     |  
|    | ** INGRESS TRAEFIK                                 |     |
|    |             host app1.foo ---> SVC app1            |     | 
|    |             host app2.foo ---> SVC app2            |     | 
|    +----------------------------------------------------+     |
|                   | |                   | |                   | 
|                   | |                   | |                   | 
|                   | |                   | |                   | 
+---------|---------+ +----------|--------+ +---------|---------+ 
  ens3.100|.1            ens3.100|            ens3.100|           
          |                      |                    |           
          |                      |                    |           
     +----------------------------------------------------+       
     |             MLB     VIP 10.123.123.200             |       
     +----------------------------------------------------+       
          |                      |                    |           
          ---------------------------------------------           
                        vlan external network                     
                           10.123.123.0/24                        
                                 |                                
                                 |.4                              
          +-------------------------------------------------+
          |                                                 | 
          | curl -H "Host: app1.foo" http://10.123.123.200  |
          |                                                 | 
          | curl -H "Host: app2.foo" http://10.123.123.200  |
          |                                                 | 
          +-------------------------------------------------+
```
Traces deployment and svc:
```
ubuntu@vm1:~$ kubectl get svc -o wide -A
NAMESPACE        NAME                      TYPE           CLUSTER-IP      EXTERNAL-IP      PORT(S)                      AGE     SELECTOR
default          app1                      ClusterIP      10.43.146.218   <none>           80/TCP                       163m    app=app1
default          app2                      ClusterIP      10.43.202.115   <none>           80/TCP                       163m    app=app2
kube-system      traefik                   LoadBalancer   10.43.30.215    10.123.123.200   80:32723/TCP,443:31748/TCP   3h32m   app.kubernetes.io/instance=traefik-kube-system,app.kubernetes.io/name=traefik
[...]
ubuntu@vm1:~$ 
ubuntu@vm1:~$ kubectl  get pods -o wide
NAME                    READY   STATUS    RESTARTS   AGE    IP           NODE   NOMINATED NODE   READINESS GATES
app1-664b65cb7c-6qgvh   1/1     Running   0          161m   10.42.1.5    vm2    <none>           <none>
app1-664b65cb7c-6rfnf   1/1     Running   0          161m   10.42.3.4    vm3    <none>           <none>
app1-664b65cb7c-hf8b2   1/1     Running   0          161m   10.42.0.10   vm1    <none>           <none>
app2-79775d4cc6-6dnc4   1/1     Running   0          161m   10.42.0.11   vm1    <none>           <none>
app2-79775d4cc6-jzs85   1/1     Running   0          161m   10.42.3.5    vm3    <none>           <none>
app2-79775d4cc6-zwk42   1/1     Running   0          161m   10.42.1.6    vm2    <none>           <none>
ubuntu@vm1:~$ 
```

For conviency, the configuration of the controller is displayed here.

```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: traefik-ingress
spec:
  ingressClassName: traefik
  rules:
  - host: app1.foo
    http:
      paths:
      - backend:
          service:
            name: app1
            port:
              number: 80
        path: /
        pathType: Prefix
  - host: app2.foo
    http:
      paths:
      - backend:
          service:
            name: app2
            port:
              number: 80
        path: /
        pathType: Prefix
```
We can check the immediatly the integration with a Load Balancer (external address in use).
```
ubuntu@vm1:~$ kubectl get ingress
NAME              CLASS     HOSTS               ADDRESS          PORTS   AGE
traefik-ingress   traefik   app1.foo,app2.foo   10.123.123.200   80      135m
ubuntu@vm1:~$ 
ubuntu@vm1:~$ kubectl get ingress -o yaml 
[...]]  
   status:
    loadBalancer:
      ingress:
      - ip: 10.123.123.200
```
###  8.3. <a name='Testsandobservations'></a>Tests and observations

We can test with curl from the external vm (vm-ext).

```

ubuntu@vm-ext:~$ curl -H "Host: app1.foo" http://10.123.123.200
Welcome to NGINX!
Application:       app1
Pod Name:          app1-664b65cb7c-6rfnf
IP:                10.42.3.4
RequestPort:       8080
ubuntu@vm-ext:~$ curl -H "Host: app2.foo" http://10.123.123.200
Welcome to NGINX!
Application:       app2
Pod Name:          app2-79775d4cc6-6dnc4
IP:                10.42.0.11
RequestPort:       8080
ubuntu@vm-ext:~$ 

Or via DNS

root@vm-ext:~# echo "10.123.123.200 app1.foo" >> /etc/hosts
root@vm-ext:~# curl app1.foo
Welcome to NGINX!
Application:       app1
Pod Name:          app1-664b65cb7c-hf8b2
IP:                10.42.0.10
RequestPort:       8080
root@vm-ext:~# 
```

We can see the mutliple layers of NAT and address mapping (NB: L7 LB is not natting, but creating new sessions)

``` 

    [NEW] tcp      6 120 SYN_SENT src=10.123.123.4 dst=10.123.123.200 sport=49562 dport=80 [UNREPLIED] src=10.42.0.7 dst=10.42.0.1 sport=8000 dport=33229
    [NEW] tcp      6 120 SYN_SENT src=10.42.0.7 dst=10.42.3.5 sport=48846 dport=8080 [UNREPLIED] src=10.42.3.5 dst=10.42.0.7 sport=8080 dport=48846

Initial Request
S = 10.123.123.4     D = 10.123.123.200, dport 80 
NAT Metallb to Traefik proxy
S = 10.42.0.1        D = 10.42.0.7, dport 8000
Traefik proxy to pod
S = 10.42.0.7        D = 10.42.3.5, dport 8080
```

Yep trafic lands on traefik with port 8000 ! This is achieved with some string indirection "web" as target port. When metallb is configured with a string as targetport it gets the actual value from the destination container spec for ports.

```
ubuntu@vm1:~$ kubectl get svc -n kube-system traefik -o yaml
apiVersion: v1
kind: Service
metadata:
  annotations:
    metallb.io/ip-allocated-from-pool: external-pool
[...]]
spec:
[...]
  ports:
  - name: web
    nodePort: 32723
    port: 80
    protocol: TCP
    targetPort: web

ubuntu@vm1:~$ kubectl get deployments.apps -n kube-system traefik  -o yaml 
apiVersion: apps/v1
kind: Deployment
[...]
    spec:
[...]
      - args:
      [...]
        - --entryPoints.web.address=:8000/tcp
        ports:
[...]
        - containerPort: 8000
          name: web
          protocol: TCP

```

We can now create a second metallb ourself 'custom-mlb' to reach trafic via another external IP address (basically skipping the automated magic that k3s enforced).

```
ubuntu@vm1:~$ kubectl apply -f - <<EOF 
apiVersion: v1
kind: Service
metadata:
  name: traefik-custom-mlb
  namespace: kube-system
spec:
  loadBalancerIP: 10.123.123.210
  ports:
  - name: http
    port: 80
    protocol: TCP
    targetPort: 8000
  selector:
    app.kubernetes.io/name: traefik
  type: LoadBalancer
EOF
service/traefik-custom-mlb created
ubuntu@vm1:~$ kubectl get svc -A
NAMESPACE        NAME                      TYPE           CLUSTER-IP      EXTERNAL-IP      PORT(S)                      AGE
default          app1                      ClusterIP      10.43.146.218   <none>           80/TCP                       3h21m
default          app2                      ClusterIP      10.43.202.115   <none>           80/TCP                       3h21m
default          kubernetes                ClusterIP      10.43.0.1       <none>           443/TCP                      4h10m
kube-system      kube-dns                  ClusterIP      10.43.0.10      <none>           53/UDP,53/TCP,9153/TCP       4h10m
kube-system      metrics-server            ClusterIP      10.43.22.229    <none>           443/TCP                      4h10m
kube-system      traefik                   LoadBalancer   10.43.30.215    10.123.123.200   80:32723/TCP,443:31748/TCP   4h9m
kube-system      traefik-custom-mlb        LoadBalancer   10.43.226.176   10.123.123.210   80:32651/TCP                 9s
metallb-system   metallb-webhook-service   ClusterIP      10.43.163.86    <none>           443/TCP                      3h59m

##### and this just works all the same but we're in charge :-) 

ubuntu@vm1:~$ curl  10.123.123.210  -H "host: app1.foo"
Welcome to NGINX!
Application:       app1
Pod Name:          app1-664b65cb7c-hf8b2
IP:                10.42.0.10
RequestPort:       8080
ubuntu@vm1:~$ 

```

###  8.4. <a name='IngressRoutetraefik'></a>IngressRoute (traefik)

Now let's delete the ingress rule and use Traefik CRDs instead (ingressroute). Both resources have same objectives wrt L7 load balancing. However, Ingress is a generic kubernetes resource, hence it is more limited than traefik CRDs which allows more advanced control !


```
kubectl delete ingress traefik-ingress
kubectl apply -f https://raw.githubusercontent.com/robric/k8s-svc-and-lb-testing/refs/heads/main/source/ingressroute.yaml
```

For quick reference here is the config. We use endpoint to steer the requests for a change. 

```
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: path-based-ingressroute
  namespace: default
spec:
  entryPoints:
    - web
  routes:
  - match: PathPrefix(`/app1`)
    kind: Rule
    services:
    - name: app1
      port: 80
  - match: PathPrefix(`/app2`)
    kind: Rule
    services:
    - name: app2
      port: 80
```
and that just works.
```
ubuntu@vm-ext:~$ curl  http://10.123.123.200/app1
Welcome to NGINX!
Application:       app1
Pod Name:          app1-664b65cb7c-6rfnf
IP:                10.42.3.4
RequestPort:       8080
ubuntu@vm-ext:~$ curl  http://10.123.123.200/app2
Welcome to NGINX!
Application:       app2
Pod Name:          app2-79775d4cc6-jzs85
IP:                10.42.3.5
RequestPort:       8080
ubuntu@vm-ext:~$ 
```

##  9. <a name='Linkerd'></a>Linkerd 

###  9.1. <a name='Installation'></a>Installation

The mainstream installation was not working.

```
ubuntu@vm1:~$ curl --proto '=https' --tlsv1.2 -sSfL https://run.linkerd.io/install-edge | sh


^C
ubuntu@vm1:~$ curl https://run.linkerd.io/install-edge -vv
*   Trying 104.21.32.1:443...
*   Trying 2606:4700:3030::6815:6001:443...
* Immediate connect fail for 2606:4700:3030::6815:6001: Network is unreachable
*   Trying 2606:4700:3030::6815:4001:443...
* Immediate connect fail for 2606:4700:3030::6815:4001: Network is unreachable
```

So I used the BEL "https://www.buoyant.io/linkerd-enterprise" version (enterprise distribution).

```
curl --proto '=https' --tlsv1.2 -sSfL https://enterprise.buoyant.io/install | sh 
export PATH=/home/ubuntu/.linkerd2/bin:$PATH
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
```

After these steps, linkerd is installed.

```console
ubuntu@vm1:~$ linkerd version --client
Client version: enterprise-2.18.3
ubuntu@vm1:~$ linkerd check --pre
kubernetes-api
--------------
√ can initialize the client
√ can query the Kubernetes API

kubernetes-version
------------------
√ is running the minimum Kubernetes API version

pre-kubernetes-setup
--------------------
√ control plane namespace does not already exist
√ can create non-namespaced resources
√ can create ServiceAccounts
√ can create Services
√ can create Deployments
√ can create CronJobs
√ can create ConfigMaps
√ can create Secrets
√ can read Secrets
√ can read extension-apiserver-authentication configmap
√ no clock skew detected

linkerd-version
---------------
√ can determine the latest version
√ cli is up-to-date

Status check results are √
ubuntu@vm1:~$ 
```
Ah you need a licence...
```
ubuntu@vm1:~$ linkerd install | kubectl apply -f -
Error: BUOYANT_LICENSE env var, license, or licenseSecret must be set
Usage:
  linkerd install [flags]

Examples:
  # Install CRDs first.
  linkerd install --crds | kubectl apply -f -

  # Install the core control plane.

``` 
Indeed this is the enterprise version, but you can get a free licence on the ![buoyant website]({E11725E9-9406-4A87-B9C5-4F89CAF6761B}.png), which is good for tests since it is valid for up to 100 pods. You need to create a workspace first - that's very quick -.
Now let's roll as per doc says (we just toggled linkerd installGatewayAPI=true to false)

```
export BUOYANT_LICENSE=eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJCdW95YW50IEluYyIsInN1YiI6ImxpY2Vuc2UiLCJhdWQiOiJ0b3RvIiwiZXhwIjo0MTAyNDQ0ODAwLCJDbGllbnRJRCI6InBWYUhzdVdiSms3WEk5cnQiLCJDbGllbnRTZWNyZXQiOiI5YjEzZjg4YWI2YTZlODA0MzE4YWJjODY2MjQ0YWNjOTdhZDljYjMxNTEzZWYwOTUwMTMzYzcyZjBkNWNmNmNhIiwiUHJvZHVjdCI6IkJFTCIsIlZlcnNpb24iOjIsIk1hbmFnZWRDb250cm9sUGxhbmVFbmFibGVkIjp0cnVlLCJNYW5hZ2VkRGF0YVBsYW5lRW5hYmxlZCI6dHJ1ZSwiRW50ZXJwcmlzZUVuYWJsZWQiOnRydWUsIkhBWkxFbmFibGVkIjpmYWxzZSwiRklQU0VuYWJsZWQiOmZhbHNlLCJQYXRjaFJlbGVhc2VzRW5hYmxlZCI6ZmFsc2V9.K-2XOKq7qlfe1IX1-6ZDvI5NNkJINJqxDaQzneziqmJvNCmDdp4uWaRAg3OJ2ncEqO_t4n6rtgmfOlX90W6fgA
linkerd install --crds --set installGatewayAPI=true | kubectl apply -f -
linkerd install | kubectl apply -f -
```
ok it almost worked. It looks like K3s installed some gateway extensions.
```
ubuntu@vm1:~$ linkerd install --crds --set installGatewayAPI=true | kubectl apply -f -
Linkerd cannot install the Gateway API CRDs because they are already installed by an external source. Please set `installGatewayAPI` to `false`.
error: no objects passed to apply
ubuntu@vm1:~$ linkerd install --crds --set installGatewayAPI=false | kubectl apply -f -
Rendering Linkerd CRDs...
Next, run `linkerd install | kubectl apply -f -` to install the control plane.

customresourcedefinition.apiextensions.k8s.io/authorizationpolicies.policy.linkerd.io created
customresourcedefinition.apiextensions.k8s.io/egressnetworks.policy.linkerd.io created
customresourcedefinition.apiextensions.k8s.io/httplocalratelimitpolicies.policy.linkerd.io created
customresourcedefinition.apiextensions.k8s.io/httproutes.policy.linkerd.io created
customresourcedefinition.apiextensions.k8s.io/meshtlsauthentications.policy.linkerd.io created
customresourcedefinition.apiextensions.k8s.io/networkauthentications.policy.linkerd.io created
customresourcedefinition.apiextensions.k8s.io/serverauthorizations.policy.linkerd.io created
customresourcedefinition.apiextensions.k8s.io/servers.policy.linkerd.io created
customresourcedefinition.apiextensions.k8s.io/serviceprofiles.linkerd.io created
customresourcedefinition.apiextensions.k8s.io/externalworkloads.workload.linkerd.io created
ubuntu@vm1:~$ 
ubuntu@vm1:~$ linkerd install | kubectl apply -f -
namespace/linkerd created
clusterrole.rbac.authorization.k8s.io/linkerd-linkerd-identity created
clusterrolebinding.rbac.authorization.k8s.io/linkerd-linkerd-identity created
serviceaccount/linkerd-identity created
clusterrole.rbac.authorization.k8s.io/linkerd-linkerd-destination created
clusterrolebinding.rbac.authorization.k8s.io/linkerd-linkerd-destination created
serviceaccount/linkerd-destination created
secret/linkerd-sp-validator-k8s-tls created
validatingwebhookconfiguration.admissionregistration.k8s.io/linkerd-sp-validator-webhook-config created
secret/linkerd-policy-validator-k8s-tls created
validatingwebhookconfiguration.admissionregistration.k8s.io/linkerd-policy-validator-webhook-config created
clusterrole.rbac.authorization.k8s.io/linkerd-policy created
clusterrolebinding.rbac.authorization.k8s.io/linkerd-destination-policy created
role.rbac.authorization.k8s.io/remote-discovery created
rolebinding.rbac.authorization.k8s.io/linkerd-destination-remote-discovery created
role.rbac.authorization.k8s.io/linkerd-heartbeat created
rolebinding.rbac.authorization.k8s.io/linkerd-heartbeat created
clusterrole.rbac.authorization.k8s.io/linkerd-heartbeat created
clusterrolebinding.rbac.authorization.k8s.io/linkerd-heartbeat created
serviceaccount/linkerd-heartbeat created
clusterrole.rbac.authorization.k8s.io/linkerd-linkerd-proxy-injector created
clusterrolebinding.rbac.authorization.k8s.io/linkerd-linkerd-proxy-injector created
serviceaccount/linkerd-proxy-injector created
secret/linkerd-proxy-injector-k8s-tls created
mutatingwebhookconfiguration.admissionregistration.k8s.io/linkerd-proxy-injector-webhook-config created
configmap/linkerd-config created
secret/buoyant-license created
clusterrole.rbac.authorization.k8s.io/linkerd-linkerd-enterprise created
clusterrolebinding.rbac.authorization.k8s.io/linkerd-linkerd-enterprise created
role.rbac.authorization.k8s.io/linkerd-enterprise created
rolebinding.rbac.authorization.k8s.io/linkerd-enterprise created
serviceaccount/linkerd-enterprise created
service/linkerd-enterprise created
deployment.apps/linkerd-enterprise created
role.rbac.authorization.k8s.io/ext-namespace-metadata-linkerd-config created
secret/linkerd-identity-issuer created
configmap/linkerd-identity-trust-roots created
service/linkerd-identity created
service/linkerd-identity-headless created
deployment.apps/linkerd-identity created
service/linkerd-dst created
service/linkerd-dst-headless created
service/linkerd-sp-validator created
service/linkerd-policy created
service/linkerd-policy-validator created
Warning: spec.template.spec.containers[2].ports[1]: duplicate port name "admin-http" with spec.template.spec.containers[1].ports[1], services and probes that select ports by name will use spec.template.spec.containers[1].ports[1]
Warning: spec.template.spec.containers[3].ports[0]: duplicate port name "grpc" with spec.template.spec.containers[1].ports[0], services and probes that select ports by name will use spec.template.spec.containers[1].ports[0]
Warning: spec.template.spec.containers[3].ports[1]: duplicate port name "admin-http" with spec.template.spec.containers[1].ports[1], services and probes that select ports by name will use spec.template.spec.containers[1].ports[1]
deployment.apps/linkerd-destination created
cronjob.batch/linkerd-heartbeat created
deployment.apps/linkerd-proxy-injector created
service/linkerd-proxy-injector created
secret/linkerd-config-overrides created
ubuntu@vm1:~$ 

ubuntu@vm1:~$ kubectl api-resources | grep linker
serviceprofiles                     sp                         linkerd.io/v1alpha2                 true         ServiceProfile
authorizationpolicies               authzpolicy                policy.linkerd.io/v1alpha1          true         AuthorizationPolicy
egressnetworks                                                 policy.linkerd.io/v1alpha1          true         EgressNetwork
httplocalratelimitpolicies                                     policy.linkerd.io/v1alpha1          true         HTTPLocalRateLimitPolicy
httproutes                                                     policy.linkerd.io/v1beta3           true         HTTPRoute
meshtlsauthentications              meshtlsauthn               policy.linkerd.io/v1alpha1          true         MeshTLSAuthentication
networkauthentications              netauthn,networkauthn      policy.linkerd.io/v1alpha1          true         NetworkAuthentication
serverauthorizations                saz,serverauthz,srvauthz   policy.linkerd.io/v1beta1           true         ServerAuthorization
servers                             srv                        policy.linkerd.io/v1beta3           true         Server
externalworkloads                                              workload.linkerd.io/v1beta1         true         ExternalWorkload
ubuntu@vm1:~$ 

ubuntu@vm1:~$ kubectl get svc -A
NAMESPACE        NAME                        TYPE           CLUSTER-IP      EXTERNAL-IP      PORT(S)                      AGE
default          app1                        ClusterIP      10.43.146.218   <none>           80/TCP                       3d4h
default          app2                        ClusterIP      10.43.202.115   <none>           80/TCP                       3d4h
default          kubernetes                  ClusterIP      10.43.0.1       <none>           443/TCP                      3d5h
kube-system      kube-dns                    ClusterIP      10.43.0.10      <none>           53/UDP,53/TCP,9153/TCP       3d5h
kube-system      metrics-server              ClusterIP      10.43.22.229    <none>           443/TCP                      3d5h
kube-system      traefik                     LoadBalancer   10.43.30.215    10.123.123.200   80:32723/TCP,443:31748/TCP   3d5h
kube-system      traefik-custom-mlb          LoadBalancer   10.43.226.176   10.123.123.210   80:32651/TCP                 3d
linkerd          linkerd-dst                 ClusterIP      10.43.172.162   <none>           8086/TCP                     19s
linkerd          linkerd-dst-headless        ClusterIP      None            <none>           8086/TCP                     19s
linkerd          linkerd-enterprise          ClusterIP      10.43.246.42    <none>           8082/TCP                     19s
linkerd          linkerd-identity            ClusterIP      10.43.58.90     <none>           8080/TCP                     19s
linkerd          linkerd-identity-headless   ClusterIP      None            <none>           8080/TCP                     19s
linkerd          linkerd-policy              ClusterIP      None            <none>           8090/TCP                     19s
linkerd          linkerd-policy-validator    ClusterIP      10.43.101.247   <none>           443/TCP                      19s
linkerd          linkerd-proxy-injector      ClusterIP      10.43.185.217   <none>           443/TCP                      19s
linkerd          linkerd-sp-validator        ClusterIP      10.43.149.191   <none>           443/TCP                      19s
metallb-system   metallb-webhook-service     ClusterIP      10.43.163.86    <none>           443/TCP                      3d4h
ubuntu@vm1:~$ 

ubuntu@vm1:~$ kubectl get pods -A | grep link
linkerd          linkerd-destination-56b9d96b97-fl8zc      4/4     Running     0          46m
linkerd          linkerd-enterprise-c7d84ccb4-db8sh        2/2     Running     0          46m
linkerd          linkerd-identity-875f6d59d-bnsr4          2/2     Running     0          46m
linkerd          linkerd-proxy-injector-5f8ccd494f-9nvkg   2/2     Running     0          46m
ubuntu@vm1:~$ 
```
### Linkerd prox injection for app1 and app2

After installation, we can start with proxy injection for app1 and app2.
This is controlled by annotating the pods - i.e. deployment template - with: "linkerd.io/inject": "enabled"

```
kubectl patch deployment app1 \
  -p '{"spec": {"template": {"metadata": {"annotations": {"linkerd.io/inject": "enabled"}}}}}'
deployment.apps/app1 patched
kubectl patch deployment app2   -p '{"spec": {"template": {"metadata": {"annotations": {"linkerd.io/inject": "enabled"}}}}}'
deployment.apps/app2 patched
```
This kicks in the "linkerd-proxy-injector" and results in having 2/2 containers running in app1 and app2 (nginx and the linkerd proxy).

```
ubuntu@vm1:~$ kubectl get pods
NAME                    READY   STATUS    RESTARTS   AGE
app1-7d54584bb9-cbhz2   2/2     Running   0          25s
app1-7d54584bb9-vw4jx   2/2     Running   0          14s
app1-7d54584bb9-xbq7j   2/2     Running   0          10s
app2-dd559b7bf-2htpv    2/2     Running   0          16s
app2-dd559b7bf-mmh6x    2/2     Running   0          11s
app2-dd559b7bf-tkwp4    2/2     Running   0          7s
ubuntu@vm1:~$ 

ubuntu@vm1:~$ kubectl describe pods app1-7d54584bb9-cbhz2 | grep -C1 "    Container ID: "
  render-nginx-config:
    Container ID:  containerd://6b78a97a2952cc838ad6018ca94f8c547c16dfe8c8b1e12bff77af00ce27346f
    Image:         busybox:latest
--
  linkerd-init:
    Container ID:    containerd://b7c023059a59f98d6ea0fab54be3473d1052287bad553f16da5f4ab607abceda
    Image:           ghcr.io/buoyantio/proxy-init:enterprise-2.18.3
--
  linkerd-proxy:
    Container ID:    containerd://bedf02d7093a6dda19215a6b1eb946cb04200d899084db6638df9fc5b7b1c315
    Image:           ghcr.io/buoyantio/proxy:enterprise-2.18.3
--
  nginx:
    Container ID:   containerd://e1a03adf869865188a294ab82d56eb43d5e64196d17679787c36b56f1d171bed
    Image:          nginx:latest
ubuntu@vm1:~$ 

/// 
  The proxy has two ports opened 4143 and 4191  
/// 

Containers:
  linkerd-proxy:
    Container ID:    containerd://bedf02d7093a6dda19215a6b1eb946cb04200d899084db6638df9fc5b7b1c315
    Image:           ghcr.io/buoyantio/proxy:enterprise-2.18.3
    Image ID:        ghcr.io/buoyantio/proxy@sha256:b6a90148f46f73f63f52fe55a3ebe0be410fecf12e041ea1d4fa34b8a72a3748
    Ports:           4143/TCP, 4191/TCP

The ports have the following functions:
- Data Plane: 4143/TCP → Inbound traffic port. The proxy listens on this port to intercept incoming traffic to the pod (from other Linkerd-injected pods).
- Control Plane: 4191/TCP → Admin + Prometheus metrics port 

/// 
```

### Tests

Trafic generation for E/W is generated from a pod in app1 (app1-7d54584bb9-cbhz2) to the app2 service via curl.

```
Diagram:

-----------------------------              
| pod app1-7d54584bb9-cbhz2 |              
|                           |              
| > curl app2               |              -----------------------------
|                           |              |         pod app2-x        |
|                           |              |                           |
-----------| eth0 |----------              -----------| eth0 |----------
               |                                          |                                        
               |---------(kernel network ns)------->  [svc app2]


Commands and Output:

ubuntu@vm1:~$ kubectl get pods app1-7d54584bb9-cbhz2 -o wide 
NAME                    READY   STATUS    RESTARTS   AGE   IP           NODE   NOMINATED NODE   READINESS GATES
app1-7d54584bb9-cbhz2   2/2     Running   0          35m   10.42.0.18   vm1    <none>           <none>
ubuntu@vm1:~$ kubectl exec -it app1-7d54584bb9-cbhz2 -c nginx -- curl app2
Welcome to NGINX!
Application:       app2
Pod Name:          app2-dd559b7bf-mmh6x
IP:                10.42.0.19
RequestPort:       8080
ubuntu@vm1:~$ 
ubuntu@vm1:~$ kubectl exec -it app1-7d54584bb9-cbhz2 -c nginx -- curl app2
Welcome to NGINX!
Application:       app2
Pod Name:          app2-dd559b7bf-2htpv
IP:                10.42.1.14
RequestPort:       8080
ubuntu@vm1:~$ 
```

So now let's find the veth  and tcpdump on it to see what is happening. No trafic is generated for now, to inspect the control plane.

```
ubuntu@vm1:~$ kubectl get pods -A -o wide |grep app1 
default          app1-7d54584bb9-cbhz2                     2/2     Running     0          80m     10.42.0.18     vm1    <none>           <none>
[...]
]ubuntu@vm1:~$ arp -na |grep 18
? (10.42.0.18) at 4a:47:c5:63:14:09 [ether] on cni0
ubuntu@vm1:~$ bridge fdb | grep  4a:47:c5:63:14:09
4a:47:c5:63:14:09 dev veth29d142c8 master cni0 
ubuntu@vm1:~$       

ubuntu@vm1:~$ sudo tcpdump -vni veth29d142c8
tcpdump: listening on veth29d142c8, link-type EN10MB (Ethernet), snapshot length 262144 bytes

///  The selected app1 pod reaches out the DNS service (10.43.0.10) to resolve "linkerd-dst-headless" and "linkerd-policy" services.
    Both services are actually headless so the resolution directly points to the (same) pod IP address.
    ubuntu@vm1:~$ kubectl get pods -A -o wide | grep 3.7
linkerd          linkerd-destination-56b9d96b97-fl8zc      4/4     Running     0          21h     10.42.3.7      vm3    

///

06:17:17.489484 IP (tos 0x0, ttl 64, id 16938, offset 0, flags [DF], proto UDP (17), length 92)
    10.42.0.18.47486 > 10.43.0.10.53: 8222+ SRV? linkerd-dst-headless.linkerd.svc.cluster.local. (64)
06:17:17.489547 IP (tos 0x0, ttl 64, id 16939, offset 0, flags [DF], proto UDP (17), length 86)
    10.42.0.18.21544 > 10.43.0.10.53: 42891+ SRV? linkerd-policy.linkerd.svc.cluster.local. (58)
06:17:17.489810 IP (tos 0x0, ttl 64, id 47882, offset 0, flags [DF], proto UDP (17), length 262)
    10.43.0.10.53 > 10.42.0.18.21544: 42891*- 1/0/1 linkerd-policy.linkerd.svc.cluster.local. SRV 10-42-3-7.linkerd-policy.linkerd.svc.cluster.local.:8090 0 100 (234)
06:17:17.489873 IP (tos 0x0, ttl 64, id 47883, offset 0, flags [DF], proto UDP (17), length 286)
    10.43.0.10.53 > 10.42.0.18.47486: 8222*- 1/0/1 linkerd-dst-headless.linkerd.svc.cluster.local. SRV 10-42-3-7.linkerd-dst-headless.linkerd.svc.cluster.local.:8086 0 100 (258)

///

There is a TCP session established to the linkerd-destination-56b9d96b97-fl8zc pod on port 8086/8090. This looks permanent.

///

ubuntu@vm1:~$ sudo tcpdump  -vni veth29d142c8 'tcp and not port 4191'
tcpdump: listening on veth29d142c8, link-type EN10MB (Ethernet), snapshot length 262144 bytes
07:32:26.227722 IP (tos 0x0, ttl 62, id 8520, offset 0, flags [DF], proto TCP (6), length 91)
    10.42.3.7.8086 > 10.42.0.18.35202: Flags [P.], cksum 0xdc4d (correct), seq 2448394407:2448394446, ack 597336651, win 501, options [nop,nop,TS val 2540664348 ecr 1812338180], length 39
07:32:26.227823 IP (tos 0x0, ttl 64, id 52532, offset 0, flags [DF], proto TCP (6), length 91)
    10.42.0.18.35202 > 10.42.3.7.8086: Flags [P.], cksum 0x17ba (incorrect -> 0x84c0), seq 1:40, ack 39, win 502, options [nop,nop,TS val 1812348182 ecr 2540664348], length 39
07:32:26.227997 IP (tos 0x0, ttl 62, id 8521, offset 0, flags [DF], proto TCP (6), length 52)
    10.42.3.7.8086 > 10.42.0.18.35202: Flags [.], cksum 0x1cd0 (correct), ack 40, win 501, options [nop,nop,TS val 2540664348 ecr 1812348182], length 0
07:32:26.507623 IP (tos 0x0, ttl 62, id 48808, offset 0, flags [DF], proto TCP (6), length 91)
    10.42.3.7.8090 > 10.42.0.18.35304: Flags [P.], cksum 0x01d0 (correct), seq 326528615:326528654, ack 3915415721, win 669, options [nop,nop,TS val 2540664628 ecr 1812338460], length 39
07:32:26.507703 IP (tos 0x0, ttl 64, id 62824, offset 0, flags [DF], proto TCP (6), length 91)

///

Then kubelet is polling the pod 4191 via kube-proxy for liveness detection.

ubuntu@vm1:~$ kubectl get pod app1-7d54584bb9-cbhz2 -o yaml | grep -A5 "livenessProbe"
    livenessProbe:
      failureThreshold: 3
      httpGet:
        path: /live
        port: 4191
        scheme: HTTP
ubuntu@vm1:~$ 

Payload inspection in tcpdump shows the probe.
*..
*....._LT@{...............
.Ds.....GET /ready HTTP/1.1
Host: 10.42.0.18:4191
User-Agent: kube-probe/1.33
Accept: */*
Connection: close

/// 
06:17:20.206932 IP (tos 0x0, ttl 64, id 16531, offset 0, flags [DF], proto TCP (6), length 60)
    10.42.0.1.44884 > 10.42.0.18.4191: Flags [S], cksum 0x1495 (incorrect -> 0x2e2f), seq 3515128348, win 64860, options [mss 1410,sackOK,TS val 117626344 ecr 0,nop,wscale 7], length 0
06:17:20.206967 IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 60)
    10.42.0.18.4191 > 10.42.0.1.44884: Flags [S.], cksum 0x1495 (incorrect -> 0xd2a1), seq 590629406, ack 3515128349, win 64308, options [mss 1410,sackOK,TS val 3195154911 ecr 117626344,nop,wscale 7], length 0
06:17:20.206980 IP (tos 0x0, ttl 64, id 16532, offset 0, flags [DF], proto TCP (6), length 52)
    10.42.0.1.44884 > 10.42.0.18.4191: Flags [.], cksum 0x148d (incorrect -> 0xfa75), ack 1, win 507, options [nop,nop,TS val 117626344 ecr 3195154911], length 0
[...]
06:17:20.289468 IP (tos 0x0, ttl 64, id 21061, offset 0, flags [DF], proto TCP (6), length 52)
    10.42.0.18.4191 > 10.42.0.1.44886: Flags [F.], cksum 0x148d (incorrect -> 0xe93b), seq 127, ack 109, win 502, options [nop,nop,TS val 3195154993 ecr 117626426], length 0

```

So now let's have a look at the data plane. We can see trafic established on port 4143 (data plane port).
The trafic is encrypted (although the curl request is in clear http). This simple native capability is a great driver for  the deployment linkerd (you may want a single control plane for the E/W encryption among services).

```
ubuntu@vm1:~$ sudo tcpdump  -vni veth29d142c8 'tcp and not port 4191 and not port 8090 and not port 8086'
tcpdump: listening on veth29d142c8, link-type EN10MB (Ethernet), snapshot length 262144 bytes
07:36:14.227680 IP (tos 0x0, ttl 64, id 20101, offset 0, flags [DF], proto TCP (6), length 60)
    10.42.0.18.60224 > 10.42.0.19.4143: Flags [S], cksum 0x14a7 (incorrect -> 0x6b55), seq 2345613851, win 64860, options [mss 1410,sackOK,TS val 1857395447 ecr 0,nop,wscale 7], length 0
07:36:14.227721 IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 60)
    10.42.0.19.4143 > 10.42.0.18.60224: Flags [S.], cksum 0x14a7 (incorrect -> 0xab47), seq 3079886454, ack 2345613852, win 64308, options [mss 1410,sackOK,TS val 872644631 ecr 1857395447,nop,wscale 7], length 0
07:36:14.227729 IP (tos 0x0, ttl 64, id 20102, offset 0, flags [DF], proto TCP (6), length 52)
    10.42.0.18.60224 > 10.42.0.19.4143: Flags [.], cksum 0x149f (incorrect -> 0xd31b), ack 1, win 507, options [nop,nop,TS val 1857395447 ecr 872644631], length 0
[...]
```

So now, let's investigate how the magic operates within the pod... because by default trafic would just take the default route via eth0 after leaving our nging container.

```

#1 There is DNS request at first with service address for app2 so trafic can be sent to svc.

DNS resolution to app2 svc (app2 ClusterIP   = 10.43.202.115)

ubuntu@vm1:~$ sudo ip netns exec cni-3c8ab1bb-dd29-06bd-3242-83a12ce53680 bash
root@vm1:/home/ubuntu# tcpdump -vni eth0

    10.42.0.18.58179 > 10.43.0.10.53: 39505+ A? app2.default.svc.cluster.local. (48)
    10.43.0.10.53 > 10.42.0.18.58179: 39505*- 1/0/0 app2.default.svc.cluster.local. A 10.43.202.115 (94)

#2 Trafic sent to SVC is redirected to local host port 4140 managed owned by linkerd

# 2.1 The  initial curl request (10.42.0.18 ) to app2 svc (10.43.202.115) is redirected to local host port 4140.

Trace in the network namespace of app1 pod (pid 290248 is the linkerd proxy for the app1 pod used for tests).

ubuntu@vm1:~$ sudo nsenter -t 290248 -n
root@vm1:/home/ubuntu# conntrack -E

 [NEW] tcp      6 120 SYN_SENT src=10.42.0.18 dst=10.43.202.115 sport=47350 dport=8080 [UNREPLIED] src=127.0.0.1 dst=10.42.0.18 sport=4140 dport=47350
 
 [UPDATE] tcp      6 60 SYN_RECV src=10.42.0.18 dst=10.43.202.115 sport=47350 dport=8080 src=127.0.0.1 dst=10.42.0.18 sport=4140 dport=47350

 [UPDATE] tcp      6 432000 ESTABLISHED src=10.42.0.18 dst=10.43.202.115 sport=47350 dport=8080 src=127.0.0.1 dst=10.42.0.18 sport=4140 dport=47350 [ASSURED]

The rule is visible in iptables 

root@vm1:/home/ubuntu# iptables-legacy -t nat -L -v

[...] Jump to PROXY_INIT_OUTPUT 

Chain OUTPUT (policy ACCEPT 8878 packets, 787K bytes)
 pkts bytes target     prot opt in     out     source               destination         
 8908  789K PROXY_INIT_OUTPUT  all  --  any    any     anywhere             anywhere             /* proxy-init/install-proxy-init-output */

[...] Redirect every tcp trafic to port 4140 except UID 2102 + dports 4567 and 4568

Chain PROXY_INIT_OUTPUT (1 references)
 pkts bytes target     prot opt in     out     source               destination         
 8844  785K RETURN     all  --  any    any     anywhere             anywhere             owner UID match 2102 /* proxy-init/ignore-proxy-user-id */
    4   240 RETURN     all  --  any    lo      anywhere             anywhere             /* proxy-init/ignore-loopback */
    0     0 RETURN     tcp  --  any    any     anywhere             anywhere             multiport dports 4567,4568 /* proxy-init/ignore-port-4567,4568 */
   30  1800 REDIRECT   tcp  --  any    any     anywhere             anywhere             /* proxy-init/redirect-all-outgoing-to-proxy-port */ redir ports 4140

#2.2 The Linkerd proxy initiates new sessions to ALL app2 pods

 [UPDATE] tcp      6 432000 ESTABLISHED src=10.42.0.18 dst=10.42.3.14 sport=52280 dport=4143 src=10.42.3.14 dst=10.42.0.18 sport=4143 dport=52280 [ASSURED]
 [UPDATE] tcp      6 432000 ESTABLISHED src=10.42.0.18 dst=10.42.0.19 sport=45052 dport=4143 src=10.42.0.19 dst=10.42.0.18 sport=4143 dport=45052 [ASSURED]
 [UPDATE] tcp      6 432000 ESTABLISHED src=10.42.0.18 dst=10.42.1.14 sport=43624 dport=4143 src=10.42.1.14 dst=10.42.0.18 sport=4143 dport=43624 [ASSURED]

For the record here is some strace activity of the linkerd proxy

ubuntu@vm1:~$ sudo strace -p 290248 -e trace=network

[...]
recvfrom(16, "GET / HTTP/1.1\r\nHost: app2:8080\r"..., 1024, 0, NULL, NULL) = 73
getpeername(16, {sa_family=AF_INET, sin_port=htons(47350), sin_addr=inet_addr("10.42.0.18")}, [128 => 16]) = 0
recvfrom(18, "\27\3\3\4fk2(\273tT\317q\351\364\244\265\230\227\t\305\210\250\6V\275+\361D\270\332\370"..., 4096, 0, NULL, NULL) = 1131
socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_IP) = 19
connect(19, {sa_family=AF_INET, sin_port=htons(4143), sin_addr=inet_addr("10.42.3.14")}, 16) = -1 EINPROGRESS (Operation now in progress)
socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_IP) = 20
connect(20, {sa_family=AF_INET, sin_port=htons(4143), sin_addr=inet_addr("10.42.0.19")}, 16) = -1 EINPROGRESS (Operation now in progress)
socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_IP) = 21
connect(21, {sa_family=AF_INET, sin_port=htons(4143), sin_addr=inet_addr("10.42.1.14")}, 16) = -1 EINPROGRESS (Operation now in progress)

We can see that packet is received from fd 16 with target port 8080.
Next we see the sockets created to port 4143 with target pod addresses. 

```




##  10. <a name='MetallbTroubleshootingtips'></a>Metallb Troubleshooting tips

###  10.1. <a name='Presentation'></a>Presentation

There is a set of pods  main pods for metallb:
 - controller (deployment): centralized control plane for metallb
 - speaker (daemonset): a pod runs on each node. It is notably responsible for responding to ARP in L2 when elected as Master for a VIP. 
 - frr: optional when you want to use frr (BGP). 
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

###  10.2. <a name='Changeloglevel'></a>Change log level

You can change log verbosity in controller to debug:
```
# Edit the deployment for controller and set args log to debug:

ubuntu@vm1:~$ kubectl edit deployments.apps -n metallb-system controller 

kind: Deployment
metadata:
[...]
    spec:
      containers:
      - args:
        - --port=7472
        - --log-level=debug

# Edit the daemonset for speakers and set args log to debug:

ubuntu@vm1:~$ kubectl  edit daemonsets.apps -n metallb-system speaker 

apiVersion: apps/v1
kind: DaemonSet
[...]
    spec:
      containers:
      - args:
        - --port=7472
        - --log-level=debug
        env:
```

###  10.3. <a name='TraceVIPownership'></a>Trace VIP ownership

Check which worker is responsible for the VIP.

You can check the log (info good enough) of speakers. The server that is responsible for a VIP has a a specific "serviceAnnounced" event.  

```console
ubuntu@vm1:~$ kubectl logs -n metallb-system speaker-89b29 | grep serviceAnnounced
{"caller":"main.go:409","event":"serviceAnnounced","ips":["10.123.123.100"],"level":"info","msg":"service has IP, announcing","pool":"external-pool","protocol":"layer2","ts":"2025-02-05T10:14:46Z"}```
ubuntu@vm1:~$ kubectl logs -n metallb-system speaker-5dbng | grep serviceAnnounced
{"caller":"main.go:409","event":"serviceAnnounced","ips":["1.2.3.4"],"level":"info","msg":"service has IP, announcing","pool":"sctp-external-pool","protocol":"layer2","ts":"2025-02-01T18:04:08Z"}
```

###  10.4. <a name='ARPresponderfunction'></a>ARP responder function

All speaker have ARP responder function activated. However, only the VIP master (cf previous section) will respond to ARP requests. 

```
ubuntu@vm1:~$ kubectl logs -n metallb-system speaker-89b29 |grep ARP
{"caller":"announcer.go:126","event":"createARPResponder","interface":"ens3","level":"info","msg":"created ARP responder for interface","ts":"2025-02-01T18:04:05Z"}
{"caller":"announcer.go:126","event":"createARPResponder","interface":"ens3.100","level":"info","msg":"created ARP responder for interface","ts":"2025-02-01T18:04:05Z"}

ubuntu@vm1:~$ kubectl logs -n metallb-system speaker-5dbng  |grep ARP
{"caller":"announcer.go:126","event":"createARPResponder","interface":"ens3","level":"info","msg":"created ARP responder for interface","ts":"2025-02-01T18:04:07Z"}
{"caller":"announcer.go:126","event":"createARPResponder","interface":"ens3.100","level":"info","msg":"created ARP responder for interface","ts":"2025-02-01T18:04:07Z"}

ubuntu@vm1:~$ kubectl logs -n metallb-system speaker-96jn5 |grep ARP
{"caller":"announcer.go:126","event":"createARPResponder","interface":"ens3","level":"info","msg":"created ARP responder for interface","ts":"2025-02-01T18:04:01Z"}
{"caller":"announcer.go:126","event":"createARPResponder","interface":"ens3.100","level":"info","msg":"created ARP responder for interface","ts":"2025-02-01T18:04:01Z"}
```

With severity log "debug", we can trace every ARP request and have information on its content.
Below is a capture on a speaker that owns the VIP in case of ARP request to the VIP. Here 10.123.123.4 is the requester.

```
ubuntu@vm1:~$ kubectl  logs -n metallb-system speaker-4xqf5  -f 
{"caller":"net.go:962","component":"Memberlist","level":"debug","msg":"memberlist: Initiating push/pull sync with: vm3 10.65.94.59:7946","ts":"2025-02-05T12:10:00Z"}
{"caller":"arp.go:110","interface":"ens3","ip":"10.123.123.100","level":"debug","msg":"got ARP request for service IP, sending response","responseMAC":"52:54:00:b2:5b:52","senderIP":"10.123.123.4","senderMAC":"52:54:00:41:4c:72","ts":"2025-02-05T12:10:03Z"}
{"caller":"arp.go:110","interface":"ens3.100","ip":"10.123.123.100","level":"debug","msg":"got ARP request for service IP, sending response","responseMAC":"52:54:00:b2:5b:52","senderIP":"10.123.123.4","senderMAC":"52:54:00:41:4c:72","ts":"2025-02-05T12:10:03Z"}
[...]
```

This trace mapsto the TCPDUMP capture for ARP on the master (vm2 here with MAC 52:54:00:41:4c:72):

```
ubuntu@vm2:~$ sudo tcpdump -evni ens3.100 "arp"
tcpdump: listening on ens3.100, link-type EN10MB (Ethernet), snapshot length 262144 bytes

04:16:58.115088 52:54:00:41:4c:72 > ff:ff:ff:ff:ff:ff, ethertype ARP (0x0806), length 42: Ethernet (len 6), IPv4 (len 4), Request who-has 10.123.123.100 tell 10.123.123.4, length 28
04:16:58.115241 52:54:00:b2:5b:52 > 52:54:00:41:4c:72, ethertype ARP (0x0806), length 60: Ethernet (len 6), IPv4 (len 4), Reply 10.123.123.100 is-at 52:54:00:b2:5b:52, length 46
```

###  10.5. <a name='Whathappensincaseoffailure'></a>What happens in case of failure ?

####  10.5.1. <a name='PODRUNNINGbuthasnoREADYcontainer'></a>POD RUNNING but has no READY container

The intent of this test is to verify whether Metallb checks for pod readyness (READY state in pod) to advertise the VIP and respond to ARP request (L2 mode). 

The following manifest creates a pod that fails with service IP 10.123.123.99.

```
kubectl apply -f https://raw.githubusercontent.com/robric/k8s-svc-and-lb-testing/refs/heads/main/source/test-NOT-READY-pod.yaml
```

Quick output check: we have our pod with status running but the service is not READY (some container is not READY).
```
ubuntu@vm1:~$ kubectl get pods
NAME                          READY   STATUS    RESTARTS   AGE
never-ready                   0/1     Running   0          5m
ubuntu@vm1:~$ kubectl  get svc
NAME                   TYPE           CLUSTER-IP     EXTERNAL-IP      PORT(S)        AGE
kubernetes             ClusterIP      10.43.0.1      <none>           443/TCP        3h38m
never-ready-svc        LoadBalancer   10.43.186.5    10.123.123.99    80:30258/TCP   5m2s
[...]
ubuntu@vm1:~$ 
``` 

Meanwhile, debugs on speaker are captured [here](../logs/debug-speaker-not-ready.log). We can see a notable difference in the traces, where we see

```
{"caller":"bgp_controller.go:152","event":"skipping should announce bgp","ips":["10.123.123.99"],"level":"debug","pool":"external-pool","protocol":"bgp","reason":"pool not matching my node","service":"default/never-ready-svc","ts":"2025-02-05T14:28:07Z"}
{"caller":"layer2_controller.go:87","event":"shouldannounce","ips":["10.123.123.99"],"level":"debug","message":"failed no active endpoints","pool":"external-pool","protocol":"l2","service":"default/never-ready-svc","ts":"2025-02-05T14:28:07Z"}
```

When trying to reach the service from the external VM, ARP is not resolved, which is confirmed with TCPDUMP.

```
# generate trafic to VIP (even though there is no ping reply excepted for VIP ... but that's ok since we're just testing ARP )

ubuntu@vm-ext:~$ ping 10.123.123.99
PING 10.123.123.99 (10.123.123.99) 56(84) bytes of data.
^C
--- 10.123.123.99 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2049ms
ubuntu@vm-ext:~$ 

#  ARP request have no reply 

ubuntu@vm2:~$ sudo tcpdump -evni ens3.100 "arp"
tcpdump: listening on ens3.100, link-type EN10MB (Ethernet), snapshot length 262144 bytes
06:47:53.728156 52:54:00:41:4c:72 > ff:ff:ff:ff:ff:ff, ethertype ARP (0x0806), length 42: Ethernet (len 6), IPv4 (len 4), Request who-has 10.123.123.99 tell 10.123.123.4, length 28
06:47:54.753046 52:54:00:41:4c:72 > ff:ff:ff:ff:ff:ff, ethertype ARP (0x0806), length 42: Ethernet (len 6), IPv4 (len 4), Request who-has 10.123.123.99 tell 10.123.123.4, length 28
06:47:55.777028 52:54:00:41:4c:72 > ff:ff:ff:ff:ff:ff, ethertype ARP (0x0806), length 42: Ethernet (len 6), IPv4 (len 4), Request who-has 10.123.123.99 tell 10.123.123.4, length 28
06:47:59.240016 52:54:00:41:4c:72 > ff:ff:ff:ff:ff:ff, ethertype ARP (0x0806), length 42: Ethernet (len 6), IPv4 (len 4), Request who-has 10.123.123.100 tell 10.123.123.4, length 28

#ARP is incomplete

ubuntu@vm-ext:~$ arp -na
? (10.42.0.23) at fa:41:32:7f:51:52 [ether] on cni0
? (10.123.123.99) at <incomplete> on ens3.100

```

####  10.5.2. <a name='PODRUNNINGbutcontainertransitionsfromREADYtoNOTREADY'></a>POD RUNNING but container transitions from READY to NOT READY 

This is a slight variation of previous test to see how Metallb reacts on pod change.

Use the following manifest for bringing up the test scenario.

```
https://raw.githubusercontent.com/robric/k8s-svc-and-lb-testing/refs/heads/main/source/test-READY-to-NOT-READY-pod.yaml
```



