#!/bin/bash

# define the vlan 100 in cni0 bridge

sudo ip link add link cni0 name cni0.100 type vlan id 100
sudo ip link set cni0.100 up
sudo ip addr add 10.123.123.254/24 dev cni0.100

# add vlan 100 on each vm inerface.

echo "Defining interface ens3.100..."
multipass exec vm1 -- sudo ip link add link ens3 name ens3.100 type vlan id 100
multipass exec vm2 -- sudo ip link add link ens3 name ens3.100 type vlan id 100
multipass exec vm3 -- sudo ip link add link ens3 name ens3.100 type vlan id 100

sleep 3

echo "Adding IP addresses..."
multipass exec vm1 -- sudo ip addr add 10.123.123.1/24 dev ens3.100
multipass exec vm2 -- sudo ip addr add 10.123.123.2/24 dev ens3.100
multipass exec vm3 -- sudo ip addr add 10.123.123.3/24 dev ens3.100

sleep 3

echo "Bringing up interfaces..."
multipass exec vm1 -- sudo ip link set dev ens3.100 up
multipass exec vm2 -- sudo ip link set dev ens3.100 up
multipass exec vm3 -- sudo ip link set dev ens3.100 up



