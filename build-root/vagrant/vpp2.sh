#!/bin/bash

#vpp21
#interface GigabitEthernet0/1
# description to vpp-2
# ipv6 address ::A:1:1:0:16/126
#!
#ipv6 route ::A:1:1:0:6/128 ::A:1:1:0:17

#vpp22
#interface GigabitEthernet0/1
# description to vpp-2
# ipv6 address ::A:1:1:0:22/126
#! Route to iosv-1
#ipv6 route ::A:1:1:0:6/128 ::A:1:1:0:23

if [ $USER != "root" ] ; then
    echo "Restarting script with sudo..."
    sudo $0 ${*}
    exit
fi

# delete previous incarnations if they exist
ip link del dev veth_vpp21
ip link del dev veth_vpp22
ip netns del vpp21
ip netns del vpp22

#create namespaces
ip netns add vpp21
ip netns add vpp22

# create and configure 1st veth pair
ip link add name veth_vpp21 type veth peer name vpp21
ip link set dev vpp21 up
ip link set dev veth_vpp21 up netns vpp21

ip netns exec vpp21 \
  bash -c "
    ip link set dev lo up
    ip addr add ::A:1:1:0:16/126 dev veth_vpp21
    ip route add ::A:1:1:0:6/128 via ::A:1:1:0:17
"

# create and configure 2st veth pair
ip link add name veth_vpp22 type veth peer name vpp22
ip link set dev vpp22 up
ip link set dev veth_vpp22 up netns vpp22

ip netns exec vpp22 \
  bash -c "
    ip link set dev lo up
    ip addr add ::A:1:1:0:22/126 dev veth_vpp22
    ip route add ::A:1:1:0:6/128 via ::A:1:1:0:23
"
ifconfig eth1 down
ip addr flush dev eth1

ifconfig eth2 down
ip addr flush dev eth2
