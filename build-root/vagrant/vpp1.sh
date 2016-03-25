#!/bin/bash

#vpp11
#interface GigabitEthernet0/1
# description to vpp-1
# ipv6 address ::A:1:1:0:6/126
#! route to iosv-2
#ipv6 route ::A:1:1:0:16/128 ::A:1:1:0:7
#! route to iosv-4
#ipv6 route ::A:1:1:0:22/128 ::A:1:1:0:7


if [ $USER != "root" ] ; then
    echo "Restarting script with sudo..."
    sudo $0 ${*}
    exit
fi

# delete previous incarnations if they exist
ip link del dev veth_vpp11
ip link del dev veth_vpp12
ip netns del vpp11
ip netns del vpp12

#create namespaces
ip netns add vpp11
ip netns add vpp12

# create and configure 1st veth pair
ip link add name veth_vpp11 type veth peer name vpp11
ip link set dev vpp11 up
ip link set dev veth_vpp11 up netns vpp11

ip netns exec vpp11 \
  bash -c "
    ip link set dev lo up
    ip addr add ::A:1:1:0:6/126 dev veth_vpp11
    ip route add ::A:1:1:0:16/128 via ::A:1:1:0:7
    ip route add ::A:1:1:0:22/128 via ::A:1:1:0:7
"

# create and configure 2st veth pair
ip link add name veth_vpp12 type veth peer name vpp12
ip link set dev vpp12 up
ip link set dev veth_vpp12 up netns vpp12

ip netns exec vpp12 \
  bash -c "
    ip link set dev lo up
    ip addr add 172.16.12.2/24 dev veth_vpp12
    ip route add 172.16.11.0/24 via 172.16.12.1
"
ifconfig eth1 down
ip addr flush dev eth1

ifconfig eth2 down
ip addr flush dev eth2
