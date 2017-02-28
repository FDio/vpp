#!/usr/bin/env bash

function topo_setup
{
  ip netns add vppns1
  ip link add veth_vpp1 type veth peer name vpp1
  ip link set dev vpp1 up
  ip link set dev veth_vpp1 up netns vppns1

  ip netns exec vppns1                          \
  bash -c "
    ip link set dev lo up
    ip addr add 6.0.1.2/24 dev veth_vpp1
  "

  ethtool --offload  vpp1 rx off tx off
  ip netns exec vppns1 ethtool --offload veth_vpp1 rx off tx off

}

function topo_clean
{
  ip link del dev veth_vpp1 &> /dev/null
  ip netns del vppns1 &> /dev/null
}

if [ "$1" == "clean" ] ; then
  topo_clean
    exit 0
else
  topo_setup
fi

# to test connectivity do:
# sudo ip netns exec vppns1 telnet 6.0.1.1 1234
# to push traffic to the server
# dd if=/dev/zero bs=1024K count=512 | nc 6.0.1.1
# to listen for incoming connection from vpp
# nc -l 1234
