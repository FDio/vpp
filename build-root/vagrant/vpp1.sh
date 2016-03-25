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


ifconfig eth1 down
ip addr flush dev eth1

ifconfig eth2 down
ip addr flush dev eth2

ifconfig eth3 down
ip addr flush dev eth3
