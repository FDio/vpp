#!/bin/bash

# Capture all the interface IPs, in case we need them later
ip -o addr show > ~vagrant/ifconfiga
chown vagrant:vagrant ~vagrant/ifconfiga

# Disable all ethernet interfaces other than the default route
# interface so VPP will use those interfaces.  The VPP auto-blacklist
# algorithm prevents the use of any physical interface contained in the
# routing table (i.e. "route --inet --inet6") preventing the theft of
# the management ethernet interface by VPP from the kernel.
for intf in $(ls /sys/class/net) ; do
    if [ -d /sys/class/net/$intf/device ] &&
        [ "$(route --inet --inet6 | grep default | grep $intf)" == "" ] ; then
        ifconfig $intf down
    fi
done
