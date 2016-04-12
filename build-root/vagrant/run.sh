#!/bin/bash

# Figure out what system we are running on
if [ -f /etc/lsb-release ];then
    . /etc/lsb-release
elif [ -f /etc/redhat-release ];then
    yum install -y redhat-lsb
    DISTRIB_ID=`lsb_release -si`
    DISTRIB_RELEASE=`lsb_release -sr`
    DISTRIB_CODENAME=`lsb_release -sc`
    DISTRIB_DESCRIPTION=`lsb_release -sd`
fi

if [ $DISTRIB_ID == "Ubuntu" ]; then
    start vpp
elif [ $DISTRIB_ID == "CentOS" ]; then
    # Install uio-pci-generic
    modprobe uio_pci_generic

    # Start vpp
    service vpp start
fi
