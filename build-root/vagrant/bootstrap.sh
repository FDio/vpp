#!/bin/bash

# Note: This script has been tested with centos7.2 and Ubuntu 14.04

# Get Command Line arguements if present
VPP_DIR=$1
if [ "x$1" != "x" ]; then
    VPP_DIR=$1
else
    VPP_DIR=`dirname $0`/../../
fi
echo "foo x$2"
if [ "x$2" != "x" ]; then
    SUDOCMD="sudo -H -u $2"
fi

# Make sure that we get the hugepages we need on provision boot
# Note: The package install should take care of this at the end
#       But sometimes after all the work of provisioning, we can't
#       get the requested number of hugepages without rebooting.
#       So do it here just in case
sysctl -w vm.nr_hugepages=1024
HUGEPAGES=`sysctl -n  vm.nr_hugepages`
if [ $HUGEPAGES != 1024 ]; then
    echo "ERROR: Unable to get 1024 hugepages, only got $HUGEPAGES.  Cannot finish."
    exit
fi

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

echo DISTRIB_ID: $DISTRIB_ID
echo DISTRIB_RELEASE: $DISTRIB_RELEASE
echo DISTRIB_CODENAME: $DISTRIB_CODENAME
echo DISTRIB_DESCRIPTION: $DISTRIB_DESCRIPTION

# Do initial setup for the system
if [ $DISTRIB_ID == "Ubuntu" ]; then
    # Fix grub-pc on Virtualbox with Ubuntu
    export DEBIAN_FRONTEND=noninteractive

    # Standard update + upgrade dance
    apt-get update
    apt-get upgrade -y

    # Fix the silly notion that /bin/sh should point to dash by pointing it to bash

    update-alternatives --install /bin/sh sh /bin/bash 100

    # Install useful but non-mandatory tools
    apt-get install -y emacs  git-review gdb gdbserver
elif [ $DISTRIB_ID == "CentOS" ]; then
    # Standard update + upgrade dance
    yum check-update
    yum update -y
fi

# Install dependencies
cd $VPP_DIR
make install-dep

# Really really clean things up so we can be sure
# that the build works even when switching distros
make wipe
(cd build-root/;make distclean)
rm build-root/.bootstrap.ok

# Build and install packaging
$SUDOCMD make bootstrap
if [ $DISTRIB_ID == "Ubuntu" ]; then
    $SUDOCMD make pkg-deb
    (cd build-root/;dpkg -i *.deb)
elif [ $DISTRIB_ID == "CentOS" ]; then
    $SUDOCMD make pkg-rpm
    (cd build-root/;rpm -Uvh *.rpm)
fi

# Capture all the interface IPs, in case we need them later
ifconfig -a > ~vagrant/ifconfiga
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

if [ $DISTRIB_ID == "Ubuntu" ]; then
    start vpp
elif [ $DISTRIB_ID == "CentOS" ]; then
    # Install uio-pci-generic
    modprobe uio_pci_generic

    # Start vpp
    service vpp start
fi
echo 0:$0
echo 1:$1
echo 2:$2
echo VPP_DIR: $VPP_DIR
echo SUDOCMD: $SUDOCMD
