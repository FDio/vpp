#!/bin/bash

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

if [ "$(uname)" <> "Darwin" ]; then
    OS_ID=$(grep '^ID=' /etc/os-release | cut -f2- -d= | sed -e 's/\"//g')
    OS_VERSION_ID=$(grep '^VERSION_ID=' /etc/os-release | cut -f2- -d= | sed -e 's/\"//g')
fi

# Do initial setup for the system
if [ "$OS_ID" == "ubuntu" ]; then

    export DEBIAN_PRIORITY=critical
    export DEBIAN_FRONTEND=noninteractive
    export DEBCONF_NONINTERACTIVE_SEEN=true
    APT_OPTS="--assume-yes --no-install-suggests --no-install-recommends -o Dpkg::Options::=\"--force-confdef\" -o Dpkg::Options::=\"--force-confold\""

    # Standard update + upgrade dance
    apt-get update ${APT_OPTS} >/dev/null
    apt-get upgrade ${APT_OPTS} >/dev/null

    # Fix the silly notion that /bin/sh should point to dash by pointing it to bash

    update-alternatives --install /bin/sh sh /bin/bash 100

    # Install useful but non-mandatory tools
    apt-get install -y emacs x11-utils git-review gdb gdbserver xfce4-terminal iperf3
elif [ "$OS_ID" == "centos" ]; then
    if [ "$(echo $DISTRIB_RELEASE | cut -d'.' -f1)" == "7" ]; then
        rpm -ivh https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
        yum groupinstall "X Window system" -y
        yum groupinstall xfce -y
    fi
    # Standard update + upgrade dance
    yum check-update
    yum update -y
fi
