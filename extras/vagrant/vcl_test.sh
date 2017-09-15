#!/bin/bash

if [ -n "$1" ]; then
    VPP_DIR=$1
else
    VPP_DIR=`dirname $0`/../../
fi

if [ -n "$2" ]; then
    SUDOCMD="sudo -H -u $2"
fi

echo 'Building VCL test apps'
cd $VPP_DIR
$SUDOCMD perl -pi -e 's/noinst_PROGRAMS/bin_PROGRAMS/g' $VPP_DIR/src/uri.am
$SUDOCMD make dpdk-install-dev build-release
sudo sysctl -p$VPP_DIR/src/vpp/conf/80-vpp.conf
sudo modprobe uio_pci_generic

if [ "$2" = "vagrant" ] && [ -d "/home/vagrant" ] ; then
    dot_bash_aliases="/home/$2/.bash_aliases"
    echo "export WS_ROOT=$VPP_DIR" | $SUDOCMD tee $dot_bash_aliases
    source $dot_bash_aliases
fi

