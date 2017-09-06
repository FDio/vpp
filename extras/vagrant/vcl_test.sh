#!/bin/bash

# Get Command Line arguements if present
VPP_DIR=$1
if [ "x$1" != "x" ]; then
    VPP_DIR=$1
else
    VPP_DIR=`dirname $0`/../../
fi

if [ "x$2" != "x" ]; then
    SUDOCMD="sudo -H -u $2"
fi

echo 'Building VCL test apps'
cd $VPP_DIR
$SUDOCMD perl -pi -e 's/noinst_PROGRAMS/bin_PROGRAMS/g' $VPP_DIR/src/uri.am
$SUDOCMD make build-release
echo "export WS_ROOT=$VPP_DIR" | sudo -H -u vagrant tee /home/vagrant/.bash_aliases
source /home/vagrant/.bash_aliases
sudo cp $VPP_DIR/src/vpp/conf/80-vpp.conf /etc/sysctl.d
sudo sysctl -p/etc/sysctl.d/80-vpp.conf
sudo modprobe uio_pci_generic
