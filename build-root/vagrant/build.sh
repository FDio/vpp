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
echo 0:$0
echo 1:$1
echo 2:$2
echo VPP_DIR: $VPP_DIR
echo SUDOCMD: $SUDOCMD

# Figure out what system we are running on
if [ -f /etc/lsb-release ];then
    . /etc/lsb-release
elif [ -f /etc/redhat-release ];then
    sudo yum install -y redhat-lsb
    DISTRIB_ID=`lsb_release -si`
    DISTRIB_RELEASE=`lsb_release -sr`
    DISTRIB_CODENAME=`lsb_release -sc`
    DISTRIB_DESCRIPTION=`lsb_release -sd`
fi
echo DISTRIB_ID: $DISTRIB_ID
echo DISTRIB_RELEASE: $DISTRIB_RELEASE
echo DISTRIB_CODENAME: $DISTRIB_CODENAME
echo DISTRIB_DESCRIPTION: $DISTRIB_DESCRIPTION

# Install dependencies
cd $VPP_DIR
make install-dep

# Really really clean things up so we can be sure
# that the build works even when switching distros
make wipe
(cd build-root/;make distclean)
rm -f build-root/.bootstrap.ok

# Build and install packaging
$SUDOCMD make bootstrap
if [ $DISTRIB_ID == "Ubuntu" ]; then
    $SUDOCMD make pkg-deb
    (cd build-root/;sudo dpkg -i *.deb)
elif [ $DISTRIB_ID == "CentOS" ]; then
    $SUDOCMD make pkg-rpm
    (cd build-root/;sudo rpm -Uvh *.rpm)
fi

