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
elif [ -f /etc/os-release ];then
   . /etc/os-release
   DISTRIB_ID=$ID
   DISTRIB_RELEASE=$VERSION_ID
   DISTRIB_CODENAME=$VERSION
   DISTRIB_DESCRIPTION=$PRETTY_NAME
fi
KERNEL_OS=`uname -o`
KERNEL_MACHINE=`uname -m`
KERNEL_RELEASE=`uname -r`
KERNEL_VERSION=`uname -v`

echo KERNEL_OS: $KERNEL_OS
echo KERNEL_MACHINE: $KERNEL_MACHINE
echo KERNEL_RELEASE: $KERNEL_RELEASE
echo KERNEL_VERSION: $KERNEL_VERSION
echo DISTRIB_ID: $DISTRIB_ID
echo DISTRIB_RELEASE: $DISTRIB_RELEASE
echo DISTRIB_CODENAME: $DISTRIB_CODENAME
echo DISTRIB_DESCRIPTION: $DISTRIB_DESCRIPTION

# Install dependencies
cd $VPP_DIR
make UNATTENDED=yes install-dep

# Really really clean things up so we can be sure
# that the build works even when switching distros
$SUDOCMD make wipe
(cd build-root/;$SUDOCMD make distclean)
rm -f build-root/.bootstrap.ok

if [ $DISTRIB_ID == "CentOS" ]; then
    echo rpm -V apr-devel
    rpm -V apr-devel
    if [ $? != 0 ]; then sudo yum reinstall -y apr-devel;fi
    echo rpm -V ganglia-devel
    rpm -V ganglia-devel
    if [ $? != 0 ]; then sudo yum reinstall -y ganglia-devel;fi
    echo rpm -V libconfuse-devel
    rpm -V libconfuse-devel
    if [ $? != 0 ]; then sudo yum reinstall -y libconfuse-devel;fi
fi

# Build and install packaging
$SUDOCMD make bootstrap

if [ "$DISTRIB_ID" == "Ubuntu" ]; then
    $SUDOCMD make pkg-deb
elif [ "$DISTRIB_ID" == "debian" ]; then
    $SUDOCMD make pkg-deb
elif [ "$DISTRIB_ID" == "CentOS" ]; then
    (cd $VPP_DIR/vnet ;$SUDOCMD aclocal;$SUDOCMD automake -a)
    $SUDOCMD make pkg-rpm
elif [ "$DISTRIB_ID" == "opensuse" ]; then
    $SUDOCMD make build-release
fi

