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

if [ "$(uname)" <> "Darwin" ]; then
    OS_ID=$(grep '^ID=' /etc/os-release | cut -f2- -d= | sed -e 's/\"//g')
    OS_VERSION_ID=$(grep '^VERSION_ID=' /etc/os-release | cut -f2- -d= | sed -e 's/\"//g')
fi

KERNEL_OS=`uname -o`
KERNEL_MACHINE=`uname -m`
KERNEL_RELEASE=`uname -r`
KERNEL_VERSION=`uname -v`

echo KERNEL_OS: $KERNEL_OS
echo KERNEL_MACHINE: $KERNEL_MACHINE
echo KERNEL_RELEASE: $KERNEL_RELEASE
echo KERNEL_VERSION: $KERNEL_VERSION
echo OS_ID: $OS_ID
echo OS_VERSION_ID: $OS_ID

# Install dependencies
cd $VPP_DIR
make UNATTENDED=yes install-dep

# Really really clean things up so we can be sure
# that the build works even when switching distros
$SUDOCMD make wipe
(cd build-root/;$SUDOCMD make distclean)
rm -f build-root/.bootstrap.ok

if [ $OS_ID == "centos" ]; then
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

if [ "$OS_ID" == "ubuntu" ]; then
    $SUDOCMD make pkg-deb
elif [ "$OS_ID" == "debian" ]; then
    $SUDOCMD make pkg-deb
elif [ "$OS_ID" == "centos" ]; then
    (cd $VPP_DIR/vnet ;$SUDOCMD aclocal;$SUDOCMD automake -a)
    $SUDOCMD make pkg-rpm
elif [ "$OS_ID" == "opensuse" ]; then
    $SUDOCMD make pkg-rpm
fi

