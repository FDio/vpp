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
make UNATTENDED=yes install-dep

# Really really clean things up so we can be sure
# that the build works even when switching distros
make wipe
(cd build-root/;make distclean)
rm -f build-root/.bootstrap.ok


if [ $DISTRIB_ID == "CentOS" ]; then
    echo "Check for ganglia-devel and apr-devel"
    echo rpm -ql ganglia-devel
    rpm -ql ganglia-devel
    echo rpm -ql apr-devel
    rpm -ql apr-devel

    echo List all installed rpms
    rpm -qa
    echo ls -l /usr/include/apr-1
    ls -l /usr/include/apr-1
    echo ls -l /usr/include/gang*
    ls -l /usr/include/gang*
    echo ls -l /usr/include/gm_*
    ls -l /usr/include/gm_*
    echo cat /usr/include/gm_value.h
    cat /usr/include/gm_value.h

    echo rpm -V apr-devel
    rpm -V apr-devel
    echo rpm -V ganglia-devel
    rpm -V ganglia-devel
    echo rpm -V libconfuse-devel
    rpm -V libconfuse-devel

    echo df
    df
fi

# Build and install packaging
echo make bootstrap
$SUDOCMD make bootstrap
if [ $DISTRIB_ID == "Ubuntu" ]; then
    $SUDOCMD make pkg-deb
elif [ $DISTRIB_ID == "CentOS" ]; then
    echo make pkg-rpm
    $SUDOCMD make pkg-rpm
fi

