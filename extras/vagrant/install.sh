#!/bin/bash

# Get Command Line arguements if present
VPP_DIR=$1
if [ "x$1" != "x" ]; then
    VPP_DIR=$1
else
    VPP_DIR=`dirname $0`/../../
fi

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

if [ $DISTRIB_ID == "Ubuntu" ]; then
    (cd ${VPP_DIR}/build-root/;sudo dpkg -i *.deb)
elif [ $DISTRIB_ID == "CentOS" ]; then
    (cd ${VPP_DIR}/build-root/;sudo rpm -Uvh *.rpm)
fi