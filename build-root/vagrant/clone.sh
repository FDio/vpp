#!/bin/bash
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

# Make sure git is installed
if [ $DISTRIB_ID == "CentOS" ]; then
    yum -y install git
elif [ $DISTRIB_ID == "Ubuntu" ]; then
    apt-get -y install git
fi

# Setup the vpp code
cd ~vagrant/
sudo -u vagrant mkdir git
cd git/
echo "SSH_AUTH_SOCK  $SSH_AUTH_SOCK x"
chmod 777 $SSH_AUTH_SOCK

CLONE_URL=`cd /vpp;git remote -v | grep origin |grep fetch |awk '{print $2}'`
echo "CLONE_URL $CLONE_URL"
echo $CLONE_URL | grep -q "^ssh:"
if [ $? == 0 ]; then
    SSH_HOST=`echo $CLONE_URL| awk -F/ '{print $3}'`
    SSH_PORT=`echo $SSH_HOST| awk -F: '{print $2}'`
    if [ -n $SSH_PORT ]; then
        SSH_PORT="-p $SSH_PORT"
    fi
    SSH_HOST=`echo $SSH_HOST| awk -F: '{print $1}'`
    echo "SSH_HOST $SSH_HOST"
    echo "SSH_PORT $SSH_PORT"
    sudo -HE -u vagrant ssh -oStrictHostKeyChecking=no -v $SSH_PORT $SSH_HOST
fi
sudo -HE -u vagrant git clone $CLONE_URL
