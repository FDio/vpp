# Fix grub-pc on Virtualbox with Ubuntu
export DEBIAN_FRONTEND=noninteractive

# Standard update + upgrade dance
apt-get update
apt-get upgrade -y

# Fix the silly notion that /bin/sh should point to dash by pointing it to bash

sudo update-alternatives --install /bin/sh sh /bin/bash 100

cd /vpp
sudo -H -u vagrant make install-dep

# Install useful but non-mandatory tools
apt-get install -y emacs  git-review gdb gdbserver

sudo -H -u vagrant make bootstrap
sudo -H -u vagrant make pkg-deb
(cd build-root/;dpkg -i *.deb)

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

systemctl start vpp
cat /vagrant/README
