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
apt-get install -y emacs emacs24-el git-review gdb gdbserver cscope cscope-el 

sudo -H -u vagrant make bootstrap
sudo -H -u vagrant make build
#sudo -H -u vagrant make pkg-deb
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

# Hugepages
echo "vm.nr_hugepages=1024" >> /etc/sysctl.d/20-hugepages.conf
sysctl --system

cat << EOF > /etc/init/hugepages.conf
start on runlevel [2345]

task

script
    mkdir -p /run/hugepages/kvm || true
    rm -f /run/hugepages/kvm/* || true
    rm -f /dev/shm/* || true
    mount -t hugetlbfs nodev /run/hugepages/kvm
end script
EOF

# Make sure we run that hugepages.conf right now
start hugepages

start vpp
cat /vagrant/README

