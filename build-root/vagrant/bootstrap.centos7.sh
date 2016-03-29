
# Standard update + upgrade dance
yum check-update
yum update -y

# Install dependencies
cd /vpp
make install-dep

# Build rpms
sudo -H -u vagrant make bootstrap
sudo -H -u vagrant make pkg-rpm

# Install rpms

(cd build-root/;sudo rpm -Uvh *.rpm)

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

# Install uio-pci-generic
modprobe uio_pci_generic

# Start vpp
service vpp start

# cat README
cat /vagrant/README
