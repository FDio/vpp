# Standard update + upgrade dance
apt-get update
apt-get upgrade -y

# Fix the silly notion that /bin/sh should point to dash by pointing it to bash

sudo update-alternatives --install /bin/sh sh /bin/bash 100

# Install build tools
apt-get install -y build-essential autoconf automake bison libssl-dev ccache libtool git dkms debhelper

# Install other stuff
# apt-get install -y qemu-kvm libvirt-bin ubuntu-vm-builder bridge-utils

# Install uio
apt-get install -y linux-image-extra-`uname -r`

# Install jdk and maven
apt-get install -y openjdk-7-jdk
# $$$ comment out for the moment
# apt-get install -y --force-yes maven3

# Install debian packaging tools
apt-get install -y debhelper dkms

# Setup for hugepages using upstart so it persists across reboots
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

# Setup the vpp code
cd ~vagrant/
sudo -u vagrant mkdir git
cd git/

# You will need to alter this line to reflect reality.
sudo -H -u vagrant git clone /vpp
cd vpp/

# Initial vpp build
if [ -d build-root ]; then
  # Bootstrap vpp
  cd build-root/
  sudo -H -u vagrant ./bootstrap.sh

  # Build vpp
  sudo -H -u vagrant make PLATFORM=vpp TAG=vpp_debug install-deb

  # Stick the dpdk module in the canonical place
  cp ./install-vpp_debug-native/dpdk/kmod/igb_uio.ko /lib/modules/`uname -r`/kernel/drivers/uio/
  depmod

  # Load igb_uio into the kernel
  modprobe igb_uio

  # Make sure igb_uio loads at boot time
  # Make sure uio loads at boot time
  echo  igb_uio >> /lib/modprobe.d/igb_uio.conf
  cd ~vagrant/
  cat /vagrant/README

fi
