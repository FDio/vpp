
# Standard update + upgrade dance
yum check-update
yum update -y

# Install build tools
yum groupinstall 'Development Tools' -y
yum install openssl-devel -y
yum install glibc-static -y

# Install development tools
yum install gdb -y
yum install gdbserver -y

# Install jdk and maven
yum install -y java-1.8.0-openjdk-devel

# Install EPEL
yum install -y epel-release

# Install components to build Ganglia modules
yum install -y apr-devel
yum install -y --enablerepo=epel libconfuse-devel
yum install -y --enablerepo=epel ganglia-devel

# PCIutils
yum install -y pciutils

# Load the uio kernel module
modprobe uio_pci_generic

echo uio_pci_generic >> /etc/modules-load.d/uio_pci_generic.conf

# Setup for hugepages using upstart so it persists across reboots
sysctl -w vm.nr_hugepages=1024
echo "vm.nr_hugepages=1024" >> /etc/sysctl.conf
mkdir -p /mnt/huge
echo "hugetlbfs       /mnt/huge  hugetlbfs       defaults        0 0" >> /etc/fstab
mount /mnt/huge

# Setup the vpp code
cd ~vagrant/
sudo -u vagrant mkdir git
cd git/

# Check if git exists and remove it before attempting clone, else clone ineffective when "reload --provision"
[ -d vpp ] && rm -rf vpp
sudo -H -u vagrant git clone /vpp
cd vpp

# Initial vpp build
if [ -d build-root ]; then
  # Bootstrap vpp
  cd build-root/
  sudo -H -u vagrant ./bootstrap.sh

  # Build vpp
  sudo -H -u vagrant make PLATFORM=vpp TAG=vpp_debug install-packages
  cd ~vagrant/
  cat /vagrant/README
fi
