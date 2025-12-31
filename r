#!/usr/bin/env zsh
r() {
        addr="0000:6e:00.0"
	iommu_group=$(basename $(realpath  /sys/bus/pci/devices/${addr}/iommu_group))
	#pci-bind 0000:0d:00.0 mhi-pci-generic
	pci-unbind ${addr}
	sleep 1
	pci-bind ${addr} vfio-pci
	sudo chown dmarion /dev/vfio/${iommu_group}
	sed -i -E 's/[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-9a-fA-F]/'"${addr}"'/g'  startup.conf
	ninja && ninja run
}

rst() {
# 1. Remove the modem from the OS to stop any active PCIe transactions
echo 1 | sudo tee  /sys/bus/pci/devices/0000:0d:00.0/remove

# 2. Trigger SBR on the parent bridge (04:08.0)
# We set bit 6 (0x40) of the Bridge Control Register (typically at offset 0x3E)
# This pulls the secondary bus reset line LOW.
sudo setpci -s 0000:04:08.0 BRIDGE_CONTROL=0x40:0x40
sleep 0.2
sudo setpci -s 0000:04:08.0 BRIDGE_CONTROL=0x00:0x40
sleep 0.5

# 3. Rescan the bus to find the device again
echo 1 | sudo tee /sys/bus/pci/rescan
}
