#!/bin/bash

modprobe vfio-pci

pci-bind() {
	echo $1 | sudo tee /sys/bus/pci/devices/$1/driver/unbind > /dev/null
	echo $2 | sudo tee /sys/bus/pci/devices/$1/driver_override > /dev/null
	echo $1 | sudo tee /sys/bus/pci/drivers/$2/bind > /dev/null
	echo | sudo tee /sys/bus/pci/devices/$1/driver_override > /dev/null
	iommu_group=$(basename $(realpath /sys/bus/pci/devices/$1/iommu_group))
	echo $1 $iommu_group
	sudo chown ${USER} /dev/vfio/${iommu_group}
}

for i in $(seq 0 7); do pci-bind 0000:00:04.${i} vfio-pci ; done
for i in $(seq 0 7); do pci-bind 0000:80:04.${i} vfio-pci ; done
