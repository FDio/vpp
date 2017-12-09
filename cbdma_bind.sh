#!/bin/bash

pci-unbind() {
	echo $1 | sudo tee /sys/bus/pci/devices/$1/driver/unbind
}

pci-bind() {
	pci-unbind $1
	echo $2 | sudo tee /sys/bus/pci/devices/$1/driver_override
	echo $1 | sudo tee /sys/bus/pci/drivers/$2/bind
	echo | sudo tee /sys/bus/pci/devices/$1/driver_override
}

for i in $(seq 0 7); do
	echo $i
	pci-bind 0000:00:04.${i} vfio-pci
	pci-bind 0000:80:04.${i} vfio-pci
done
