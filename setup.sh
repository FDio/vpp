#!/bin/bash

if [ $USER != "root" ] ; then
	echo "Restarting script with sudo..."
	sudo $0 ${*}
	exit
fi

setup () {
  cd /sys/bus/pci/devices/${1}
  ifname=$(basename net/*)
  echo 0 | tee sriov_numvfs > /dev/null
  echo 1 | tee sriov_numvfs > /dev/null
  ip link set dev ${ifname} vf 0 mac ${2}
  ip link show dev ${ifname}
  vf=$(basename $(readlink virtfn0))
  echo ${vf} | tee virtfn0/driver/unbind
  echo vfio-pci | tee virtfn0/driver_override
  echo ${vf} | sudo tee /sys/bus/pci/drivers/vfio-pci/bind
  echo  | tee virtfn0/driver_override
}


setup 0000:3b:00.1 00:11:22:33:44:01
setup 0000:3b:00.0 00:11:22:33:44:00
