#!/bin/bash

# script to bind/uunbind a driver to a PCI

bind_nic()
{
	vd=$(cat /sys/bus/pci/devices/${2}/vendor /sys/bus/pci/devices/${2}/device)
	echo $2 | tee /sys/bus/pci/devices/${2}/driver/unbind > /dev/null 2> /dev/null
	echo $vd | tee /sys/bus/pci/drivers/${1}/new_id > /dev/null 2> /dev/null
	echo $2 | tee /sys/bus/pci/drivers/${1}/bind > /dev/null 2> /dev/null
}

unbind_nic ()
{
	echo $2 | tee /sys/bus/pci/drivers/${1}/unbind > /dev/null 2> /dev/null
	echo $2 | tee /sys/bus/pci/drivers_probe > /dev/null 2> /dev/null
}

usage()
{ 
	echo "Usage: $0 --bind | --unbind <driver-name> <pci-number>" 
	echo "Examples:"
	echo "  vpp_pci_bind.sh --bind vfio-pci 0000:00:07.0"
	echo "  vpp_pci_bind.sh --unbind vfio-pci 0000:00:07.0"
}

if [ $USER != "root" ] ; then
   echo "Restarting script with sudo..."
   sudo $0 ${*}
   exit
fi

if [[ ( $# != 3 ) ]] ; then
   usage
elif [[ ( $1 == "--bind" ) ]] ; then
   bind_nic "$2" "$3"
elif [[ ( $1 == "--unbind" ) ]] ; then
   unbind_nic "$2" "$3"
else
   usage
fi
