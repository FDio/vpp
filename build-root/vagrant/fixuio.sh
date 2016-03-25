#!/bin/bash

sudo lsmod | grep uio
sudo modprobe uio
sudo insmod /vpp/build-root/install-vpp-native/dpdk/kmod/igb_uio.ko
sudo lsmod | grep uio
