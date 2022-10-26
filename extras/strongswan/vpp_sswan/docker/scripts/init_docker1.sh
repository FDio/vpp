#!/bin/bash

echo "Initialization Docker 1 - VPP with SSWAN"

cd /root/vpp
make build-release

cd /root/vpp/extras/strongswan/vpp_sswan
make clean
make all

cd /root/vpp/build-root/build-vpp-native/external/sswan
sudo make install

cd /root/vpp/extras/strongswan/vpp_sswan
make install

sudo systemctl daemon-reload
sudo systemctl restart strongswan.service

echo "### Loaded plugin in strogswan"
sudo swanctl --stats

sudo cp /root/vpp/extras/strongswan/vpp_sswan/docker/configs/swanctl_docker1.conf /etc/swanctl/conf.d/swanctl.conf
