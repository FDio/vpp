#!/bin/bash

echo "Initialization Docker 1 - VPP with SSWAN"

cd /root/vpp
make build-release

cd /root/vpp/extras/strongswan/vpp_sswan
make clean
make all

sudo systemctl daemon-reload
sudo systemctl restart strongswan.service

echo "### Loaded plugin in strogswan"
sudo swanctl --stats
