#!/bin/bash

cd /root/vpp/
make run-release STARTUP_CONF=/root/vpp/extras/strongswan/vpp_sswan/docker/configs/startup.conf &

sleep 5

sudo systemctl restart strongswan.service

sleep 2

echo "### Checking connections between VPP and Strongswan"
/root/vpp/build-root/build-vpp-native/vpp/bin/vppctl -s /run/vpp/cli.sock sh api client
