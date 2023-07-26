#!/bin/bash

echo "Initialization Docker 2 - SSWAN in kernel"

# tested only with 5.9.5 and 5.9.6 version of strongSwan
VERSION_SSWAN=5.9.6

curl -o ./strongswan-${VERSION_SSWAN}.tar.gz -LO https://github.com/strongswan/strongswan/archive/${VERSION_SSWAN}.tar.gz;
tar -zxof ./strongswan-${VERSION_SSWAN}.tar.gz

cd /root/strongswan-${VERSION_SSWAN}
./autogen.sh
./configure --prefix=/usr --sysconfdir=/etc --enable-libipsec --enable-systemd --enable-swanctl --disable-gmp --enable-openssl
make -j$(nproc)
sudo make install

sudo cp /root/vpp/extras/strongswan/vpp_sswan/docker/configs/swanctl_docker_policy_2.conf /etc/swanctl/conf.d/swanctl.conf

sudo systemctl daemon-reload
sudo systemctl restart strongswan.service

echo "### Loaded plugin in strogswan"
sudo swanctl --stats
