#!/bin/bash

echo "Initialization Image"

git clone https://github.com/FDio/vpp.git ./vpp

cp -R vpp_sswan vpp/extras/strongswan/
cd vpp
yes | make install-dep
