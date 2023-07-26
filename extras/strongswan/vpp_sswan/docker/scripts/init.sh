#!/bin/bash

echo "Initialization Image"

git clone https://github.com/FDio/vpp.git ./vpp

# only for testing, should be deleted after merged this patch
rm -rf vpp/extras/strongswan/vpp_sswan
cp -R vpp_sswan vpp/extras/strongswan/

cd vpp
yes | make install-dep
