#!/usr/bin/env bash

source vars

bin=vpp-data/bin
lib=vpp-data/lib

mkdir -p ${bin} ${lib} || true

cp ${VPP_WS}/build-root/build-vpp_debug-native/vpp/bin/* ${bin}
cp -r ${VPP_WS}/build-root/build-vpp_debug-native/vpp/lib/x86_64-linux-gnu/* ${lib}

docker build -t hs-test/vpp -f Dockerfile.vpp .
