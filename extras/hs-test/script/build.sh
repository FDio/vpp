#!/usr/bin/env bash

if [ $(lsb_release -is) != Ubuntu ]; then
	echo "Host stack test framework is supported only on Ubuntu"
	exit 1
fi

source vars

bin=vpp-data/bin
lib=vpp-data/lib

mkdir -p ${bin} ${lib} || true

cp ${VPP_WS}/build-root/build-vpp_debug-native/vpp/bin/* ${bin}
res+=$?
cp -r ${VPP_WS}/build-root/build-vpp_debug-native/vpp/lib/x86_64-linux-gnu/* ${lib}
res+=$?
if [ $res -ne 0 ]; then
	echo "Failed to copy VPP files. Is VPP built? Try running 'make build' in VPP directory."
	exit 1
fi

docker build --build-arg UBUNTU_VERSION -t hs-test/vpp -f docker/Dockerfile.vpp .
docker build --build-arg UBUNTU_VERSION -t hs-test/nginx-ldp -f docker/Dockerfile.nginx .
