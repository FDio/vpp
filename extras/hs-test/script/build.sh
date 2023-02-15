#!/usr/bin/env bash

if [ $(lsb_release -is) != Ubuntu ]; then
	echo "Host stack test framework is supported only on Ubuntu"
	exit 1
fi

if [ $(which ab) -z ]; then
	echo "Host stack test framework requires apache2-utils to be installed"
        echo "Installing it now"
        sudo apt install -y apache2-utils
fi

if [ $(which wrk) -z ]; then
	echo "Host stack test framework requires wrk to be installed"
        echo "Installing it now"
        sudo apt install -y wrk
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

docker build --build-arg UBUNTU_VERSION --build-arg http_proxy=$HTTP_PROXY \
	-t hs-test/vpp -f docker/Dockerfile.vpp .
docker build --build-arg UBUNTU_VERSION --build-arg http_proxy=$HTTP_PROXY \
	-t hs-test/nginx-ldp -f docker/Dockerfile.nginx .
