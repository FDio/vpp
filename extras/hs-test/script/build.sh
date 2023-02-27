#!/usr/bin/env bash

if [ $(lsb_release -is) != Ubuntu ]; then
	echo "Host stack test framework is supported only on Ubuntu"
	exit 1
fi

if [ -z $(which ab) ]; then
	echo "Host stack test framework requires apache2-utils to be installed"
	echo "It is recommended to run 'sudo make install-dep'"
	exit 1
fi

if [ -z $(which wrk) ]; then
	echo "Host stack test framework requires wrk to be installed"
	echo "It is recommended to run 'sudo make install-dep'"
	exit 1
fi

export VPP_WS=../..

if [ "$1" == "debug" ]; then
	VPP_BUILD_ROOT=${VPP_WS}/build-root/build-vpp_debug-native/vpp
else
	VPP_BUILD_ROOT=${VPP_WS}/build-root/build-vpp-native/vpp
fi
echo "Taking build objects from ${VPP_BUILD_ROOT}"

if [ -z "$UBUNTU_VERSION" ] ; then
	export UBUNTU_VERSION=$(lsb_release -rs)
fi
echo "Ubuntu version is set to ${UBUNTU_VERSION}"

export HST_LDPRELOAD=${VPP_BUILD_ROOT}/lib/x86_64-linux-gnu/libvcl_ldpreload.so
echo "HST_LDPRELOAD is set to ${HST_LDPRELOAD}"

export PATH=${VPP_BUILD_ROOT}/bin:$PATH

bin=vpp-data/bin
lib=vpp-data/lib

mkdir -p ${bin} ${lib} || true
rm -rf vpp-data/bin/* || true
rm -rf vpp-data/lib/* || true

cp ${VPP_BUILD_ROOT}/bin/* ${bin}
res+=$?
cp -r ${VPP_BUILD_ROOT}/lib/x86_64-linux-gnu/* ${lib}
res+=$?
if [ $res -ne 0 ]; then
	echo "Failed to copy VPP files. Is VPP built? Try running 'make build' in VPP directory."
	exit 1
fi

docker_build () {
    tag=$1
    dockername=$2
    docker build --build-arg UBUNTU_VERSION --build-arg http_proxy=$HTTP_PROXY \
            -t $tag  -f docker/Dockerfile.$dockername .
}

docker_build hs-test/vpp vpp
docker_build hs-test/nginx-ldp nginx
docker_build hs-test/nginx-standalone nginx-standalone
