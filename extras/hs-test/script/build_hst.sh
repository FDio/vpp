#!/usr/bin/env bash

if [ "$(lsb_release -is)" != Ubuntu ]; then
	echo "Host stack test framework is supported only on Ubuntu"
	exit 1
fi

if [ -z "$(which ab)" ]; then
	echo "Host stack test framework requires apache2-utils to be installed"
	echo "It is recommended to run 'sudo make install-dep'"
	exit 1
fi

if [ -z "$(which wrk)" ]; then
	echo "Host stack test framework requires wrk to be installed"
	echo "It is recommended to run 'sudo make install-dep'"
	exit 1
fi

export VPP_WS=../..
OS_ARCH="$(uname -m)"
DOCKER_BUILD_DIR="/scratch/docker-build"
DOCKER_CACHE_DIR="${DOCKER_BUILD_DIR}/docker_cache"

if [ -d "${DOCKER_BUILD_DIR}" ] ; then
  mkdir -p "${DOCKER_CACHE_DIR}"
  DOCKER_HST_BUILDER="hst_builder"
  set -x
  if ! docker buildx ls --format "{{.Name}}" | grep -q "${DOCKER_HST_BUILDER}"; then
    docker buildx create --name=${DOCKER_HST_BUILDER} --driver=docker-container --use --bootstrap || true
  fi
  set -x
  DOCKER_CACHE_ARGS="--builder=${DOCKER_HST_BUILDER} --load --cache-to type=local,dest=${DOCKER_CACHE_DIR},mode=max --cache-from type=local,src=${DOCKER_CACHE_DIR}"
fi

if [ "$1" == "debug" ]; then
	VPP_BUILD_ROOT=${VPP_WS}/build-root/build-vpp_debug-native/vpp
elif [ "$1" == "gcov" ]; then
  VPP_BUILD_ROOT=${VPP_WS}/build-root/build-vpp_gcov-native/vpp
else
	VPP_BUILD_ROOT=${VPP_WS}/build-root/build-vpp-native/vpp
fi
echo "Taking build objects from ${VPP_BUILD_ROOT}"

export UBUNTU_VERSION=${UBUNTU_VERSION:-"$(lsb_release -rs)"}
echo "Ubuntu version is set to ${UBUNTU_VERSION}"

export HST_LDPRELOAD=${VPP_BUILD_ROOT}/lib/${OS_ARCH}-linux-gnu/libvcl_ldpreload.so
echo "HST_LDPRELOAD is set to ${HST_LDPRELOAD}"

export PATH=${VPP_BUILD_ROOT}/bin:$PATH

bin=vpp-data/bin
lib=vpp-data/lib

mkdir -p ${bin} ${lib} || true
rm -rf vpp-data/bin/* || true
rm -rf vpp-data/lib/* || true

cp ${VPP_BUILD_ROOT}/bin/* ${bin}
res+=$?
cp -r ${VPP_BUILD_ROOT}/lib/"${OS_ARCH}"-linux-gnu/* ${lib}
res+=$?
if [ $res -ne 0 ]; then
	echo "Failed to copy VPP files. Is VPP built? Try running 'make build' in VPP directory."
	exit 1
fi

docker_build () {
    tag=$1
    dockername=$2
    set -ex
    # shellcheck disable=2086
    docker buildx build ${DOCKER_CACHE_ARGS}  \
      --build-arg UBUNTU_VERSION              \
      --build-arg http_proxy="$HTTP_PROXY"    \
      --build-arg https_proxy="$HTTP_PROXY"   \
      --build-arg HTTP_PROXY="$HTTP_PROXY"    \
      --build-arg HTTPS_PROXY="$HTTP_PROXY"   \
      -t "$tag" -f docker/Dockerfile."$dockername" .
    set +ex
}

docker_build hs-test/vpp vpp
docker_build hs-test/nginx-ldp nginx
docker_build hs-test/nginx-server nginx-server
docker_build hs-test/build build
if [ "$HST_EXTENDED_TESTS" = true ] ; then
    docker_build hs-test/nginx-http3 nginx-http3
    docker_build hs-test/curl curl
fi

# cleanup detached images
images=$(docker images --filter "dangling=true" -q --no-trunc)
if [ "$images" != "" ]; then
		# shellcheck disable=SC2086
    docker rmi $images
fi
