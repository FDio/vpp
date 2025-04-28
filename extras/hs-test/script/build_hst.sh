#!/usr/bin/env bash

if [ "$(lsb_release -is)" != Ubuntu ]; then
	echo "Host stack test framework is supported only on Ubuntu"
	exit 1
fi

export VPP_WS=../..
export UBUNTU_VERSION=${UBUNTU_VERSION:-"$(lsb_release -rs)"}
echo "Ubuntu version is set to ${UBUNTU_VERSION}"

if [ "$1" == "debug" ]; then
	VPP_BUILD_ROOT=${VPP_WS}/build-root/build-vpp_debug-native/vpp
elif [ "$1" == "gcov" ]; then
  VPP_BUILD_ROOT=${VPP_WS}/build-root/build-vpp_gcov-native/vpp
else
	VPP_BUILD_ROOT=${VPP_WS}/build-root/build-vpp-native/vpp
fi

LAST_STATE_FILE=".last_state_hash"

# get current state hash and ubuntu version
current_state_hash=$(ls -l "$VPP_BUILD_ROOT"/.mu_build_install_timestamp; ls -l docker | sha1sum | awk '{print $1}')
current_state_hash=$current_state_hash$UBUNTU_VERSION$1

if [ -f "$LAST_STATE_FILE" ]; then
    last_state_hash=$(cat "$LAST_STATE_FILE")
else
    last_state_hash=""
fi

# compare current state with last state and check FORCE_BUILD
if [ "$current_state_hash" = "$last_state_hash" ] && [ "$2" = "false" ]; then
    echo "*** Skipping docker build - no new changes ***"
    exit 0
fi

OS_ARCH="$(uname -m)"
DOCKER_BUILD_DIR="/scratch/docker-build"
DOCKER_CACHE_DIR="${DOCKER_BUILD_DIR}/docker_cache"

if [ -d "${DOCKER_BUILD_DIR}" ] ; then
  mkdir -p "${DOCKER_CACHE_DIR}"
  DOCKER_HST_BUILDER="hst_builder"
  set -x
  if ! docker buildx ls --format "{{.Name}}" | grep -q "${DOCKER_HST_BUILDER}"; then
    docker buildx create --use --driver-opt env.http_proxy="$HTTP_PROXY" --driver-opt env.https_proxy="$HTTP_PROXY" --driver-opt '"env.no_proxy='"$NO_PROXY"'"' --name=${DOCKER_HST_BUILDER} --driver=docker-container --use --bootstrap || true
  fi
  set -x
  DOCKER_CACHE_ARGS="--builder=${DOCKER_HST_BUILDER} --load --cache-to type=local,dest=${DOCKER_CACHE_DIR},mode=max --cache-from type=local,src=${DOCKER_CACHE_DIR}"
fi

echo "Taking build objects from ${VPP_BUILD_ROOT}"

export HST_LDPRELOAD=${VPP_BUILD_ROOT}/lib/${OS_ARCH}-linux-gnu/libvcl_ldpreload.so
echo "HST_LDPRELOAD is set to ${HST_LDPRELOAD}"

export PATH=${VPP_BUILD_ROOT}/bin:$PATH

bin=vpp-data/bin
lib=vpp-data/lib

mkdir -p ${bin} ${lib} || true
rm -rf vpp-data/bin/* || true
rm -rf vpp-data/lib/* || true

declare -i res=0
cp ${VPP_BUILD_ROOT}/bin/* ${bin}
res+=$?
cp -r ${VPP_BUILD_ROOT}/lib/"${OS_ARCH}"-linux-gnu/* ${lib}
res+=$?
if [ "$res" -ne 0 ]; then
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
      --build-arg OS_ARCH="$OS_ARCH"          \
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
docker_build hs-test/curl curl
docker_build hs-test/envoy envoy
docker_build hs-test/nginx-http3 nginx-http3
docker_build hs-test/ab ab
docker_build hs-test/wrk wrk
docker_build hs-test/h2load h2load

# make it multi-user friendly
if [ -d "${DOCKER_CACHE_DIR}" ] ; then
  chgrp -R docker "${DOCKER_CACHE_DIR}"
  chmod -R g+rwx "${DOCKER_CACHE_DIR}"
fi

# cleanup detached images
images=$(docker images --filter "dangling=true" -q --no-trunc)
if [ "$images" != "" ]; then
		# shellcheck disable=SC2086
    docker rmi $images
fi

echo "$current_state_hash" > "$LAST_STATE_FILE"
