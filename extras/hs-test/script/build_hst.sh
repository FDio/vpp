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
DOCKER_LOGIN_SCRIPT="/scratch/nomad/.docker-ro/dlogin.sh"
if [ -x "$DOCKER_LOGIN_SCRIPT" ] ; then
  $DOCKER_LOGIN_SCRIPT
fi

# Set up the local registry before creating containers
echo "=== Setting up local registry ==="
if [ -x "$(dirname "$0")/../docker/setup-local-registry.sh" ]; then
  "$(dirname "$0")/../docker/setup-local-registry.sh"
else
  echo "Warning: setup-local-registry.sh not found or not executable"
  echo "Attempting to create and use local registry at localhost:5000"
  if ! docker ps | grep -q "local-registry"; then
    docker run -d --restart=always -p 5000:5000 --name local-registry registry:2
  fi
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

# Use the build-images.sh script to build all containers
echo "=== Building all containers using build-images.sh ==="
(
    # Export necessary environment variables for build-images.sh
    export BASE_TAG="localhost:5000/vpp-test-base:latest"
    export OS_ARCH
    export UBUNTU_VERSION
    export HTTP_PROXY
    export HTTPS_PROXY
    export NO_PROXY
    export DOCKER_CACHE_DIR="${DOCKER_CACHE_DIR}"
    export DOCKER_HST_BUILDER="${DOCKER_HST_BUILDER}"

    # Run the build script
    ./script/build-images.sh
)

# Check if the build was successful
if [ $? -ne 0 ]; then
    echo "Failed to build Docker images. Check the output above for errors."
    exit 1
fi

echo "$current_state_hash" > "$LAST_STATE_FILE"
