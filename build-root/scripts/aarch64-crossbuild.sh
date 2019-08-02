#!/bin/bash

REPO_DIR=$(realpath "$(dirname ${0})/../..")

CONTAINER_ID=$(docker run --privileged -dt -v "${REPO_DIR}:${REPO_DIR}" ubuntu:18.04 /bin/bash)
docker exec ${CONTAINER_ID} apt update
docker exec ${CONTAINER_ID} apt install -y sudo make
docker exec ${CONTAINER_ID} make -C ${REPO_DIR} UNATTENDED=yes install-dep
docker exec ${CONTAINER_ID} bash -c "cat << EOF > /etc/apt/sources.list
deb [arch=amd64] http://archive.ubuntu.com/ubuntu/ bionic main restricted
deb [arch=amd64] http://archive.ubuntu.com/ubuntu/ bionic-updates main restricted
deb [arch=amd64] http://archive.ubuntu.com/ubuntu/ bionic universe
deb [arch=amd64] http://archive.ubuntu.com/ubuntu/ bionic-updates universe
deb [arch=amd64] http://archive.ubuntu.com/ubuntu/ bionic multiverse
deb [arch=amd64] http://archive.ubuntu.com/ubuntu/ bionic-updates multiverse
deb [arch=amd64] http://archive.ubuntu.com/ubuntu/ bionic-backports main restricted universe multiverse
deb [arch=amd64] http://security.ubuntu.com/ubuntu/ bionic-security main restricted
deb [arch=amd64] http://security.ubuntu.com/ubuntu/ bionic-security universe
deb [arch=amd64] http://security.ubuntu.com/ubuntu/ bionic-security multiverse

deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports/ bionic main restricted universe multiverse
deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports/ bionic-updates main restricted universe multiverse
deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports/ bionic-backports main restricted universe multiverse
EOF"
docker exec ${CONTAINER_ID} apt update
docker exec ${CONTAINER_ID} dpkg --add-architecture arm64
docker exec ${CONTAINER_ID} apt install -y libssl-dev:arm64 libmbedtls-dev:arm64 uuid-dev:arm64 libnuma-dev:arm64 libnl-3-dev:arm64 gcc-8-aarch64-linux-gnu g++-8-aarch64-linux-gnu
docker exec ${CONTAINER_ID} update-alternatives \
	    --install /usr/bin/aarch64-linux-gnu-gcc aarch64-linux-gnu-gcc /usr/bin/aarch64-linux-gnu-gcc-8 800 \
	    --slave /usr/bin/aarch64-linux-gnu-g++ aarch64-linux-gnu-g++ /usr/bin/aarch64-linux-gnu-g++-8

docker exec ${CONTAINER_ID} make -C ${REPO_DIR} PLATFORM=aarch64-generic build-release
