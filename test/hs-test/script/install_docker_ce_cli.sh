#!/bin/bash
set -eux
DOCKER_CE_CLI_DEB=docker-ce-cli_29.3.1-1~ubuntu.${UBUNTU_VERSION}~${CODENAME}_${TARGETARCH}.deb
DOCKER_CE_CLI_DEB_PATH=/var/cache/downloads/"$DOCKER_CE_CLI_DEB"
if [ ! -s "$DOCKER_CE_CLI_DEB_PATH" ] ; then
  wget -t 2 https://download.docker.com/linux/ubuntu/dists/"${CODENAME}"/pool/stable/"${TARGETARCH}"/"$DOCKER_CE_CLI_DEB" -O "$DOCKER_CE_CLI_DEB_PATH"
fi
dpkg -i "$DOCKER_CE_CLI_DEB_PATH"
