#!/bin/bash
set -eux
DOCKER_CE_CLI_DEB=docker-ce-cli_29.3.1-1~ubuntu.${UBUNTU_VERSION}~${CODENAME}_${TARGETARCH}.deb
DOCKER_CE_CLI_DEB_PATH=/var/cache/downloads/"$DOCKER_CE_CLI_DEB"
if [ ! -s "$DOCKER_CE_CLI_DEB_PATH" ] || ! dpkg-deb --contents "$DOCKER_CE_CLI_DEB_PATH" >/dev/null 2>&1; then
  DOCKER_CE_CLI_DOWNLOAD_TMP=$(mktemp "${DOCKER_CE_CLI_DEB_PATH}.tmp.XXXXXX")
  trap 'rm -f "$DOCKER_CE_CLI_DOWNLOAD_TMP"' EXIT
  wget -t 2 https://download.docker.com/linux/ubuntu/dists/"${CODENAME}"/pool/stable/"${TARGETARCH}"/"$DOCKER_CE_CLI_DEB" -O "$DOCKER_CE_CLI_DOWNLOAD_TMP"
  dpkg-deb --contents "$DOCKER_CE_CLI_DOWNLOAD_TMP" >/dev/null
  mv "$DOCKER_CE_CLI_DOWNLOAD_TMP" "$DOCKER_CE_CLI_DEB_PATH"
  trap - EXIT
fi
dpkg -i "$DOCKER_CE_CLI_DEB_PATH"
