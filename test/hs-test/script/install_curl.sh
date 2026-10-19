#!/bin/bash
set -eux
OS_ARCH="$(uname -m)"
CURL_VERSION="8.23.0"
CURL_TARBALL=curl-linux-"${OS_ARCH}"-glibc-"$CURL_VERSION".tar.xz
CURL_TARBALL_PATH=/var/cache/downloads/"$CURL_TARBALL"
if [ ! -s "$CURL_TARBALL_PATH" ] || ! tar -tf "$CURL_TARBALL_PATH" >/dev/null 2>&1; then
  CURL_DOWNLOAD_TMP=$(mktemp "${CURL_TARBALL_PATH}.tmp.XXXXXX")
  trap 'rm -f "$CURL_DOWNLOAD_TMP"' EXIT
  wget -t 2 https://github.com/stunnel/static-curl/releases/download/"$CURL_VERSION"/"$CURL_TARBALL" -O "$CURL_DOWNLOAD_TMP"
  tar -tf "$CURL_DOWNLOAD_TMP" >/dev/null
  mv "$CURL_DOWNLOAD_TMP" "$CURL_TARBALL_PATH"
  trap - EXIT
fi
tar -xvf "$CURL_TARBALL_PATH" -C /usr/bin
