#!/bin/bash
set -eux
OS_ARCH="$(uname -m)"
CURL_VERSION="8.18.0"
CURL_TARBALL=curl-linux-"${OS_ARCH}"-glibc-"$CURL_VERSION".tar.xz
CURL_TARBALL_PATH=/var/cache/downloads/"$CURL_TARBALL"
if [ ! -s "$CURL_TARBALL_PATH" ] ; then
  wget -t 2 https://github.com/stunnel/static-curl/releases/download/"$CURL_VERSION"/"$CURL_TARBALL" -O "$CURL_TARBALL_PATH"
fi
tar -xvf "$CURL_TARBALL_PATH" -C /usr/bin
