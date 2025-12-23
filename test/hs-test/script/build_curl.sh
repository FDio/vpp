#!/bin/bash
set -x
OS_ARCH="$(uname -m)"
CURL_VERSION="8.17.0"
CURL_TARBALL=curl-linux-"${OS_ARCH}"-glibc-"$CURL_VERSION".tar.xz
DOWNLOADS_DIR=~/Downloads
mkdir -p "$DOWNLOADS_DIR"
pushd "$DOWNLOADS_DIR"
if [ ! -f "$CURL_TARBALL" ] ; then
  wget -t 2 https://github.com/stunnel/static-curl/releases/download/"$CURL_VERSION"/"$CURL_TARBALL"
fi
tar -xvf ./"$CURL_TARBALL"
cp curl /usr/bin/curl
popd
