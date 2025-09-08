#!/bin/bash
set -x
OS_ARCH="$(uname -m)"
wget -t 2 https://github.com/stunnel/static-curl/releases/download/8.15.0/curl-linux-"${OS_ARCH}"-glibc-8.15.0.tar.xz
tar -xvf ./curl-linux-"${OS_ARCH}"-glibc-8.15.0.tar.xz
cp curl /usr/bin/curl