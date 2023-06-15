#!/bin/bash
cd openssl
echo "install path ${1}"
./config enable-tls1_3 --prefix=${1}
make
make install
