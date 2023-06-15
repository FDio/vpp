#!/bin/bash
cd curl
autoreconf -fi
LDFLAGS="-Wl,-rpath,${1}/lib64" ./configure --with-openssl=${1} --with-nghttp3=${2} --with-ngtcp2=${3}
make
make install
