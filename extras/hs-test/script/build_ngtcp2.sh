#!/bin/bash
cd ngtcp2
autoreconf -fi
./configure PKG_CONFIG_PATH=${1}/lib64/pkgconfig:${2}/lib/pkgconfig LDFLAGS="-Wl,-rpath,${1}/lib64" --prefix=${3} --enable-lib-only
make
make install
