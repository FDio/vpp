#!/bin/bash
cd nghttp3
autoreconf -fi
./configure --prefix=${1} --enable-lib-only
make
make install
