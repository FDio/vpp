#!/bin/bash

dir1=/tmp/dir1
dir2=/tmp/dir2
dir3=/tmp/dir3

git clone --depth 1 -b openssl-3.0.9+quic https://github.com/quictls/openssl
cd openssl
echo "install path ${dir1}"
./config enable-tls1_3 --prefix=${dir1}
make
make install

cd ..
git clone -b v0.12.0 https://github.com/ngtcp2/nghttp3
cd nghttp3
autoreconf -fi
./configure --prefix=${dir2} --enable-lib-only
make
make install

cd ..
git clone -b v0.16.0 https://github.com/ngtcp2/ngtcp2
cd ngtcp2
autoreconf -fi
./configure PKG_CONFIG_PATH=${dir1}/lib64/pkgconfig:${dir2}/lib/pkgconfig LDFLAGS="-Wl,-rpath,${dir1}/lib64" --prefix=${dir3} --enable-lib-only
make
make install

cd ..
git clone https://github.com/curl/curl
cd curl
autoreconf -fi
LDFLAGS="-Wl,-rpath,${dir1}/lib64" ./configure --with-openssl=${dir1} --with-nghttp3=${dir2} --with-ngtcp2=${dir3}
make
make install
