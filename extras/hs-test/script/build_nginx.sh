#!/bin/bash
cd nginx || exit 1
./auto/configure --with-debug --with-http_v3_module --with-cc-opt="-I../boringssl/include" --with-ld-opt="-L../boringssl/build/ssl -L../boringssl/build/crypto" --without-http_rewrite_module --without-http_gzip_module
make
make install
