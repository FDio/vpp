#!/bin/bash
set -x
wget https://github.com/stunnel/static-curl/releases/download/8.5.0/curl-static-"$TARGETARCH"-8.5.0.tar.xz
tar -xvf ./curl-static-"$TARGETARCH"-8.5.0.tar.xz
cp curl /usr/bin/curl