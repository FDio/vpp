#!/usr/bin/env bash

source vars

docker build -t hs-test/buildhstest -f Dockerfile.buildhstest ../../
docker build -t hs-test/buildvpp -f Dockerfile.buildvpp ../../

docker build -t hs-test/vpp -f Dockerfile.vpp ../../
docker build -t hs-test/nginx-ldp -f Dockerfile.nginx .
