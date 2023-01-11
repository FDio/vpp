#!/usr/bin/env bash

source vars

docker build --build-arg UBUNTU_VERSION -t hs-test/build -f Dockerfile.build ../../

docker build --build-arg UBUNTU_VERSION -t hs-test/vpp -f Dockerfile.vpp .
docker build --build-arg UBUNTU_VERSION -t hs-test/nginx-ldp -f Dockerfile.nginx .
