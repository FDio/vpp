#!/usr/bin/env bash

source vars

docker build --build-arg UBUNTU_VERSION -t hs-test/build -f Dockerfile.build ../../

docker build --build-arg UBUNTU_VERSION -t hs-test/vpp -f Dockerfile.vpp .
docker build --build-arg UBUNTU_VERSION -t hs-test/nginx-ldp -f Dockerfile.nginx .

mkdir -p ${bin} ${lib} || true

container_id=$(docker create hs-test/build)
docker cp ${container_id}:/vpp/build-root/build-vpp_debug-native/vpp/bin ./vpp-data/
docker cp ${container_id}:/vpp/build-root/build-vpp_debug-native/vpp/lib/x86_64-linux-gnu ${lib}/
docker rm $container_id
