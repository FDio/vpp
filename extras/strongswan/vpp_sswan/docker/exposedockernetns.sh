#!/bin/bash

if [ "$1" == "" ]; then
        echo "usage: $0 <container_name>"
        echo "Exposes the netns of a docker container to the host"
        exit 1
fi

        pid=`docker inspect -f '{{.State.Pid}}' $1`
        ln -s /proc/$pid/ns/net /var/run/netns/$1

        echo "netns of ${1} exposed as /var/run/netns/${1}"

        #echo "try: ip netns exec ${1} ip addr list"
