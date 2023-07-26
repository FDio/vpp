#!/bin/bash

DOCKER_1_NAME="vpp_sswan_docker_1"
DOCKER_2_NAME="vpp_sswan_docker_2"

if [ "_$1" == "_prepare_containers" ];
then
        echo "### Building docker image for vpp sswan plugin"
        ./init_containers.sh build_docker_image
        echo "### Building the first container for vpp sswan plugin"
        ./init_containers.sh create_docker1 $DOCKER_1_NAME
        echo "### Building the second container for vpp sswan plugin"
        ./init_containers.sh create_docker2 $DOCKER_2_NAME
elif [ "_$1" == "_config_policy" ];
then
        echo "### Configuration $DOCKER_1_NAME and $DOCKER_2_NAME"
        #ADD 1: set network namespace
        echo "### Adding network namespace for $DOCKER_1_NAME and $DOCKER_2_NAME"
        ip netns add vpp_sswan_temp
        ./exposedockernetns.sh $DOCKER_1_NAME
        ./exposedockernetns.sh $DOCKER_2_NAME
        ip netns del vpp_sswan_temp
        echo "### Adding network namespace for $DOCKER_1_NAME and $DOCKER_2_NAME finished"

        #ADD 2: settings network
        echo "### Setting network for $DOCKER_1_NAME and $DOCKER_2_NAME"

        ip link add docker_1_eth2 type veth peer name docker_2_eth2
        ip link set netns $DOCKER_1_NAME dev docker_1_eth2
        ip link set netns $DOCKER_2_NAME dev docker_2_eth2
        #ADD 3: ip address
        ip netns exec $DOCKER_2_NAME ip addr add 192.168.0.1/24 dev docker_2_eth2
        ip netns exec $DOCKER_2_NAME ip link set dev docker_2_eth2 up

        #LAN for Docker 1
        ip link add docker_1a_eth1 type veth peer name docker_1b_eth1
        ip link set netns $DOCKER_1_NAME dev docker_1a_eth1
        ip link set netns $DOCKER_1_NAME dev docker_1b_eth1
        ip netns exec $DOCKER_1_NAME ip addr add 192.168.200.10/24 dev docker_1b_eth1
        ip netns exec $DOCKER_1_NAME ip link set dev docker_1b_eth1 up
        ip netns exec $DOCKER_1_NAME ip route add 192.168.100.0/24 via 192.168.200.1 dev docker_1b_eth1

        #LAN for Docker 2
        ip link add docker_2a_eth1 type veth peer name docker_2b_eth1
        ip link set netns $DOCKER_2_NAME dev docker_2a_eth1
        ip link set netns $DOCKER_2_NAME dev docker_2b_eth1
        ip netns exec $DOCKER_2_NAME ip addr add 192.168.100.1/24 dev docker_2a_eth1
        ip netns exec $DOCKER_2_NAME ip addr add 192.168.100.10/24 dev docker_2b_eth1
        ip netns exec $DOCKER_2_NAME ip link set dev docker_2a_eth1 up
        ip netns exec $DOCKER_2_NAME ip link set dev docker_2b_eth1 up
        ip netns exec $DOCKER_2_NAME ip route add 192.168.200.0/24 via 192.168.100.1 dev docker_2b_eth1

        echo "### Setting network for $DOCKER_1_NAME and $DOCKER_2_NAME finished"

        #install policy mode
        docker exec -i $DOCKER_1_NAME make -C /root/vpp/extras/strongswan/vpp_sswan/ install-policy
        docker exec -i $DOCKER_1_NAME cp /root/vpp/extras/strongswan/vpp_sswan/docker/configs/swanctl_docker_policy_1.conf /etc/swanctl/conf.d/swanctl.conf

        #ADD 4: run VPP on the first docker
        echo "### Running VPP and sswan on: $DOCKER_1_NAME and $DOCKER_2_NAME"
        docker exec -i "$DOCKER_1_NAME" "/root/run_vpp.sh"
        docker exec -d $DOCKER_2_NAME systemctl restart strongswan.service
        echo "### Running VPP and sswan on: $DOCKER_1_NAME and $DOCKER_2_NAME finished"

        #ADD 5: initiate sswan
        echo "### initiate SSWAN between $DOCKER_1_NAME and $DOCKER_2_NAME"
        docker exec -i $DOCKER_1_NAME swanctl --initiate --child net-net
        echo "### initiate SSWAN between $DOCKER_1_NAME and $DOCKER_2_NAME finished"

elif [ "_$1" == "_clean" ];
then
        #DELETE 5: initiate sswan
        echo "### Terminate SSWAN between $DOCKER_1_NAME and $DOCKER_2_NAME"
        docker exec -i $DOCKER_1_NAME swanctl --terminate --child net-net
        echo "### Terminate SSWAN between $DOCKER_1_NAME and $DOCKER_2_NAME finished"

        #DELETE 4: run VPP on the first docker
        echo "### Exit VPP on: $DOCKER_1_NAME"
        docker exec -d $DOCKER_1_NAME pkill -9 -f vpp
        echo "### Exit VPP on: $DOCKER_1_NAME finished"

        echo "### Deletting settings network for $DOCKER_1_NAME and $DOCKER_2_NAME"
        #DELETE 3: ip address
        ip netns exec $DOCKER_1_NAME ip link set dev docker_1_eth2 down
        ip netns exec $DOCKER_2_NAME ip link set dev docker_2_eth2 down
        #docker 1
        ip netns exec $DOCKER_1_NAME ip link set dev docker_1b_eth1 down
        ip netns exec $DOCKER_1_NAME ip link set netns 1 dev docker_1a_eth1
        ip netns exec $DOCKER_1_NAME ip link set netns 1 dev docker_1b_eth1
        ip link del docker_1a_eth1 type veth peer name docker_1b_eth1

        #docker 2
        ip netns exec $DOCKER_2_NAME ip link set dev docker_2a_eth1 down
        ip netns exec $DOCKER_2_NAME ip link set dev docker_2b_eth1 down
        ip netns exec $DOCKER_2_NAME ip link set netns 1 dev docker_2a_eth1
        ip netns exec $DOCKER_2_NAME ip link set netns 1 dev docker_2b_eth1
        ip link del docker_2a_eth1 type veth peer name docker_2b_eth1

        #DELETE 2: settings network
        ip netns exec $DOCKER_1_NAME ip link set netns 1 dev docker_1_eth2
        ip netns exec $DOCKER_2_NAME ip link set netns 1 dev docker_2_eth2
        ip link del docker_1_eth2 type veth peer name docker_2_eth2
        echo "### Deletting settings network for $DOCKER_1_NAME and $DOCKER_2_NAME finished"

        #DELETE 1: delete network namespace
        echo "### Deleting network namespace for $DOCKER_1_NAME and $DOCKER_2_NAME"
        ip netns del $DOCKER_1_NAME
        ip netns del $DOCKER_2_NAME
        echo "### Deleting network namespace for $DOCKER_1_NAME and $DOCKER_2_NAME finished"

elif [ "_$1" == "_deleted" ];
then
        echo "### Exit VPP on: $DOCKER_1_NAME"
        docker exec -d $DOCKER_1_NAME pkill -9 -f vpp
        echo "### Exit VPP on: $DOCKER_1_NAME finished"

        echo "### Deleting container $DOCKER_1_NAME and $DOCKER_2_NAME"
        ./init_containers.sh clean $DOCKER_1_NAME
        ./init_containers.sh clean $DOCKER_2_NAME
        echo "### Deleting image"
        ./init_containers.sh clean_image
fi
