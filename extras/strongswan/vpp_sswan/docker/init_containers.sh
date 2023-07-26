#!/bin/bash

DOCKER_IMAGE_NAME="vppstrongswan"
DOCKER_IMAGE_TAG="1.0"
DOCKER_IMAGE_NAME_FULL="$DOCKER_IMAGE_NAME:$DOCKER_IMAGE_TAG"

if [ "_$1" == "_build_docker_image" ];
then
	count=`docker image list | grep -c "$DOCKER_IMAGE_NAME.*$DOCKER_IMAGE_TAG"`
	if [ $count -ne 0 ];
	then
		echo "Error: docker image $DOCKER_IMAGE_NAME_FULL already exists"
		echo "Re-use it or remove to build new image"
		exit 0
	else
		echo "### Building docker image $DOCKER_IMAGE_NAME ..."
                cd ../ && docker build -t $DOCKER_IMAGE_NAME_FULL -f ./docker/Dockerfile .
                echo "### Building docker image $DOCKER_IMAGE_NAME finished"
	fi
elif [ "_$1" == "_create_docker1" ];
then
        if [ "_$2" == "_" ];
	then
		exit 1
	fi
	DOCKER_CONTAINER_NAME="$2"

	echo "### Creating container $DOCKER_CONTAINER_NAME"
	docker run -itd --name="$DOCKER_CONTAINER_NAME" --privileged --cap-add=ALL -p 8022:22 -v /mnt/huge:/mnt/huge -v /sys/bus/pci/devices:/sys/bus/pci/devices -v /sys/devices/system/node:/sys/devices/system/node -v /lib/modules:/lib/modules -v /dev:/dev --tmpfs /tmp --tmpfs /run --tmpfs /run/lock -v /sys/fs/cgroup:/sys/fs/cgroup:ro "$DOCKER_IMAGE_NAME_FULL"
        if [ $? -eq 0 ];
	then
            docker exec -i "$DOCKER_CONTAINER_NAME" "/root/init_docker1.sh" || { echo "call init_docker1.sh failed"; exit 127; }
	fi
        echo "### Creating container $DOCKER_CONTAINER_NAME finished"
	exit 0
elif [ "_$1" == "_create_docker2" ];
then
        if [ "_$2" == "_" ];
	then
		exit 1
	fi
	DOCKER_CONTAINER_NAME="$2"

	echo "### Creating container $DOCKER_CONTAINER_NAME"
	docker run -itd --name="$DOCKER_CONTAINER_NAME" --privileged --cap-add=ALL -p 8023:22 -v /mnt/huge:/mnt/huge -v /sys/bus/pci/devices:/sys/bus/pci/devices -v /sys/devices/system/node:/sys/devices/system/node -v /lib/modules:/lib/modules -v /dev:/dev --tmpfs /tmp --tmpfs /run --tmpfs /run/lock -v /sys/fs/cgroup:/sys/fs/cgroup:ro "$DOCKER_IMAGE_NAME_FULL"
        if [ $? -eq 0 ];
	then
            docker exec -i "$DOCKER_CONTAINER_NAME" "/root/init_docker2.sh" || { echo "call init_docker2.sh failed"; exit 127; }
            fi
	echo "### Creating container $DOCKER_CONTAINER_NAME finished"
        exit 0
elif [ "_$1" == "_clean" ];
then
        if [ "_$2" == "_" ];
	then
		exit 1
	fi
	DOCKER_CONTAINER_NAME="$2"

	echo "### Deleting container $DOCKER_CONTAINER_NAME"
	sudo docker rm -f $DOCKER_CONTAINER_NAME
        echo "### Deleting container $DOCKER_CONTAINER_NAME finished"
        exit 0
elif [ "_$1" == "_clean_image" ];
then
	echo "### Deleting image $DOCKER_IMAGE_NAME_FULL"
	sudo docker rmi -f $DOCKER_IMAGE_NAME_FULL
        echo "### Deleting image $DOCKER_IMAGE_NAME_FULL finished"
        exit 0
fi
