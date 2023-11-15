#!/bin/bash
#
# pinning_relative_test.sh -- script to test relative core pinning.
#
#
DOCKER_CONTAINER_NAME="vpp_relative_pinning"
CONTAINER_CPU_RANGE="4-7"
MAIN_CORE="0"
VPP_SOCK_PATH=/run/vpp


if [ ! $WS_ROOT ]
then
	WS_ROOT="$(dirname $(readlink -e "../../../vpp"))/$(basename "../../../vpp")"
fi

# Get available CPU count on host machine
cpulist=$(cat /sys/devices/system/cpu/online)
startcpu="${cpulist%-*}"
endcpu="${cpulist#*\-}"
cpucount="$(($endcpu - $startcpu + 1))"

if [ $cpucount -lt 8 ]
then
	echo "Current host machine has $cpucount CPUs"
    echo "A minimum of 8 CPUs is required to run testcases, exiting.."
    exit 1
fi

# Check that container 'vpp_relative_pinning' does not already exist
count=$(docker ps | grep -c "$DOCKER_CONTAINER_NAME")

if [ $count -ne 0 ]
then
	echo "Error: docker container $DOCKER_CONTAINER_NAME already exists"
	echo "Remove it using 'docker stop/docker rm', then re-run test"
	exit 1
fi

mkdir -p $VPP_SOCK_PATH
results=""

for CORELIST_WORKERS in "1" "1-3" "1,3" ; do

	# TODO - Iterate through combination of: main-core, corelist-workers, workers, skip-core
	# TODO - Shorten this to not surpass line limit
	results="VPP with 'cpu {main-core ${MAIN_CORE} corelist-workers ${CORELIST_WORKERS} relative}'....." 
	(docker run -d --cpuset-cpus $CONTAINER_CPU_RANGE --name="$DOCKER_CONTAINER_NAME" \
	-e LD_LIBRARY_PATH="/vpp/build-root/build-vpp_debug-native/vpp/lib/x86_64-linux-gnu/" -v $VPP_SOCK_PATH:$VPP_SOCK_PATH \
	-v $WS_ROOT:/vpp  ubuntu:22.04 sh -c "/vpp/build-root/build-vpp_debug-native/vpp/bin/vpp unix {interactive \
	nodaemon cli-listen $VPP_SOCK_PATH/cli.sock} cpu {main-core ${MAIN_CORE} corelist-workers ${CORELIST_WORKERS} relative} plugins \
	{ plugin dpdk_plugin.so {disable } }"  > /dev/null)

	sleep 3 # wait for VPP to initialize socket


	# Change access permissions on vpp cli socket
	docker exec -it "$DOCKER_CONTAINER_NAME" /bin/bash -c "chmod 777  $VPP_SOCK_PATH/cli.sock"  > /dev/null

	# check if vppctl can connect to vpp container instance
	$WS_ROOT/build-root/build-vpp_debug-native/vpp/bin/vppctl -s $VPP_SOCK_PATH/cli.sock show threads  1> /dev/null

	rc=$?
	if [ $rc -eq 0 ]
	then
		results="$results : Test Successful" 
	else
		results="$results : Test Failed" 
	fi
	echo $results

	# Stop & destroy container instance
	docker stop $DOCKER_CONTAINER_NAME  &> /dev/null
	docker rm -f $DOCKER_CONTAINER_NAME &> /dev/null
done
