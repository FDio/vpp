#!/bin/bash
#
# pinning_relative_test.sh -- script to test relative core pinning.
#
#
DOCKER_CONTAINER_NAME="vpp_relative_pinning"
VPP_SOCK_PATH=/run/vpp
CONTAINER_CPU_RANGE="4-7"
TEST_SUCCESS=0
TEST_FAIL=0

if [ ! $WS_ROOT ]
then
	WS_ROOT="$(dirname $(readlink -e "../../../vpp"))/$(basename "../../../vpp")"
fi

# Get available CPU count on host machine
host_cpulist=$(cat /sys/devices/system/cpu/online)
startcpu="${host_cpulist%-*}"
endcpu="${host_cpulist#*\-}"
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

# Check that there is no vpp instance currently running on the machine
count=$(pgrep vpp | wc -l)

if [ $count -ne 0 ]
then
	echo "Error: a vpp instance is currently running on this machine"
	echo "Please stop the running instance, then re-run test"
	exit 1
fi

mkdir -p $VPP_SOCK_PATH

# Function to parse corelist range to an array
# e.g. "0,3-5,7" is parsed to ('0','3','4','5','7')
parse_corelist () {
    corelist_args=$1
    corelist_args=$(echo $corelist_args | grep -Po '[0-9]+-[0-9]+|[0-9]+')
    corelist_parsed=()
    for corelist_elt in ${corelist_args[@]};do
        if [ $(echo $corelist_elt | grep -Po '[0-9]+-[0-9]+') ]
        then
            startcpu="${corelist_elt%-*}"
            endcpu="${corelist_elt#*\-}"
            cpucount="$(($endcpu - $startcpu))"

            for ((i=0;i<=$cpucount;i++)); do
              corelist_parsed+=" $(($i+$startcpu))"
            done
        elif [ $(echo $corelist_elt | grep -Po '[0-9]+') ]
        then
            corelist_parsed+=" ${corelist_elt}"
        fi
    done

    echo $corelist_parsed
}

test_pinning_conf () {
	if [ -z "$RELATIVE_PINNING" ];
	then
		VPP_EXTRA_CPU_PARAMS=""
	else
		VPP_EXTRA_CPU_PARAMS="relative"
	fi

	echo "TEST - conf 'cpu {main-core ${MAIN_CORE} corelist-workers ${CORELIST_WORKERS} ${VPP_EXTRA_CPU_PARAMS}}'"


	if [ -z "$CONTAINER_RESTRAIN_CPUSET" ];
	then
		VPP_CONTAINER_CPUSET=""
		echo "(Running vpp in container with full host cpuset $host_cpulist)"
	else
		VPP_CONTAINER_CPUSET="--cpuset-cpus $CONTAINER_CPU_RANGE"
		echo "(Running vpp in container with limited cpuset $CONTAINER_CPU_RANGE)"
	fi


	(docker run -d ${VPP_CONTAINER_CPUSET} --name="$DOCKER_CONTAINER_NAME" \
	-e LD_LIBRARY_PATH="/vpp/build-root/build-vpp_debug-native/vpp/lib/x86_64-linux-gnu/" -v $VPP_SOCK_PATH:$VPP_SOCK_PATH \
	-v $WS_ROOT:/vpp  ubuntu:22.04 sh -c "/vpp/build-root/build-vpp_debug-native/vpp/bin/vpp unix {interactive \
	nodaemon cli-listen $VPP_SOCK_PATH/cli.sock} cpu {main-core ${MAIN_CORE} corelist-workers ${CORELIST_WORKERS} ${VPP_EXTRA_CPU_PARAMS}} plugins \
	{ plugin dpdk_plugin.so {disable } }" > /dev/null )

	sleep 3 # wait for VPP to initialize socket

	# Change access permissions on vpp cli socket
	# docker exec -it "$DOCKER_CONTAINER_NAME" /bin/bash -c "chmod 777  $VPP_SOCK_PATH/cli.sock"  > /dev/null

	# check if vppctl can connect to vpp container instance
	$WS_ROOT/build-root/build-vpp_debug-native/vpp/bin/vppctl -s $VPP_SOCK_PATH/cli.sock show threads  1> /dev/null

	# get CPUs vpp instance in container is running on
	taskset_vpp_cpus=($( taskset --all-tasks -pc $(pgrep vpp) | grep -e ".$" -o))
	rc=$?

	# parse list of user requested CPUs for vpp
	requested_cpus=()
	requested_cpus+=(${MAIN_CORE})
	requested_cpus+=($(parse_corelist ${CORELIST_WORKERS}))


	# parse list of expected CPUs used by vpp
	# relative pinning on : Expected CPUs = Mapping of User Requested CPUs relative to Container CPUs
	# relative pinning off: Expected CPUs = User Requested CPUs
	expected_cpu_mapping=()
	if [ -z "$RELATIVE_PINNING" ];
	then
		expected_cpu_mapping=("${requested_cpus[@]}")
	else
		echo "CPUs available on container: [${container_cpus[@]}]"
		for k in ${requested_cpus[@]}; do
			expected_cpu_mapping+=(${container_cpus[ $k ]})
		done
	fi

	echo "CPUs requested by user:      [${requested_cpus[@]}]"
	echo "--------------------"
	echo "Expected CPU Mapping:        [${expected_cpu_mapping[@]}]"
	echo "VPP pinning (taskset):       [${taskset_vpp_cpus[@]}]"

	failure_cond=""
	if [ -z "$RELATIVE_PINNING" ];
	then
		for index in ${!taskset_vpp_cpus[@]}; do
		if [ ${taskset_vpp_cpus[$index]} -ne  ${requested_cpus[ $index ]} ]
		then
			echo "Test Failed"
			echo "=============================================="
			failure_cond="t"
		fi
	done
	else
		for index in ${!taskset_vpp_cpus[@]}; do
			req_cpu="${requested_cpus[$index]}"
			if [ ${taskset_vpp_cpus[$index]} -ne  ${container_cpus[ $req_cpu ]} ]
			then
				echo "Test Failed"
				echo "=============================================="
				failure_cond="t"
			fi
		done
	fi


	if [ $rc -eq 0 ] || [ -z "$failure_cond" ]
	then
		echo "Test Successful"
	else
		echo "Test Failed"
	fi
	echo "=============================================="

	# Stop & destroy container instance
	docker stop $DOCKER_CONTAINER_NAME  &> /dev/null
	docker rm -f $DOCKER_CONTAINER_NAME &> /dev/null
}

test_invalid_conf () {

	if [ -z "$RELATIVE_PINNING" ];
	then
		VPP_EXTRA_CPU_PARAMS=""
	else
		VPP_EXTRA_CPU_PARAMS="relative"
	fi

	echo "TEST - conf 'cpu {main-core ${MAIN_CORE} corelist-workers ${CORELIST_WORKERS} ${VPP_EXTRA_CPU_PARAMS}}'"


	if [ -z "$CONTAINER_RESTRAIN_CPUSET" ];
	then
		VPP_CONTAINER_CPUSET=""
		echo "(Running vpp in container with full host cpuset $host_cpulist)"
	else
		VPP_CONTAINER_CPUSET="--cpuset-cpus $CONTAINER_CPU_RANGE"
		echo "(Running vpp in container with limited cpuset $CONTAINER_CPU_RANGE)"
	fi

	(docker run -d --cpuset-cpus $CONTAINER_CPU_RANGE --name="$DOCKER_CONTAINER_NAME" \
	-e LD_LIBRARY_PATH="/vpp/build-root/build-vpp_debug-native/vpp/lib/x86_64-linux-gnu/" -v $VPP_SOCK_PATH:$VPP_SOCK_PATH \
	-v $WS_ROOT:/vpp  ubuntu:22.04 sh -c "/vpp/build-root/build-vpp_debug-native/vpp/bin/vpp unix {interactive \
	nodaemon cli-listen $VPP_SOCK_PATH/cli.sock} cpu {main-core ${MAIN_CORE} corelist-workers ${CORELIST_WORKERS} ${VPP_EXTRA_CPU_PARAMS}} plugins \
	{ plugin dpdk_plugin.so {disable } }"  > /dev/null)

	sleep 3 # wait for vpp to initialize socket

	# check if vpp has been launched
	taskset --all-tasks -pc $(pgrep vpp) &> /dev/null

	rc=$?
	if [ $rc -eq 1 ]
	then
		echo "Success (VPP did not launch with wrong conf)"
	else
		echo "Failure (VPP launched with wrong conf)"
	fi
	echo "=============================================="

	# Stop & destroy container instance
	docker stop $DOCKER_CONTAINER_NAME  &> /dev/null
	docker rm -f $DOCKER_CONTAINER_NAME &> /dev/null
}

run_tests () {

	# Construct relative mapping vector between host cpus and container cpus

	container_cpus=($(parse_corelist ${CONTAINER_CPU_RANGE}))


	echo "Testing correct core pinning configurations..."

	RELATIVE_PINNING=""
	CONTAINER_RESTRAIN_CPUSET=""

	# Test case A
	CORELIST_WORKERS="1-3"
	MAIN_CORE="0"
	test_pinning_conf

	# Test case B
	CORELIST_WORKERS="0,2-3"
	MAIN_CORE="1"
	test_pinning_conf

	# Test case C
	CORELIST_WORKERS="0-2"
	MAIN_CORE="3"
	test_pinning_conf

	echo "Testing relative core pinning configurations..."

	RELATIVE_PINNING="t"
	CONTAINER_RESTRAIN_CPUSET="t"

	# Test case A
	CORELIST_WORKERS="1-3"
	MAIN_CORE="0"
	test_pinning_conf

	# Test case B
	CORELIST_WORKERS="0,2-3"
	MAIN_CORE="1"
	test_pinning_conf

	# Test case C
	CORELIST_WORKERS="0-2"
	MAIN_CORE="3"
	test_pinning_conf

	echo "Testing incorrect core pinning configurations..."

	RELATIVE_PINNING=""
	CONTAINER_RESTRAIN_CPUSET="t"

	CORELIST_WORKERS="1-3"
	MAIN_CORE="0"
	test_invalid_conf

	RELATIVE_PINNING=""
	CONTAINER_RESTRAIN_CPUSET=""

	CORELIST_WORKERS="0-2"
	MAIN_CORE="1"
	test_invalid_conf

	CORELIST_WORKERS="4-7"
	MAIN_CORE="5"
	test_invalid_conf


	CORELIST_WORKERS="0-2"
	MAIN_CORE="1"
	test_invalid_conf
}

run_tests
