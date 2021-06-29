#!/bin/bash
#set -x
# packetdrill_test.sh
#
#   Run packetdrill test case.
#

# Configuration variables
# Comment out the next line to run the VPP release version
debug="_debug"

# ip address on vpp side
local_ip=10.10.1.2
# ip address on host side
remote_ip=10.10.1.1
# port on vpp size
local_port=32586
# port on remote side
remote_port=32586

script_path=$(dirname $(readlink -f "$0"))
tc_path=$script_path/test-case
pd_path=$script_path/packetdrill
so_path=$script_path/vpp_adapter
vpp_path=$(dirname $(dirname $(dirname  $script_path)))/build-root/install-vpp${debug}-native/vpp
unix_sock="/run/vpp/pd_test.sock"

# Detect if VPP is running
detect_vpp () {
	pid=$(ps -aux | grep vpp | grep pdstartup.conf | grep -v "grep" | awk '{print $2}')
	if [ "$pid" != "" ]; then
		return 1
	fi
		return 0
}

# Create veth pair in the host namespace, assign an IP address on host-side veth
create_veth(){
	if ip link show vppvethout  >/dev/null 2>&1 ;then
		return
	fi

	ip link add name vppvethout type veth peer name vppvethhost
	ip link set dev vppvethout up
	ip link set dev vppvethhost up
	ip addr add $remote_ip/24 dev vppvethhost

	if [ $? -ne 0 ]; then
		echo "failed to create veth-pair"
		exit 1
	fi
}

# Config veth pair in VPP
config_veth(){
	if $vpp_path/bin/vppctl -s $unix_sock show int | grep host-vppvethout >/dev/null 2>&1 ; then
		return
	else
		$vpp_path/bin/vppctl -s $unix_sock create host-interface name vppvethout  hw-addr  ee:ff:ff:ff:ff:ff >/dev/null 2>&1
		$vpp_path/bin/vppctl -s $unix_sock set int state host-vppvethout up >/dev/null 2>&1
		$vpp_path/bin/vppctl -s $unix_sock set int ip address host-vppvethout $local_ip/24 >/dev/null 2>&1
		$vpp_path/bin/vppctl -s $unix_sock ping $remote_ip >/dev/null 2>&1
	fi
}

# Delete veth pair
delete_veth() {
	if ip link show vppvethout >/dev/null 2>&1 ;then
		ip link delete vppvethout
	fi
}

# Startup VPP
start_vpp(){
	if [ ! -d "$vpp_path" ]; then
		echo "vpp isn't built"
		exit 1
	fi


	if [  ! -e "$unix_sock" ]; then
		LD_LIBRARY_PATH=$vpp_path/lib  $vpp_path/bin/vpp -c $script_path/pdstartup.conf &

		# wait for vpp startup complete
		sleep 5s
		while [ ! -e "$unix_sock" ];
		do
			echo "vpp is not running yet..."
			sleep 2
		done

		config_veth
	fi

}

# Control VPP
ctrl_vpp(){
	detect_vpp
		if [ $? -eq 1 ]; then
			shift
			$vpp_path/bin/vppctl -s $unix_sock $@
		else
			echo "vpp is not running"
		fi
}

# Stop VPP
stop_vpp(){
	#kill vpp process
	detect_vpp
	if [ $? -eq 1 ]; then
		kill -9 $pid
		echo "vpp stop successful"
	else
		echo "vpp is not running"
	fi
	delete_veth
	rm -rf $unix_sock
}

# Run packetdrill test case
run_test(){
	if [ ! -e "$pd_path/gtests/net/packetdrill/packetdrill" ]; then
		echo "You need to build packetdrill first. Please read README.md"
		exit 1
	fi
	if [ ! -e "$so_path/vpp_adapter.so" ]; then
		echo "You need to build vpp_adapter.so first. Please read README.md "
		exit 1
	fi

	test_cases=(
		"close/close-remote-fin-then-close.pkt"
		"close/close-local-close-then-remote-fin.pkt"
		"blocking/blocking-accept.pkt"
		"blocking/blocking-connect.pkt"
		"blocking/blocking-read.pkt"
		"shutdown/shutdown-rd-close.pkt"
		"shutdown/shutdown-wr-close.pkt"
		"shutdown/shutdown-rdwr-close.pkt"
		"shutdown/shutdown-rd-wr-close.pkt"
		"epoll/epoll_in_edge.pkt"
		"ts_recent/fin_tsval.pkt"
		"ts_recent/reset_tsval.pkt"
	)

	iptables -t filter -A INPUT -s $local_ip -jDROP
	for value in ${test_cases[@]}
		do
			echo -e "\n"
		echo starting $value
		LD_PRELOAD=$vpp_path/lib/libvcl_ldpreload.so VCL_CONFIG=$script_path/vcl.conf  VCL_DEBUG=1 $pd_path/gtests/net/packetdrill/packetdrill --local_ip=$local_ip --remote_ip=$remote_ip --bind_port=$local_port --connect_port=$remote_port --so_filename=$so_path/vpp_adapter.so $tc_path/tcp/$value
		echo  ending $value
		echo -e "\n"
		# The test may make different to next test, so sleep to avoid influencing
			sleep 5
		done
	iptables -t filter -D INPUT -s $local_ip -jDROP
}

case $1 in
	createVeth)
		create_veth
		;;
	deleteVeth)
		delete_veth
		;;
	startVpp)
		start_vpp
		;;
	stopVpp)
		stop_vpp
		;;
	ctrlVpp)
		ctrl_vpp $@
		;;
	runTest)
		run_test
		;;
	*)

	echo "Usage: $0 {createVeth | deleteVeth | startVpp | stopVpp | ctrlVpp | runTest}"

	exit 1
	;;
esac

exit 0

