#! /bin/bash
#
# nginx_test.sh
#
#   Run specified app using LD_PRELOAD to fetch a page from
#   nginx running in vpp1 net-namespace.
#
# Specify the following environment variables:
#
# STRACE_ONLY - Run app with strace instead of LD_PRELOAD.
# TEST_APP    - App to run (default: curl)
# 

# Configuration variables.
#
vpp_dk_name="NGINX"
# Comment out the next line to run the VPP release version
debug="_debug"
vpp_app="$WS_ROOT/build-root/install-vpp${debug}-native/vpp/bin/vpp"

check_for_vpp() {
    local grep_for_vpp="ps -eaf|grep -v grep|grep \"bin/vpp\""
    running_vpp="$(eval $grep_for_vpp)"
}

# Verify Environment.
if [ -z "$WS_ROOT" ] ; then
    echo "ERROR: WS_ROOT environment variable not set!" >&2
    echo "       Please set WS_ROOT to VPP workspace root directory." >&2
    exit 1
fi

if [ -z "$VCL_LDPRELOAD_LIB_DIR" ] ; then
    echo "ERROR: VCL_LDPRELOAD_LIB_DIR environment variable not set!" >&2
    echo "       Please set VCL_LDPRELOAD_LIB_DIR to " >&2
    echo "       $WS_ROOT/build-root/install-vpp[_debug]-native/vpp/lib64." >&2
    exit 1
fi

TEST_APP="${TEST_APP:-curl}"
LDP_DIR="${WS_ROOT}/extras/vcl-ldpreload"
LDP_TEST_DIR="${LDP_TEST_DIR:-${LDP_DIR}/test}"
LDP_LIB="${LDP_LIB:-${VCL_LDPRELOAD_LIB_DIR}/libvcl_ldpreload.so.0.0.0}"

if [ ! -f "$LDP_LIB" ] ; then
    echo "ERROR: Missing VCL-LDPRELOAD Library: $LDP_LIB"
    echo "       Run 'cd $WS_ROOT; make build[-release] ' !"
    exit 1
fi

if [ -n "$STRACE_ONLY" ] ; then
    echo "Running strace -tt $TEST_APP http://$nginx_addr"
    strace -tt $TEST_APP http://$nginx_addr
else
    check_for_vpp
    if [ -z "$running_vpp" ] ; then
        echo -e "\nConfiguring network interfaces"
        sudo ip link del dev vpp_dk
        sudo ip link add name vpp_dk type veth peer name vpp1
        sudo ip link set dev vpp_dk up
        sudo ethtool --offload vpp_dk rx off tx off
        sudo ip link set dev vpp1 up
        sudo ethtool --offload vpp1 rx off tx off
        sudo ip link set dev lo up
        sudo brctl addif docker0 vpp_dk
        
        echo "Starting VPP "
        sudo rm -f /dev/shm/*
        sudo xfce4-terminal --title VPP --command "$vpp_app unix { interactive exec $LDP_TEST_DIR/common/vpp_docker.conf full-coredump coredump-size unlimited } api-segment { gid $(id -g) }" &
#        sudo $vpp_app unix { cli-listen localhost:5002 exec $LDP_TEST_DIR/common/vpp_docker.conf } api-segment { gid $(id -g) }
        sleep 4
    fi

    if [ -z "$(docker ps -qf name=$vpp_dk_name)" ] ; then
        echo -e "\nStarting NGINX in docker container ($vpp_dk_name)"
        echo "docker run --rm --name $vpp_dk_name -v $LDP_TEST_DIR/common/nginx_welcome.html:/usr/share/nginx/html/index.html:ro -d nginx"
        docker run --rm --name $vpp_dk_name -v $LDP_TEST_DIR/common/nginx_welcome.html:/usr/share/nginx/html/index.html:ro -d nginx
        
        export LD_LIBRARY_PATH="$WS_ROOT/build-root/install-vpp${debug}-native/vpp/lib64/:$LDP_DIR/src/.libs:"

        # Extract nginx IPv4 address from docker bridge
        #
        nginx_addr=$(docker network inspect bridge | grep IPv4Address | awk -e '{print $2}' | sed -e 's,/16,,' -e 's,",,g' -e 's/,//')
        
        if [ -z "$nginx_addr" ] ; then
            echo "ERROR: Unable to determine docker container address!"
            exit 1
        fi
    fi
    
    echo -e "\nRunning wget"
    echo -e "LD_PRELOAD=$LDP_LIB $TEST_APP http://$nginx_addr\n"
    LD_PRELOAD=$LDP_LIB $TEST_APP http://$nginx_addr
fi
