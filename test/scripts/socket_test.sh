#! /bin/bash
#
# socket_test.sh -- script to run socket tests.
#
script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
vpp_dir="$WS_ROOT/build-root/build-vpp-native/vpp/bin/"
vpp_debug_dir="$WS_ROOT/build-root/build-vpp_debug-native/vpp/bin/"
vpp_shm_dir="/dev/shm/"
vpp_run_dir="/run/vpp"
lib_dir="$WS_ROOT/build-root/install-vpp-native/vpp/lib/"
lib_debug_dir="$WS_ROOT/build-root/install-vpp_debug-native/vpp/lib/"
dpdk_devbind="$WS_ROOT/extras/vpp_config/scripts/dpdk-devbind.py"
docker_vpp_dir="/vpp/"
docker_app_dir="/vpp/"
docker_lib_dir="/vpp-lib/"
docker_os="ubuntu"
vcl_ldpreload_lib="libvcl_ldpreload.so"
user_gid="$(id -g)"
vpp_app="vpp"
sock_srvr_app="sock_test_server"
sock_clnt_app="sock_test_client"
sock_srvr_addr="127.0.0.1"
sock_srvr_port="22000"
iperf_srvr_app="iperf3 -V4d -s"
iperf_clnt_app="iperf3 -V4d -c \$srvr_addr"
gdb_in_emacs="gdb_in_emacs"
vcl_config="vcl.conf"
vcl_config_dir="$WS_ROOT/src/vcl/"
docker_vcl_config_dir="/etc/vpp/"
xterm_geom="100x60"
bash_header="#! /bin/bash"
tmp_cmdfile_prefix="/tmp/socket_test_cmd"
cmd1_file="${tmp_cmdfile_prefix}1.$$"
cmd2_file="${tmp_cmdfile_prefix}2.$$"
cmd3_file="${tmp_cmdfile_prefix}3.$$"
vpp_eth_name="enp0s8"
tmp_vpp_exec_file="/tmp/vpp_config.$$"
tmp_gdb_cmdfile_prefix="/tmp/gdb_cmdfile"
def_gdb_cmdfile_prefix="$WS_ROOT/extras/gdb/gdb_cmdfile"
tmp_gdb_cmdfile_vpp="${tmp_gdb_cmdfile_prefix}_vpp.$$"
tmp_gdb_cmdfile_client="${tmp_gdb_cmdfile_prefix}_vcl_client.$$"
tmp_gdb_cmdfile_server="${tmp_gdb_cmdfile_prefix}_vcl_server.$$"
get_docker_server_ip4addr='srvr_addr=$(docker network inspect bridge | grep IPv4Address | awk -e '\''{print $2}'\'' | sed -e '\''s,/16,,'\'' -e '\''s,",,g'\'' -e '\''s/,//'\'')'
#' single quote to fix the confused emacs colorizer.
trap_signals="SIGINT SIGTERM EXIT"

# Set default values for imported environment variables if they don't exist.
#
VPP_GDB_CMDFILE="${VPP_GDB_CMDFILE:-${def_gdb_cmdfile_prefix}.vpp}"
VPPCOM_CLIENT_GDB_CMDFILE="${VPPCOM_CLIENT_GDB_CMDFILE:-${def_gdb_cmdfile_prefix}.vppcom_client}"
VPPCOM_SERVER_GDB_CMDFILE="${VPPCOM_SERVER_GDB_CMDFILE:-${def_gdb_cmdfile_prefix}.vppcom_server}"

usage() {
    cat <<EOF
Usage: socket_test.sh OPTIONS TEST
TESTS:
  nk, native-kernel   Run server & client on host using kernel.
  nv, native-vcl      Run vpp, server & client on host using VppComLib.
  np, native-preload  Run vpp, server & client on host using LD_PRELOAD.
  dk, docker-kernel   Run server & client in docker using kernel stack.
  dv, docker-vcl      Run vpp on host, server & client in docker using VppComLib.
  dp, docker-preload  Run vpp on host, server & client in docker using LD_PRELOAD.

OPTIONS:
  -h                  Print this usage text.
  -l                  Leave ${tmp_cmdfile_prefix}* files after test run.
  -b                  Run bash after application exit.
  -d                  Run the vpp_debug version of all apps.
  -c                  Set VCL_CONFIG to use the vcl_test.conf file.
  -i                  Run iperf3 for client/server app in native tests.
  -n                  Name of ethernet for VPP to use in multi-host cfg.
  -f                  Full thru host stack vpp configuration. 
  -m c[lient]         Run client in multi-host cfg (server on remote host)
     s[erver]         Run server in multi-host cfg (client on remote host)
  -e a[ll]            Run all in emacs+gdb.
     c[lient]         Run client in emacs+gdb.
     s[erver]         Run server in emacs+gdb.
     v[pp]            Run vpp in emacs+gdb.
  -g a[ll]            Run all in gdb.
     c[lient]         Run client in gdb.
     s[erver]         Run server in gdb.
     v[pp]            Run vpp in gdb.
  -t                  Use tabs in one xterm if available (e.g. xfce4-terminal).

OPTIONS passed to client/server:
  -6                  Use IPv6.
  -D                  Use UDP as the transport.
  -S <ip address>     Server IP address.
  -P <server port>    Server Port number.
  -E <data>           Run Echo test.
  -N <num-writes>     Test Cfg: number of writes.
  -R <rxbuf-size>     Test Cfg: rx buffer size.
  -T <txbuf-size>     Test Cfg: tx buffer size.
  -U                  Run Uni-directional test.
  -B                  Run Bi-directional test.
  -I <num-tst-socks>  Send data over multiple test sockets in parallel.
  -V                  Test Cfg: Verbose mode.
  -X                  Exit client/server after running test.

Environment variables:
  VCL_CONFIG                Pathname of vppcom configuration file.
  VPP_GDB_CMDFILE            Pathname of gdb command file for vpp.
  VPPCOM_CLIENT_GDB_CMDFILE  Pathname of gdb command file for client.
  VPPCOM_SERVER_GDB_CMDFILE  Pathname of gdb command file for server.
EOF
    exit 1
}

declare -i emacs_vpp=0
declare -i emacs_client=0
declare -i emacs_server=0
declare -i gdb_vpp=0
declare -i gdb_client=0
declare -i gdb_server=0
declare -i perf_vpp=0
declare -i perf_client=0
declare -i perf_server=0
declare -i leave_tmp_files=0
declare -i bash_after_exit=0
declare -i iperf3=0
declare -i use_ipv6=0
declare -i transport_udp=0

while getopts ":hitlbcd6fn:m:e:g:p:E:I:N:P:R:S:T:UBVXD" opt; do
    case $opt in
        h) usage ;;
        l) leave_tmp_files=1
           ;;
        b) bash_after_exit=1
           ;;
        i) iperf3=1
           ;;
        6) use_ipv6=1
           sock_srvr_addr="::1"
           sock_clnt_options="$sock_clnt_options -$opt"
           sock_srvr_options="$sock_srvr_options -$opt"
           ;;
        f) full_thru_host_stack_vpp_cfg=1
           ;;
        t) xterm_geom="180x40"
           use_tabs="true"
           ;;
        c) VCL_CONFIG="${vcl_config_dir}vcl_test.conf"
           ;;
        d) title_dbg="-DEBUG"
           vpp_dir=$vpp_debug_dir
           lib_dir=$lib_debug_dir
           ;;
        e) if [ $OPTARG = "a" ] || [ $OPTARG = "all" ] ; then
               emacs_client=1
               emacs_server=1
               emacs_vpp=1
           elif [ $OPTARG = "c" ] || [ $OPTARG = "client" ] ; then
               emacs_client=1
           elif [ $OPTARG = "s" ] || [ $OPTARG = "server" ] ; then
               emacs_server=1
           elif [ $OPTARG = "v" ] || [ $OPTARG = "vpp" ] ; then
               emacs_vpp=1
           else
               echo "ERROR: Option -e unknown argument \'$OPTARG\'" >&2
               usage
           fi
           title_dbg="-DEBUG"
           vpp_dir=$vpp_debug_dir
           lib_dir=$lib_debug_dir
           ;;
        n) vpp_eth_name="$OPTARG"
           ;;
        m) if [ $OPTARG = "c" ] || [ $OPTARG = "client" ] ; then
               multi_host="client"
           elif [ $OPTARG = "s" ] || [ $OPTARG = "server" ] ; then
               multi_host="server"
           else
               echo "ERROR: Option -e unknown argument \'$OPTARG\'" >&2
               usage
           fi
           ;;
        g) if [ $OPTARG = "a" ] || [ $OPTARG = "all" ] ; then
               gdb_client=1
               gdb_server=1
               gdb_vpp=1
           elif [ $OPTARG = "c" ] || [ $OPTARG = "client" ] ; then
               gdb_client=1
           elif [ $OPTARG = "s" ] || [ $OPTARG = "server" ] ; then
               gdb_server=1
           elif [ $OPTARG = "v" ] || [ $OPTARG = "vpp" ] ; then
               gdb_vpp=1
           else
               echo "ERROR: Option -g unknown argument \'$OPTARG\'" >&2
               usage
           fi
           ;;
        p) if [ $OPTARG = "a" ] || [ $OPTARG = "all" ] ; then
               perf_client=1
               perf_server=1
               perf_vpp=1
           elif [ $OPTARG = "c" ] || [ $OPTARG = "client" ] ; then
               perf_client=1
           elif [ $OPTARG = "s" ] || [ $OPTARG = "server" ] ; then
               perf_server=1
           elif [ $OPTARG = "v" ] || [ $OPTARG = "vpp" ] ; then
               perf_vpp=1
           else
               echo "ERROR: Option -p unknown argument \'$OPTARG\'" >&2
               usage
           fi
           echo "WARNING: -p options TBD"
           ;;
        S) sock_srvr_addr="$OPTARG"
           ;;
        P) sock_srvr_port="$OPTARG"
           ;;
        D) sock_clnt_options="$sock_clnt_options -$opt"
           sock_srvr_options="$sock_srvr_options -$opt"
           ;;
E|I|N|R|T) sock_clnt_options="$sock_clnt_options -$opt \"$OPTARG\""
           ;;
  U|B|V|X) sock_clnt_options="$sock_clnt_options -$opt"
           ;;
       \?)
           echo "ERROR: Invalid option: -$OPTARG" >&2
           usage
           ;;
        :)
           echo "ERROR: Option -$OPTARG requires an argument." >&2
           usage
           ;;
    esac
done

shift $(( $OPTIND-1 ))
while ! [[ $run_test ]] && (( $# > 0 )) ; do
    case $1 in
        "nk" | "native-kernel")
            run_test="native_kernel" ;;
        "np" | "native-preload")
            run_test="native_preload" ;;
        "nv" | "native-vcl")
            sock_srvr_app="vcl_test_server"
            sock_clnt_app="vcl_test_client"
            run_test="native_vcl" ;;
        "dk" | "docker-kernel")
            run_test="docker_kernel" ;;
        "dp" | "docker-preload")
            run_test="docker_preload" ;;
        "dv" | "docker-vcl")
            sock_srvr_app="vcl_test_server"
            sock_clnt_app="vcl_test_client"
            run_test="docker_vcl" ;;
        *)
            echo "ERROR: Unknown option '$1'!" >&2
            usage ;;
    esac
    shift
done

if [ -z "$VCL_DEBUG" ] ; then
    if [ "$title_dbg" = "-DEBUG" ] ; then
        VCL_DEBUG=1
    else
        VCL_DEBUG=0
    fi
fi

VCL_LDPRELOAD_LIB_DIR="${VCL_LDPRELOAD_LIB_DIR:-$lib_dir}"

if [ -z "$WS_ROOT" ] ; then
    echo "ERROR: WS_ROOT environment variable not set!" >&2
    echo "       Please set WS_ROOT to VPP workspace root directory." >&2
    exit 1
fi

if [ ! -d $vpp_dir ] ; then
    if [ -z "$title_dbg" ] ; then
        (cd $WS_ROOT; make build-release)
    else
        (cd $WS_ROOT; make build)
    fi
fi

if [ ! -d $vpp_dir ] ; then
    echo "ERROR: Missing VPP$title_dbg bin directory!" >&2
    echo "       $vpp_dir" >&2
    env_test_failed="true"
fi

if [[ $run_test =~ .*"_preload" ]] ; then
   if [ ! -d $lib_dir ] ; then
       echo "ERROR: Missing VPP$title_dbg lib directory!" >&2
       echo "       $lib_dir" >&2
   elif [ ! -d $VCL_LDPRELOAD_LIB_DIR ] ; then
       echo "ERROR: Missing VCL LD_PRELOAD Library directory!" >&2
       echo "       $VCL_LDPRELOAD_LIB_DIR" >&2
       env_test_failed="true"
   elif [ ! -f $VCL_LDPRELOAD_LIB_DIR/$vcl_ldpreload_lib ] ; then
       echo "ERROR: Missing VCL LD_PRELOAD library!" >&2
       echo "       $VCL_LDPRELOAD_LIB_DIR/$vcl_ldpreload_lib" >&2
       env_test_failed="true"
   fi
fi

if [ ! -f $vpp_dir$vpp_app ] ; then
    echo "ERROR: Missing VPP$title_dbg Application!" >&2
    echo "       $vpp_dir$vpp_app" >&2
    env_test_failed="true"
fi

if [ ! -f $vpp_dir$sock_srvr_app ] && [ ! $iperf3 -eq 1 ] ; then
    echo "ERROR: Missing SERVER$title_dbg Socket Server Application!" >&2
    echo "       $vpp_dir$sock_srvr_app" >&2
    env_test_failed="true"
fi

if [ ! -f $vpp_dir$sock_clnt_app ] && [ ! $iperf3 -eq 1 ] ; then
    echo "ERROR: Missing CLIENT$title_dbg Socket Client Application!" >&2
    echo "       $vpp_dir$sock_clnt_app" >&2
    env_test_failed="true"
fi

if [[ $run_test =~ "docker_".* ]] ; then
    if [ $emacs_client -eq 1 ] || [ $emacs_server -eq 1 ] || [ $gdb_client -eq 1 ] || [ $gdb_server -eq 1 ] ; then
        
        echo "WARNING: gdb is not currently supported in docker."
        echo "         Ignoring client/server gdb options."
        emacs_client=0
        emacs_server=0
        gdb_client=0
        gdb_server=0
    fi
fi

if [[ $run_test =~ .*"_vcl" ]] && [ $iperf3 -eq 1 ] ; then
    echo "ERROR: Invalid option 'i' for test $run_test!"
    echo "       iperf3 is not compiled with the VCL library."
    env_test_failed="true"
fi

if [ -n "$multi_host"] && [ ! -f "$dpdk_devbind" ] ; then
    echo "ERROR: Can't find dpdk-devbind.py!"
    echo "       Run \"cd \$WS_ROOT; make install-ext-deps\" to install it."
    echo
    env_test_failed="true"
fi

if [ -n "$full_thru_host_stack_vpp_cfg" ] && [ -n "$multi_host" ] ; then
    echo "ERROR: Invalid options, cannot specify both \"-f\" and \"-m $multi_host\"!"
    echo
    env_test_failed="true"
fi

if [ -n "$env_test_failed" ] ; then
    exit 1
fi

if [ -f "$VCL_CONFIG" ] ; then
    vcl_config="$(basename $VCL_CONFIG)"
    vcl_config_dir="$(dirname $VCL_CONFIG)/"
    api_prefix="$(egrep -s '^\s*api-prefix \w+' $VCL_CONFIG | tail -1 | awk -e '{print $2}')"
    if [ -n "$api_prefix" ] ; then
        api_segment=" api-segment { gid $user_gid prefix $api_prefix }"
    fi
fi
if [ -n "$VCL_APP_NAMESPACE_ID" ] && [ -n "$VCL_APP_NAMESPACE_SECRET" ] ; then
    namespace_id="$VCL_APP_NAMESPACE_ID"
    namespace_secret="$VCL_APP_NAMESPACE_SECRET"
fi
    
if [ -z "$api_segment" ] ; then
    api_segment=" api-segment { gid $user_gid }"
fi
vpp_args="unix { interactive full-coredump coredump-size unlimited exec $tmp_vpp_exec_file}${api_segment}"

if [ $iperf3 -eq 1 ] ; then
    app_dir="$(dirname $(which iperf3))/"
    srvr_app=$iperf_srvr_app
    clnt_app=$iperf_clnt_app
    if [[ $run_test =~ "docker_".* ]] ; then
        unset -v app_dir
        sock_srvr_port=5201
        docker_app_dir="networkstatic/"
        unset -v docker_os
    fi
else
    app_dir="$vpp_dir"
    srvr_app="$sock_srvr_app${sock_srvr_options} $sock_srvr_port"
    clnt_app="$sock_clnt_app${sock_clnt_options} \$srvr_addr $sock_srvr_port"
fi


verify_no_vpp() {
    local grep_for_vpp="ps -eaf|grep -v grep|grep \"bin/vpp\""
    
    if [ -n "$api_prefix" ] ; then
        grep_for_vpp="$grep_for_vpp|grep \"prefix $api_prefix\""
    fi
    local running_vpp="$(eval $grep_for_vpp)"
    if [ -n "$running_vpp" ] ; then
        echo "ERROR: Please kill the following vpp instance(s):"
        echo
        echo $running_vpp
        echo
        exit 1
    fi
    clean_devshm="$vpp_shm_dir*db $vpp_shm_dir*global_vm $vpp_shm_dir*vpe-api $vpp_shm_dir[0-9]*-[0-9]* $vpp_shm_dir*:segment[0-9]*"
    sudo rm -f $clean_devshm
    devshm_files="$(ls -l $clean_devshm 2>/dev/null | grep $(whoami))"
    if [ "$devshm_files" != "" ] ; then
        echo "ERROR: Please remove the following $vpp_shm_dir files:"
        for file in "$devshm_files" ; do
            echo "  $file"
        done
        exit 1
    fi
    if [ ! -d "$vpp_run_dir" ] ; then
        sudo mkdir $vpp_run_dir
        sudo chown root:$USER $vpp_run_dir
    fi
    if [ $use_ipv6 -eq 0 ] && [ -n "$full_thru_host_stack_vpp_cfg" ] ; then
        sock_srvr_table=0
        sock_srvr_addr=172.16.1.1
        sock_client_table=1
        sock_client_addr=172.16.2.1
        client_namespace_id="1"
        client_namespace_secret="5678"
        server_namespace_id="0"
        server_namespace_secret="1234"
        cat <<EOF >> $tmp_vpp_exec_file
session enable
create loop inter
create loop inter
set inter state loop0 up 
set inter ip table loop0 $sock_srvr_table
set inter ip address loop0 $sock_srvr_addr/24
set inter state loop1 up
set inter ip table loop1 $sock_client_table
set inter ip address loop1 $sock_client_addr/24
app ns add id 0 secret 1234 sw_if_index 1
app ns add id 1 secret 5678 sw_if_index 2
ip route add $sock_srvr_addr/32 table $sock_client_table via lookup in table $sock_srvr_table
ip route add $sock_client_addr/32 table $sock_srvr_table via lookup in table $sock_client_table
EOF
    elif [ $use_ipv6 -eq 1 ] && [ -n "$full_thru_host_stack_vpp_cfg" ] ; then
        sock_srvr_table=1
        sock_srvr_addr=fd01:1::1
        sock_client_table=2
        sock_client_addr=fd01:2::1
        client_namespace_id="1"
        client_namespace_secret="5678"
        server_namespace_id="0"
        server_namespace_secret="1234"
        cat <<EOF >> $tmp_vpp_exec_file
session enable
create loop inter
create loop inter
set inter state loop0 up 
set inter ip6 table loop0 $sock_srvr_table
set inter ip address loop0 $sock_srvr_addr/64
set inter state loop1 up
set inter ip6 table loop1 $sock_client_table
set inter ip address loop1 $sock_client_addr/64
app ns add id 0 secret 1234 sw_if_index 1
app ns add id 1 secret 5678 sw_if_index 2
ip route add $sock_srvr_addr/128 table $sock_client_table via lookup in table $sock_srvr_table
ip route add $sock_client_addr/128 table $sock_srvr_table via lookup in table $sock_client_table
EOF
    elif [ -n "$multi_host" ] ; then
        vpp_eth_pci_id="$(ls -ld /sys/class/net/$vpp_eth_name/device | awk '{print $11}' | cut -d/ -f4)"
        if [ -z "$vpp_eth_pci_id" ] ; then
            echo "ERROR: Missing ethernet interface $vpp_eth_name!"
            usage
        fi
        printf -v bus "%x" "0x$(echo $vpp_eth_pci_id | cut -d: -f2)"
        printf -v slot "%x" "0x$(echo $vpp_eth_pci_id | cut -d: -f3 | cut -d. -f1)"
        printf -v func "%x" "0x$(echo $vpp_eth_pci_id | cut -d. -f2)"

        vpp_eth_kernel_driver="$(basename $(ls -l /sys/bus/pci/devices/$vpp_eth_pci_id/driver | awk '{print $11}'))"
        if [ -z "$vpp_eth_kernel_driver" ] ; then
            echo "ERROR: Missing kernel driver for $vpp_eth_name!"
            usage
        fi
        case $vpp_eth_kernel_driver in
            e1000)
                vpp_eth_ifname="GigabitEthernet$bus/$slot/$func" ;;
            ixgbe)
                vpp_eth_ifname="TenGigabitEthernet$bus/$slot/$func" ;;
            i40e)
                vpp_eth_ifname="FortyGigabitEthernet$bus/$slot/$func" ;;
            *)
                echo "ERROR: Unknown ethernet kernel driver $vpp_eth_kernel_driver!"
                usage ;;
        esac
        
        vpp_eth_ip4_addr="$(ip -4 -br addr show $vpp_eth_name | awk '{print $3}')"
        if [ -z "$vpp_eth_ip4_addr" ] ; then
            if [ "$multi_host" = "server" ] ; then
                vpp_eth_ip4_addr="10.10.10.10/24"
            else
                vpp_eth_ip4_addr="10.10.10.11/24"
            fi
        fi
        if [ $use_ipv6 -eq 1 ] && [ -z "$vpp_eth_ip6_addr" ] ; then
            echo "ERROR: No inet6 address configured for $vpp_eth_name!"
            usage
        fi
        vpp_args="$vpp_args plugins { path ${lib_dir}vpp_plugins } dpdk { dev $vpp_eth_pci_id }"
                
        sudo ifconfig $vpp_eth_name down 2> /dev/null
        echo "Configuring VPP to use $vpp_eth_name ($vpp_eth_pci_id), inet addr $vpp_eth_ip4_addr"

        cat <<EOF >> $tmp_vpp_exec_file
set int state $vpp_eth_ifname up
set int ip addr $vpp_eth_ifname $vpp_eth_ip4_addr
EOF

    fi

    if [ -z "$full_thru_host_stack_vpp_cfg" ] && [ -n "$namespace_id" ] ; then
        cat <<EOF >> $tmp_vpp_exec_file
session enable
app ns add id $namespace_id secret $namespace_secret sw_if_index 0
EOF
    fi
    
    cat <<EOF >> $tmp_vpp_exec_file
create tap id 0
set int ip addr tap0 172.17.0.2/24
show version
show version verbose
show cpu
show int
EOF
}

verify_no_docker_containers() {
    if (( $(which docker | wc -l) < 1 )) ; then
        echo "ERROR: docker is not installed!"
        echo "See https://docs.docker.com/engine/installation/linux/ubuntu/"
        echo " or https://docs.docker.com/engine/installation/linux/centos/"
        exit 1
    fi
    if (( $(docker ps | wc -l) > 1 )) ; then
        echo "ERROR: Run the following to kill all docker containers:"
        echo "docker kill \$(docker ps -q)"
        echo
        docker ps
        exit 1
    fi
}

set_pre_cmd() {
    # arguments
    #   $1 : emacs flag
    #   $2 : gdb flag
    #   $3 : optional LD_PRELOAD library pathname
    local -i emacs=$1
    local -i gdb=$2

    if [ $emacs -eq 1 ] ; then
        write_gdb_cmdfile $tmp_gdb_cmdfile $gdb_cmdfile $emacs $3
        pre_cmd="$gdb_in_emacs "
    elif [ $gdb -eq 1 ] ; then
        write_gdb_cmdfile $tmp_gdb_cmdfile $gdb_cmdfile $emacs $3
        pre_cmd="gdb -x $tmp_gdb_cmdfile --args "
    elif [ -z $3 ] ; then
        unset -v pre_cmd
    else
        docker_ld_preload="-e LD_PRELOAD=$3 "
        pre_cmd="LD_PRELOAD=$3 "
    fi
}

write_script_header() {
    # arguments
    #   $1 : command script file
    #   $2 : gdb command file
    #   $3 : title
    #   $4 : optional command string (typically "sleep 2")
    echo "$bash_header" > $1
    echo -e "#\n# $1 generated on $(date)\n#" >> $1
    if [ $leave_tmp_files -eq 0 ] ; then
        if [ -n "$multi_host" ] ; then
            echo "trap \"rm -f $1 $2 $tmp_vpp_exec_file; sudo $dpdk_devbind -b $vpp_eth_kernel_driver $vpp_eth_pci_id; sudo ifconfig $vpp_eth_name up\" $trap_signals" >> $1
        else
            echo "trap \"rm -f $1 $2 $tmp_vpp_exec_file\" $trap_signals" >> $1
        fi
    fi
    if [ -n "$VCL_CONFIG" ] ; then
        echo "export VCL_CONFIG=${vcl_config_dir}${vcl_config}" >> $1
    fi
    if [ -n "$VCL_API_PREFIX" ] ; then
        echo "export VCL_API_PREFIX=$VCL_API_PREFIX" >> $1
    fi
    if [ -n "$VCL_DEBUG" ] ; then
        echo "export VCL_DEBUG=$VCL_DEBUG" >> $1
    fi
    if [ -n "$LDP_DEBUG" ] ; then
        echo "export LDP_DEBUG=$LDP_DEBUG" >> $1
    fi
    if [ -n "$VCOM_APP_NAME" ] ; then
        echo "export VCOM_APP_NAME=$VCOM_APP_NAME" >> $1
    fi
    if [ -n "$VCOM_SID_BIT" ] ; then
        echo "export VCOM_SID_BIT=$VCOM_SID_BIT" >> $1
    fi
    if [ -n "$namespace_id" ] ; then
        echo "export VCL_APP_NAMESPACE_ID=\"$namespace_id\"" >> $1
        echo "export VCL_APP_NAMESPACE_SECRET=\"$namespace_secret\"" >> $1
    fi
    if [ -n "$VCL_APP_SCOPE_LOCAL" ] || [ -z "$multi_host" ] &&
           [ -z "$full_thru_host_stack_vpp_cfg" ] ; then
        echo "export VCL_APP_SCOPE_LOCAL=true" >> $1
    fi
    if [ -n "$VCL_APP_SCOPE_GLOBAL" ] || [ -n "$multi_host" ] ||
           [ -n "$full_thru_host_stack_vpp_cfg" ] ; then
        echo "export VCL_APP_SCOPE_GLOBAL=true" >> $1
    fi
    if [ -n "$VCL_APP_PROXY_TRANSPORT_TCP" ] ; then
        echo "export VCL_APP_PROXY_TRANSPORT_TCP=true" >> $1
    fi
    if [ -n "$VCL_APP_PROXY_TRANSPORT_UDP" ] ; then
        echo "export VCL_APP_PROXY_TRANSPORT_UDP=true" >> $1
    fi
    if [ "$pre_cmd" = "$gdb_in_emacs " ] ; then
        if [ -n "$multi_host" ] && [[ $3 =~ "VPP".* ]] ; then
            cat <<EOF >> $1
$gdb_in_emacs() {
    sudo emacs --eval "(gdb \"gdb -x $2 -i=mi --args \$*\")" --eval "(setq frame-title-format \"$3\")"
}
EOF
        else
            cat <<EOF >> $1
$gdb_in_emacs() {
    emacs --eval "(gdb \"gdb -x $2 -i=mi --args \$*\")" --eval "(setq frame-title-format \"$3\")"
}
EOF
        fi
    fi
    if [ -n "$4" ] ; then
        echo "$4" >> $1
    fi
}

write_script_footer() {
    # arguments
    #   $1 : command script file
    #   $2 : perf flag indicating to run bash before exit
    local -i perf=$2
    if [ $bash_after_exit -eq 1 ] || [ $perf -eq 1 ] ; then
        echo "bash" >> $1
    fi
}

write_gdb_cmdfile() {
    # arguments
    #   $1 : gdb command file
    #   $2 : User specified gdb cmdfile
    #   $3 : emacs flag
    #   $4 : optional LD_PRELOAD library pathname.
    local -i emacs=$3
    
    echo "# $1 generated on $(date)" > $1
    echo "#" >> $1
    echo "set confirm off" >> $1
    if [ -n "$4" ] ; then
        echo "set exec-wrapper env LD_PRELOAD=$4" >> $1
        # echo "start" >> $1
    fi

    if [ ! -f $2 ] ; then
        echo -n "# " >> $1
    fi
    echo "source $2" >> $1
    if [ $emacs -eq 0 ] ; then
        echo "run" >> $1
    fi
}

native_kernel() {
    banner="Running NATIVE-KERNEL socket test"
    if [ -z "$multi_host" ] || [ "$multi_host" = "server" ] ; then
        title1="SERVER$title_dbg (Native-Kernel Socket Test)"
        tmp_gdb_cmdfile=$tmp_gdb_cmdfile_server
        gdb_cmdfile=$VPPCOM_SERVER_GDB_CMDFILE
        set_pre_cmd $emacs_server $gdb_server
        write_script_header $cmd1_file $tmp_gdb_cmdfile "$title1"
        echo "${pre_cmd}${app_dir}${srvr_app}" >> $cmd1_file
        write_script_footer $cmd1_file $perf_server
        chmod +x $cmd1_file
    fi
    
    if [ -z "$multi_host" ] || [ "$multi_host" = "client" ] ; then
        title2="CLIENT$title_dbg (Native-Kernel Socket Test)"
        tmp_gdb_cmdfile=$tmp_gdb_cmdfile_client
        gdb_cmdfile=$VPPCOM_CLIENT_GDB_CMDFILE
        set_pre_cmd $emacs_client $gdb_client
        write_script_header $cmd2_file $tmp_gdb_cmdfile "$title2" "sleep 2"
        echo "srvr_addr=\"$sock_srvr_addr\"" >> $cmd2_file
        echo "${pre_cmd}${app_dir}${clnt_app}" >> $cmd2_file
        write_script_footer $cmd2_file $perf_client
        chmod +x $cmd2_file

    fi
}

native_preload() {
    verify_no_vpp
    banner="Running NATIVE-PRELOAD socket test"
    ld_preload="$VCL_LDPRELOAD_LIB_DIR/$vcl_ldpreload_lib "

    title1="VPP$title_dbg (Native-Preload Socket Test)"
    tmp_gdb_cmdfile=$tmp_gdb_cmdfile_vpp
    gdb_cmdfile=$VPP_GDB_CMDFILE
    set_pre_cmd $emacs_vpp $gdb_vpp
    write_script_header $cmd1_file $tmp_gdb_cmdfile "$title1"
    if [ -n "$multi_host" ] && [ $emacs_vpp -eq 0 ] ; then
        echo -n "sudo " >> $cmd1_file
    fi
    echo "${pre_cmd}$vpp_dir$vpp_app $vpp_args " >> $cmd1_file
    write_script_footer $cmd1_file $perf_vpp
    chmod +x $cmd1_file

    if [ -z "$multi_host" ] || [ "$multi_host" = "server" ] ; then
        title2="SERVER$title_dbg (Native-Preload Socket Test)"
        tmp_gdb_cmdfile=$tmp_gdb_cmdfile_server
        gdb_cmdfile=$VPPCOM_SERVER_GDB_CMDFILE
        set_pre_cmd $emacs_server $gdb_server $ld_preload
        if [ -n "$full_thru_host_stack_vpp_cfg" ] ; then
            namespace_id="$server_namespace_id"
            namespace_secret="$server_namespace_secret"
        fi
        write_script_header $cmd2_file $tmp_gdb_cmdfile "$title2" "sleep 3"
        echo "export LD_LIBRARY_PATH=\"$lib_dir:$VCL_LDPRELOAD_LIB_DIR:$LD_LIBRARY_PATH\"" >> $cmd2_file
        echo "${pre_cmd}${app_dir}${srvr_app}" >> $cmd2_file
        write_script_footer $cmd2_file $perf_server
        chmod +x $cmd2_file
    fi

    if [ -z "$multi_host" ] || [ "$multi_host" = "client" ] ; then
        title3="CLIENT$title_dbg (Native-Preload Socket Test)"
        tmp_gdb_cmdfile=$tmp_gdb_cmdfile_client
        gdb_cmdfile=$VPPCOM_CLIENT_GDB_CMDFILE
        set_pre_cmd $emacs_client $gdb_client $ld_preload
        if [ -n "$full_thru_host_stack_vpp_cfg" ] ; then
            namespace_id="$client_namespace_id"
            namespace_secret="$client_namespace_secret"
        fi
        write_script_header $cmd3_file $tmp_gdb_cmdfile "$title3" "sleep 4"
        echo "export LD_LIBRARY_PATH=\"$lib_dir:$VCL_LDPRELOAD_LIB_DIR:$LD_LIBRARY_PATH\"" >> $cmd3_file
        echo "srvr_addr=\"$sock_srvr_addr\"" >> $cmd3_file
        echo "${pre_cmd}${app_dir}${clnt_app}" >> $cmd3_file
        write_script_footer $cmd3_file $perf_client
        chmod +x $cmd3_file
    fi
}

native_vcl() {
    verify_no_vpp
    banner="Running NATIVE-VCL socket test"

    title1="VPP$title_dbg (Native-VCL Socket Test)"
    tmp_gdb_cmdfile=$tmp_gdb_cmdfile_vpp
    gdb_cmdfile=$VPP_GDB_CMDFILE
    set_pre_cmd $emacs_vpp $gdb_vpp
    write_script_header $cmd1_file $tmp_gdb_cmdfile "$title1"
    if [ -n "$multi_host" ] && [ $emacs_vpp -eq 0 ] ; then
        echo -n "sudo " >> $cmd1_file
    fi
    echo "${pre_cmd}$vpp_dir$vpp_app $vpp_args " >> $cmd1_file
    write_script_footer $cmd1_file $perf_vpp
    chmod +x $cmd1_file

    if [ -z "$multi_host" ] || [ "$multi_host" = "server" ] ; then
        title2="SERVER$title_dbg (Native-VCL Socket Test)"
        tmp_gdb_cmdfile=$tmp_gdb_cmdfile_server
        gdb_cmdfile=$VPPCOM_SERVER_GDB_CMDFILE
        set_pre_cmd $emacs_server $gdb_server
        if [ "$multi_host" = "server" ] ; then
            delay="sleep 10"
        else
            delay="sleep 3"
        fi
        if [ -n "$full_thru_host_stack_vpp_cfg" ] ; then
            namespace_id="$server_namespace_id"
            namespace_secret="$server_namespace_secret"
        fi
        write_script_header $cmd2_file $tmp_gdb_cmdfile "$title2" "$delay"
        echo "export LD_LIBRARY_PATH=\"$lib_dir:$LD_LIBRARY_PATH\"" >> $cmd2_file
        echo "${pre_cmd}${app_dir}${srvr_app}" >> $cmd2_file
        write_script_footer $cmd2_file $perf_server
        chmod +x $cmd2_file
    fi

    if [ -z "$multi_host" ] || [ "$multi_host" = "client" ] ; then
        title3="CLIENT$title_dbg (Native-VCL Socket Test)"
        tmp_gdb_cmdfile=$tmp_gdb_cmdfile_client
        gdb_cmdfile=$VPPCOM_CLIENT_GDB_CMDFILE
        set_pre_cmd $emacs_client $gdb_client
        if [ "$multi_host" = "client" ] ; then
            delay="sleep 10"
        else
            delay="sleep 4"
        fi
        if [ -n "$full_thru_host_stack_vpp_cfg" ] ; then
            namespace_id="$client_namespace_id"
            namespace_secret="$client_namespace_secret"
        fi
        write_script_header $cmd3_file $tmp_gdb_cmdfile "$title3" "$delay"
        echo "export LD_LIBRARY_PATH=\"$lib_dir:$LD_LIBRARY_PATH\"" >> $cmd3_file
        echo "srvr_addr=\"$sock_srvr_addr\"" >> $cmd3_file
        echo "${pre_cmd}${app_dir}${clnt_app}" >> $cmd3_file
        write_script_footer $cmd3_file $perf_client
        chmod +x $cmd3_file
    fi
}

docker_kernel() {
    verify_no_docker_containers
    banner="Running DOCKER-KERNEL socket test"
    
    if [ -z "$multi_host" ] || [ "$multi_host" = "server" ] ; then
        title1="SERVER$title_dbg (Docker-Native Socket Test)"
        tmp_gdb_cmdfile=$tmp_gdb_cmdfile_server
        gdb_cmdfile=$VPPCOM_SERVER_GDB_CMDFILE
        set_pre_cmd $emacs_server $gdb_server
        write_script_header $cmd1_file $tmp_gdb_cmdfile "$title1"
        echo "docker run -it --cpuset-cpus='4-7' --cpuset-cpus='4-7' -v $vpp_dir:$docker_vpp_dir -p $sock_srvr_port:$sock_srvr_port $docker_os ${docker_app_dir}${srvr_app}" >> $cmd1_file
        write_script_footer $cmd1_file $perf_server
        chmod +x $cmd1_file
    fi
    
    if [ -z "$multi_host" ] || [ "$multi_host" = "client" ] ; then
        title2="CLIENT$title_dbg (Docker-Native Socket Test)"
        tmp_gdb_cmdfile=$tmp_gdb_cmdfile_client
        gdb_cmdfile=$VPPCOM_CLIENT_GDB_CMDFILE
        set_pre_cmd $emacs_client $gdb_client
        write_script_header $cmd2_file $tmp_gdb_cmdfile "$title2" "sleep 2"
        echo "$get_docker_server_ip4addr" >> $cmd2_file
        echo "docker run -it --cpuset-cpus='4-7' -v $vpp_dir:$docker_vpp_dir $docker_os ${docker_app_dir}${clnt_app}" >> $cmd2_file
        write_script_footer $cmd2_file $perf_client
        chmod +x $cmd2_file
    fi
}

docker_preload() {
    verify_no_vpp
    verify_no_docker_containers
    banner="Running DOCKER-PRELOAD socket test"
    docker_ld_preload_dir="/vcl-ldpreload/"
    ld_preload_dir="$VCL_LDPRELOAD_LIB_DIR"
    ld_preload="$docker_ld_preload_dir$vcl_ldpreload_lib "
    docker_ld_preload_lib="$docker_ld_preload_dir$vcl_ldpreload_lib "
    
    title1="VPP$title_dbg (Docker-Preload Socket Test)"
    tmp_gdb_cmdfile=$tmp_gdb_cmdfile_vpp
    gdb_cmdfile=$VPP_GDB_CMDFILE
    set_pre_cmd $emacs_vpp $gdb_vpp
    write_script_header $cmd1_file $tmp_gdb_cmdfile "$title1"
    if [ -n "$multi_host" ] ; then
        echo -n "sudo " >> $cmd1_file
    fi
    echo "${pre_cmd}$vpp_dir$vpp_app $vpp_args" >> $cmd1_file
    write_script_footer $cmd1_file $perf_vpp
    chmod +x $cmd1_file

    if [ -z "$multi_host" ] || [ "$multi_host" = "server" ] ; then
        title2="SERVER$title_dbg (Docker-Preload Socket Test)"
        tmp_gdb_cmdfile=$tmp_gdb_cmdfile_server
        gdb_cmdfile=$VPPCOM_SERVER_GDB_CMDFILE
        set_pre_cmd $emacs_server $gdb_server $docker_ld_preload_lib
        if [ -n "$full_thru_host_stack_vpp_cfg" ] ; then
            namespace_id="$server_namespace_id"
            namespace_secret="$server_namespace_secret"
        fi
        write_script_header $cmd2_file $tmp_gdb_cmdfile "$title2" "sleep 2"
        echo "docker run -it -v $vpp_shm_dir:$vpp_shm_dir -v $vpp_dir:$docker_vpp_dir -v $lib_dir:$docker_lib_dir -v $ld_preload_dir:$docker_ld_preload_dir -v $vcl_config_dir:$docker_vcl_config_dir -p $sock_srvr_port:$sock_srvr_port -e VCL_DEBUG=$VCL_DEBUG -e VCL_CONFIG=${docker_vcl_config_dir}$vcl_config -e LD_LIBRARY_PATH=$docker_lib_dir:$docker_ld_preload_dir ${docker_ld_preload}$docker_os ${docker_app_dir}${srvr_app}" >> $cmd2_file
        write_script_footer $cmd2_file $perf_server
        chmod +x $cmd2_file
    fi

    if [ -z "$multi_host" ] || [ "$multi_host" = "client" ] ; then
        title3="CLIENT$title_dbg (Docker-Preload Socket Test)"
        tmp_gdb_cmdfile=$tmp_gdb_cmdfile_client
        gdb_cmdfile=$VPPCOM_CLIENT_GDB_CMDFILE
        set_pre_cmd $emacs_client $gdb_client $docker_ld_preload_lib
        if [ -n "$full_thru_host_stack_vpp_cfg" ] ; then
            namespace_id="$client_namespace_id"
            namespace_secret="$client_namespace_secret"
        fi
        write_script_header $cmd3_file $tmp_gdb_cmdfile "$title3" "sleep 4"
        echo "$get_docker_server_ip4addr" >> $cmd3_file
        echo "docker run -it --cpuset-cpus='4-7' -v $vpp_shm_dir:$vpp_shm_dir -v $vpp_dir:$docker_vpp_dir -v $lib_dir:$docker_lib_dir  -v $ld_preload_dir:$docker_ld_preload_dir -v $vcl_config_dir:$docker_vcl_config_dir -e VCL_DEBUG=$VCL_DEBUG -e VCL_CONFIG=${docker_vcl_config_dir}$vcl_config -e LD_LIBRARY_PATH=$docker_lib_dir ${docker_ld_preload}$docker_os ${docker_app_dir}${clnt_app}" >> $cmd3_file
        write_script_footer $cmd3_file $perf_client
        chmod +x $cmd3_file
    fi
}

docker_vcl() {
    verify_no_vpp
    verify_no_docker_containers
    banner="Running DOCKER-VCL socket test"
    
    title1="VPP$title_dbg (Docker-VCL Socket Test)"
    tmp_gdb_cmdfile=$tmp_gdb_cmdfile_vpp
    gdb_cmdfile=$VPP_GDB_CMDFILE
    set_pre_cmd $emacs_vpp $gdb_vpp
    write_script_header $cmd1_file $tmp_gdb_cmdfile "$title1"
    if [ -n "$multi_host" ] ; then
        echo -n "sudo " >> $cmd1_file
    fi
    echo "${pre_cmd}$vpp_dir$vpp_app $vpp_args" >> $cmd1_file
    write_script_footer $cmd1_file $perf_vpp
    chmod +x $cmd1_file

    if [ -z "$multi_host" ] || [ "$multi_host" = "server" ] ; then
        title2="SERVER$title_dbg (Docker-VCL Socket Test)"
        tmp_gdb_cmdfile=$tmp_gdb_cmdfile_server
        gdb_cmdfile=$VPPCOM_SERVER_GDB_CMDFILE
        set_pre_cmd $emacs_server $gdb_server
        if [ -n "$full_thru_host_stack_vpp_cfg" ] ; then
            namespace_id="$server_namespace_id"
            namespace_secret="$server_namespace_secret"
        fi
        write_script_header $cmd2_file $tmp_gdb_cmdfile "$title2" "sleep 2"
        echo "docker run -it --cpuset-cpus='4-7' -v $vpp_shm_dir:$vpp_shm_dir -v $vpp_dir:$docker_vpp_dir -v $lib_dir:$docker_lib_dir -v $vcl_config_dir:$docker_vcl_config_dir -p $sock_srvr_port:$sock_srvr_port -e VCL_CONFIG=${docker_vcl_config_dir}/$vcl_config -e LD_LIBRARY_PATH=$docker_lib_dir $docker_os ${docker_app_dir}${srvr_app}" >> $cmd2_file
        write_script_footer $cmd2_file $perf_server
        chmod +x $cmd2_file
    fi

    if [ -z "$multi_host" ] || [ "$multi_host" = "client" ] ; then
        title3="CLIENT$title_dbg (Docker-VCL Socket Test)"
        tmp_gdb_cmdfile=$tmp_gdb_cmdfile_client
        gdb_cmdfile=$VPPCOM_CLIENT_GDB_CMDFILE
        set_pre_cmd $emacs_client $gdb_client
        if [ -n "$full_thru_host_stack_vpp_cfg" ] ; then
            namespace_id="$client_namespace_id"
            namespace_secret="$client_namespace_secret"
        fi
        write_script_header $cmd3_file $tmp_gdb_cmdfile "$title3" "sleep 3"
        echo "$get_docker_server_ip4addr" >> $cmd3_file
        echo "docker run -it --cpuset-cpus='4-7' -v $vpp_shm_dir:$vpp_shm_dir -v $vpp_dir:$docker_vpp_dir -v $lib_dir:$docker_lib_dir -v $vcl_config_dir:$docker_vcl_config_dir -e VCL_CONFIG=${docker_vcl_config_dir}/$vcl_config -e LD_LIBRARY_PATH=$docker_lib_dir $docker_os ${docker_app_dir}${clnt_app}" >> $cmd3_file
        write_script_footer $cmd3_file $perf_client
        chmod +x $cmd3_file
    fi
}

if [[ $run_test ]] ; then
    eval $run_test
else
    echo "ERROR: Please specify a test to run!" >&2
    usage;
fi

if (( $(which xfce4-terminal | wc -l) > 0 )) ; then
    xterm_cmd="xfce4-terminal --geometry $xterm_geom"
    if [[ $use_tabs ]] ; then
        declare -a tab_cmd_files
        declare -a tab_titles
        declare -i i=0

        if [ -x "$cmd1_file" ] ; then
            tab_cmd_files[$i]="$cmd1_file"
            tab_titles[$i]="$title1"
            (( i++ ))
        fi
        if [ -x "$cmd2_file" ] ; then
            tab_cmd_files[$i]="$cmd2_file"
            tab_titles[$i]="$title2"
            (( i++ ))
        fi
        if [ -x "$cmd3_file" ] ; then
            tab_cmd_files[$i]="$cmd3_file"
            tab_titles[$i]="$title3"
        fi

        if [ -n "${tab_cmd_files[2]}" ] ; then
            $xterm_cmd  --title "${tab_titles[0]}" --command "${tab_cmd_files[0]}" --tab --title "${tab_titles[1]}" --command "${tab_cmd_files[1]}" --tab --title "${tab_titles[2]}" --command "${tab_cmd_files[2]}"
        elif [ -n "${tab_cmd_files[1]}" ] ; then
            $xterm_cmd --title "${tab_titles[0]}" --command "${tab_cmd_files[0]}" --tab --title "${tab_titles[1]}" --command "${tab_cmd_files[1]}"

        else
            $xterm_cmd --title "${tab_titles[0]}" --command "${tab_cmd_files[0]}"
        fi
        
    else
        if [ -x "$cmd1_file" ] ; then
            ($xterm_cmd --title "$title1" --command "$cmd1_file" &)
        fi
        if [ -x "$cmd2_file" ] ; then
            ($xterm_cmd --title "$title2" --command "$cmd2_file" &)
        fi
        if [ -x "$cmd3_file" ] ; then
            ($xterm_cmd --title "$title3" --command "$cmd3_file" &)
        fi
    fi
        
else
    if [[ $use_tabs ]] ; then
        echo "Sorry, plain ol' xterm doesn't support tabs."
    fi
    xterm_cmd="xterm -fs 10 -geometry $xterm_geom"
    if [ -x "$cmd1_file" ] ; then
        ($xterm_cmd -title "$title1" -e "$cmd1_file" &)
    fi
    if [ -x "$cmd2_file" ] ; then
        ($xterm_cmd -title "$title2" -e "$cmd2_file" &)
    fi
    if [ -x "$cmd3_file" ] ; then
        ($xterm_cmd -title "$title3" -e "$cmd3_file" &)
    fi
fi

sleep 1
