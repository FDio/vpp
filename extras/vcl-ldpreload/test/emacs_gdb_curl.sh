#! /bin/bash

if [ -z "$WS_ROOT" ] ; then
    echo "ERROR: WS_ROOT environment variable is not set!"
    exit 1
fi

source $WS_ROOT/extras/vcl-ldpreload/env.sh
tmp_gdb_cmdfile="/tmp/gdb_cmdfile_curl.$$"

trap "rm -f $tmp_gdb_cmdfile" SIGINT SIGTERM EXIT

cat <<EOF > $tmp_gdb_cmdfile
set confirm off
source $WS_ROOT/extras/gdb/gdb_cmdfile.vpp
set exec-wrapper env LD_PRELOAD=$VCL_LDPRELOAD_LIB_DIR/libvcl_ldpreload.so.0.0.0
start
EOF

gdb_in_emacs() {
    sudo -E emacs --eval "(gdb \"gdb -x $tmp_gdb_cmdfile -i=mi --args $*\")" --eval "(setq frame-title-format \"CURL-DEBUG (VCL-LDPRELOAD)\")"
}

# Extract nginx IPv4 address from docker bridge
#
nginx_addr=$(docker network inspect bridge | grep IPv4Address | awk -e '{print $2}' | sed -e 's,/16,,' -e 's,",,g' -e 's/,//')

if [ -z "$nginx_addr" ] ; then
    echo "ERROR: Unable to determine docker container address!"
    exit 1
fi

gdb_in_emacs /usr/bin/curl http://$nginx_addr
