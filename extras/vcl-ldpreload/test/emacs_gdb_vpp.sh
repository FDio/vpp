#! /bin/bash

if [ -z "$WS_ROOT" ] ; then
    echo "ERROR: WS_ROOT environment variable is not set!"
    exit 1
fi

source $WS_ROOT/extras/vcl-ldpreload/env.sh
tmp_gdb_cmdfile="/tmp/gdb_cmdfile_vpp.$$"

trap "rm -f $tmp_gdb_cmdfile" SIGINT SIGTERM EXIT

cat <<EOF > $tmp_gdb_cmdfile
set confirm off
source $WS_ROOT/extras/gdb/gdb_cmdfile.vpp
start
EOF

gdb_in_emacs() {
    sudo -E emacs --eval "(gdb \"gdb -x $tmp_gdb_cmdfile -i=mi --args $*\")" --eval "(setq frame-title-format \"VPP-DEBUG\")"
}
sudo rm -f /dev/shm/*
gdb_in_emacs $WS_ROOT/build-root/install-vpp_debug-native/vpp/bin/vpp unix { interactive exec $LDP_TEST_DIR/common/vpp_docker.conf } api-segment { gid $(id -g) }
