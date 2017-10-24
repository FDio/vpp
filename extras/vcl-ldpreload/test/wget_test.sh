#! /bin/bash
#
# wget_test.sh - VCL-LDPRELOAD wget test.
#
#   Run wget using LD_PRELOAD to fetch a page from
#   nginx running in vpp1 net-namespace.
#
# 

# Verify Environment.
if [ -z "$WS_ROOT" ] ; then
    echo "ERROR: WS_ROOT environment variable not set!" >&2
    echo "       Please set WS_ROOT to VPP workspace root directory." >&2
    exit 1
fi

LDP_DIR="${WS_ROOT}/extras/vcl-ldpreload"
LDP_TEST_DIR="${LDP_TEST_DIR:-${LDP_DIR}/test}"
VCL_LDPRELOAD_LIB_DIR="${VCL_LDPRELOAD_LIB_DIR:-$WS_ROOT/build-root/install-vpp_debug-native/vpp/lib64}"

TEST_APP="${TEST_APP:-wget}"
source $LDP_TEST_DIR/common/nginx_test.sh
