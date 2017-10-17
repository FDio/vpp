#! /bin/bash
#
# curl_test.sh - VCL-LDPRELOAD curl test.
#
#   Run curl using LD_PRELOAD to fetch a page from
#   nginx running in vpp1 net-namespace.
#
# 

# Verify Environment.
if [ -z "$WS_ROOT" ] ; then
    echo "ERROR: WS_ROOT environment variable not set!" >&2
    echo "       Please set WS_ROOT to VPP workspace root directory." >&2
    exit 1
fi
if [ -z "$LDP_DIR" ] ; then
    echo "WARNING: LDP_DIR environment variable is not set!"
    echo "         Sourcing $WS_ROOT/extras/vcl-ldpreload/env.sh"
    source $WS_ROOT/extras/vcl-ldpreload/env.sh
fi

TEST_APP="${TEST_APP:-curl}"
LDP_TEST_DIR="${LDP_TEST_DIR:-${LDP_DIR}/test}"
source $LDP_TEST_DIR/common/nginx_test.sh
