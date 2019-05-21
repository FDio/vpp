#!/bin/sh
set -eux

/usr/bin/vpp unix { cli-listen /run/vpp/cli.sock }

sleep 5

export VPP_CHECK_VERSION=$(cat /VPP_CHECK_VERSION.txt)
echo "Checking the running VPP for version ${VPP_CHECK_VERSION}"

vppctl show version
# vppctl show version | grep 19.01.2-release
vppctl show version | grep ${VPP_CHECK_VERSION}
vppctl show plugins
WRONG_VER=$(vppctl show plugins | grep -v ${VPP_CHECK_VERSION} | grep -v Description | grep -v 'Plugin path is' | tr -d '[\r\n]' )
echo "Plugins with wrong version: '$WRONG_VER'"
if [ "x$WRONG_VER" != "x" ]; then
  exit 123
fi




