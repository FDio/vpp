#!/bin/sh
set -eu

/usr/bin/vpp unix { cli-listen /run/vpp/cli.sock } 2> /dev/null

sleep 1

VPP_CHECK_VERSION="$(cat /VPP_CHECK_VERSION.txt)"
echo "Checking the running VPP for version v${VPP_CHECK_VERSION}"

vppctl show version
VPP_SHOW_VER=$(vppctl show version | cut -d' ' -f2 | cut -d'~' -f1)
if [ "$VPP_SHOW_VER" != "v$VPP_CHECK_VERSION" ] ; then
  echo "WRONG VPP version: $VPP_SHOW_VER"
  echo
  exit 1
fi

PLUGINS_INSTALLED="$(vppctl show plugins | grep -v Description | grep -v 'Plugin path is' | grep -v '^[[:space:]]*$' | wc -l)"
WRONG_VER="$(vppctl show plugins | grep -v ${VPP_CHECK_VERSION} | grep -v Description | grep -v 'Plugin path is' | tr -d '[\r\n]' )"
if [ "$PLUGINS_INSTALLED" = "0" ] ; then
  echo "NO PLUGINS INSTALLED!"
  exit 2
elif [ -n "$WRONG_VER" ] ; then
  echo "Plugins with wrong version:"
  vppctl show plugins | gawk -e "!/${VPP_CHECK_VERSION}/{print \$0}"
  echo
  exit 3
else
  echo "$PLUGINS_INSTALLED plugins verified"
fi




