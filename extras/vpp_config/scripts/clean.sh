#!/bin/bash -x
# Copyright (c) 2016 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

check_os()
{

    # perform some very rudimentary platform detection
    lsb_dist=''
    if command_exists lsb_release; then
        lsb_dist="$(lsb_release -si)"
    fi
    if [ -z "$lsb_dist" ] && [ -r /etc/lsb-release ]; then
        lsb_dist="$(. /etc/lsb-release && echo "$DISTRIB_ID")"
    fi
    if [ -z "$lsb_dist" ] && [ -r /etc/fedora-release ]; then
        lsb_dist='fedora'
    fi
    if [ -z "$lsb_dist" ] && [ -r /etc/centos-release ]; then
        lsb_dist='centos'
    fi
    if [ -z "$lsb_dist" ] && [ -r /etc/os-release ]; then
        lsb_dist="$(. /etc/os-release && echo "$ID")"
    fi

    lsb_dist="$(echo "$lsb_dist" | tr '[:upper:]' '[:lower:]')"
    case "$lsb_dist" in
    fedora|centos|ubuntu|debian)
        ;;
    *)
        echo "Operating system [$lsb_dist] is unsupported"
        exit 0
        ;;
     esac
    LSB=$lsb_dist
}

check_os
case "$LSB" in
    centos)
	ROOTDIR='/usr'
	;;
    ubuntu)
	ROOTDIR='/usr/local'
	;;
    *)
	echo "$LSB is not supported"
	exit 1
	;;
esac

sudo -H pip uninstall vpp-config
sudo rm *~
sudo rm *.pyc
sudo rm vpplib/*~
sudo rm vpplib/*.pyc
sudo rm scripts/*~
sudo rm data/*~
sudo rm -r build
sudo rm -r dist
sudo rm -r vpp_config.egg-info
sudo rm -r $ROOTDIR/vpp/vpp-config
sudo rm $ROOTDIR/bin/vpp-config
