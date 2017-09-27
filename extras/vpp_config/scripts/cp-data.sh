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

ROOTDIR='/usr/local'

sudo mkdir $ROOTDIR/vpp
sudo mkdir $ROOTDIR/vpp/vpp-config
sudo mkdir $ROOTDIR/vpp/vpp-config/dryrun
sudo mkdir $ROOTDIR/vpp/vpp-config/scripts
sudo mkdir $ROOTDIR/vpp/vpp-config/configs
sudo mkdir $ROOTDIR/vpp/vpp-config/dryrun/default
sudo mkdir $ROOTDIR/vpp/vpp-config/dryrun/sysctl.d
sudo mkdir $ROOTDIR/vpp/vpp-config/dryrun/vpp
sudo cp data/auto-config.yaml $ROOTDIR/vpp/vpp-config/configs/.
sudo cp data/grub.template $ROOTDIR/vpp/vpp-config/dryrun/default/.
sudo cp data/startup.conf.template $ROOTDIR/vpp/vpp-config/dryrun/vpp/.
sudo cp data/80-vpp.conf.template $ROOTDIR/vpp/vpp-config/dryrun/sysctl.d/.
sudo cp scripts/dpdk-devbind.py $ROOTDIR/vpp/vpp-config/scripts/.
