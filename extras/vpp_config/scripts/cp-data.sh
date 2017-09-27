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

sudo mkdir /usr/local/vpp
sudo mkdir /usr/local/vpp/vpp-config
sudo mkdir /usr/local/vpp/vpp-config/dryrun
sudo mkdir /usr/local/vpp/vpp-config/scripts
sudo mkdir /usr/local/vpp/vpp-config/configs
sudo mkdir /usr/local/vpp/vpp-config/dryrun/default
sudo mkdir /usr/local/vpp/vpp-config/dryrun/sysctl.d
sudo mkdir /usr/local/vpp/vpp-config/dryrun/vpp
sudo cp data/auto-config.yaml /usr/local/vpp/vpp-config/configs/.
sudo cp data/grub.template /usr/local/vpp/vpp-config/dryrun/default/.
sudo cp data/startup.conf.template /usr/local/vpp/vpp-config/dryrun/vpp/.
sudo cp data/80-vpp.conf.template /usr/local/vpp/vpp-config/dryrun/sysctl.d/.
sudo cp scripts/dpdk-devbind.py /usr/local/vpp/vpp-config/scripts/.
