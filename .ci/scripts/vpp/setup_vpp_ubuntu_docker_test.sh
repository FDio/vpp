# Copyright (c) 2025 Cisco and/or its affiliates.
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

set -e -o pipefail

OS_ID=$(grep '^ID=' /etc/os-release | cut -f2- -d= | sed -e 's/\"//g')
OS_VERSION_ID=$(grep '^VERSION_ID=' /etc/os-release | cut -f2- -d= | sed -e 's/\"//g')

if [ -n ${DOCKER_TEST} ] ; then
        # for 4 cores:
        # framework.VppTestCase.MIN_REQ_SHM + (num_cores * framework.VppTestCase.SHM_PER_PROCESS)
        # 1073741824 == 1024M (1073741824 >> 20)
        MEM=1024M
        if [[ ${MAKE_PARALLEL_JOBS} == '16' ]]
        then
            # arm build are running with 16 cores, empirical evidence shows
            # that 2048M is enough
            MEM=2048M
        fi
	sudo mount -o remount /dev/shm -o size=${MEM} || true
        echo "/dev/shm remounted with size='${MEM}'"
fi
