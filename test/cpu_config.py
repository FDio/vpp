# Copyright (c) 2021 Cisco and/or its affiliates.
#
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#
# Licensed under the Apache License 2.0 or
# GNU General Public License v2.0 or later;  you may not use this file
# except in compliance with one of these Licenses. You
# may obtain a copy of the Licenses at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#     https://www.gnu.org/licenses/old-licenses/gpl-2.0-standalone.html
#
# Note: If this file is linked with Scapy, which is GPLv2+, your use of it
# must be under GPLv2+.  If at any point in the future it is no longer linked
# with Scapy (or other GPLv2+ licensed software), you are free to choose
# Apache 2.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os
import psutil

available_cpus = psutil.Process().cpu_affinity()
num_cpus = len(available_cpus)

max_vpp_cpus = os.getenv("MAX_VPP_CPUS", "auto").lower()

if max_vpp_cpus == "auto":
    max_vpp_cpus = num_cpus
else:
    try:
        max_vpp_cpus = int(max_vpp_cpus)
    except ValueError as e:
        raise ValueError("Invalid MAX_VPP_CPUS value specified, valid "
                         "values are a positive integer or 'auto'") from e
    if max_vpp_cpus <= 0:
        raise ValueError("Invalid MAX_VPP_CPUS value specified, valid "
                         "values are a positive integer or 'auto'")
    if max_vpp_cpus > num_cpus:
        max_vpp_cpus = num_cpus
