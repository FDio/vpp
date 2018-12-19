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

from __future__ import print_function

"""VPP Huge Page Utilities"""

import re

from vpplib.VPPUtil import VPPUtil

# VPP Huge page File
DEFAULT_VPP_HUGE_PAGE_CONFIG_FILENAME = "/etc/vpp/80-vpp.conf"
VPP_HUGEPAGE_CONFIG = """
vm.nr_hugepages={nr_hugepages}
vm.max_map_count={max_map_count}
vm.hugetlb_shm_group=0
kernel.shmmax={shmmax}
"""


class VppHugePageUtil(object):
    """
    Huge Page Utilities
    """
    def hugepages_dryrun_apply(self):
        """
        Apply the huge page configuration

        """

        node = self._node
        hugepages = node['hugepages']

        vpp_hugepage_config = VPP_HUGEPAGE_CONFIG.format(
            nr_hugepages=hugepages['total'],
            max_map_count=hugepages['max_map_count'],
            shmmax=hugepages['shmax'])

        rootdir = node['rootdir']
        filename = rootdir + node['hugepages']['hugepage_config_file']

        cmd = 'echo "{0}" | sudo tee {1}'.\
            format(vpp_hugepage_config, filename)
        (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
        if ret != 0:
            raise RuntimeError('{} failed on node {} {} {}'.
                               format(cmd, node['host'],
                                      stdout, stderr))

    def get_actual_huge_pages(self):
        """
        Get the current huge page configuration

        :returns the hugepage total, hugepage free, hugepage size,
        total memory, and total memory free
        :rtype: tuple
        """

        # Get the memory information using /proc/meminfo
        cmd = 'sudo cat /proc/meminfo'
        (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
        if ret != 0:
            raise RuntimeError(
                '{} failed on node {} {} {}'.format(
                    cmd, self._node['host'],
                    stdout, stderr))

        total = re.findall(r'HugePages_Total:\s+\w+', stdout)
        free = re.findall(r'HugePages_Free:\s+\w+', stdout)
        size = re.findall(r'Hugepagesize:\s+\w+\s+\w+', stdout)
        memtotal = re.findall(r'MemTotal:\s+\w+\s+\w+', stdout)
        memfree = re.findall(r'MemFree:\s+\w+\s+\w+', stdout)

        total = total[0].split(':')[1].lstrip()
        free = free[0].split(':')[1].lstrip()
        size = size[0].split(':')[1].lstrip()
        memtotal = memtotal[0].split(':')[1].lstrip()
        memfree = memfree[0].split(':')[1].lstrip()
        return total, free, size, memtotal, memfree

    def show_huge_pages(self):
        """
        Print the current huge page configuration

        """

        node = self._node
        hugepages = node['hugepages']
        print ("  {:30}: {}".format("Total System Memory",
                                   hugepages['memtotal']))
        print ("  {:30}: {}".format("Total Free Memory",
                                    hugepages['memfree']))
        print ("  {:30}: {}".format("Actual Huge Page Total",
                                    hugepages['actual_total']))
        print ("  {:30}: {}".format("Configured Huge Page Total",
                                    hugepages['total']))
        print ("  {:30}: {}".format("Huge Pages Free", hugepages['free']))
        print ("  {:30}: {}".format("Huge Page Size", hugepages['size']))

    def get_huge_page_config(self):
        """
        Returns the huge page config.

        :returns: The map max count and shmmax
        """

        total = self._node['hugepages']['total']
        max_map_count = int(total) * 2 + 1024
        shmmax = int(total) * 2 * 1024 * 1024
        return max_map_count, shmmax

    def __init__(self, node):
        self._node = node
