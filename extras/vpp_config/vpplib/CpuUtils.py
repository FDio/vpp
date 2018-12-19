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

"""CPU utilities library."""
from __future__ import absolute_import, division
import re

from vpplib.VPPUtil import VPPUtil

__all__ = ["CpuUtils"]


class CpuUtils(object):
    """CPU utilities"""

    # Number of threads per core.
    NR_OF_THREADS = 2

    @staticmethod
    def __str2int(string):
        """Conversion from string to integer, 0 in case of empty string.

        :param string: Input string.
        :type string: str
        :returns: Integer converted from string, 0 in case of ValueError.
        :rtype: int
        """
        try:
            return int(string)
        except ValueError:
            return 0

    @staticmethod
    def is_smt_enabled(cpu_info):
        """Uses CPU mapping to find out if SMT is enabled or not. If SMT is
        enabled, the L1d,L1i,L2,L3 setting is the same for two processors.
        These two processors are two threads of one core.

        :param cpu_info: CPU info, the output of "lscpu -p".
        :type cpu_info: list
        :returns: True if SMT is enabled, False if SMT is disabled.
        :rtype: bool
        """

        cpu_mems = [item[-4:] for item in cpu_info]
        cpu_mems_len = len(cpu_mems) // CpuUtils.NR_OF_THREADS
        count = 0
        for cpu_mem in cpu_mems[:cpu_mems_len]:
            if cpu_mem in cpu_mems[cpu_mems_len:]:
                count += 1
        return bool(count == cpu_mems_len)

    @staticmethod
    def get_cpu_layout_from_all_nodes(nodes):
        """Retrieve cpu layout from all nodes, assuming all nodes
           are Linux nodes.

        :param nodes: DICT__nodes from Topology.DICT__nodes.
        :type nodes: dict
        :raises RuntimeError: If the ssh command "lscpu -p" fails.
        """
        for node in nodes.values():
            cmd = "lscpu -p"
            ret, stdout, stderr = VPPUtil.exec_command(cmd)
            #           parsing of "lscpu -p" output:
            #           # CPU,Core,Socket,Node,,L1d,L1i,L2,L3
            #           0,0,0,0,,0,0,0,0
            #           1,1,0,0,,1,1,1,0
            if ret != 0:
                raise RuntimeError(
                    "Failed to execute ssh command, ret: {} err: {}".format(
                        ret, stderr))
            node['cpuinfo'] = list()
            for line in stdout.split("\n"):
                if line != '' and line[0] != "#":
                    node['cpuinfo'].append([CpuUtils.__str2int(x) for x in
                                            line.split(",")])

    @staticmethod
    def cpu_node_count(node):
        """Return count of numa nodes.

        :param node: Targeted node.
        :type node: dict
        :returns: Count of numa nodes.
        :rtype: int
        :raises RuntimeError: If node cpuinfo is not available.
        """
        cpu_info = node.get("cpuinfo")
        if cpu_info is not None:
            return node["cpuinfo"][-1][3] + 1
        else:
            raise RuntimeError("Node cpuinfo not available.")

    @staticmethod
    def cpu_list_per_node(node, cpu_node, smt_used=False):
        """Return node related list of CPU numbers.

        :param node: Node dictionary with cpuinfo.
        :param cpu_node: Numa node number.
        :param smt_used: True - we want to use SMT, otherwise false.
        :type node: dict
        :type cpu_node: int
        :type smt_used: bool
        :returns: List of cpu numbers related to numa from argument.
        :rtype: list of int
        :raises RuntimeError: If node cpuinfo is not available or if SMT is not
        enabled.
        """

        cpu_node = int(cpu_node)
        cpu_info = node.get("cpuinfo")
        if cpu_info is None:
            raise RuntimeError("Node cpuinfo not available.")

        smt_enabled = CpuUtils.is_smt_enabled(cpu_info)
        if not smt_enabled and smt_used:
            raise RuntimeError("SMT is not enabled.")

        cpu_list = []
        for cpu in cpu_info:
            if cpu[3] == cpu_node:
                cpu_list.append(cpu[0])

        if not smt_enabled or smt_enabled and smt_used:
            pass

        if smt_enabled and not smt_used:
            cpu_list_len = len(cpu_list)
            cpu_list = cpu_list[:cpu_list_len // CpuUtils.NR_OF_THREADS]

        return cpu_list

    @staticmethod
    def cpu_slice_of_list_per_node(node, cpu_node, skip_cnt=0, cpu_cnt=0,
                                   smt_used=False):
        """Return string of node related list of CPU numbers.

        :param node: Node dictionary with cpuinfo.
        :param cpu_node: Numa node number.
        :param skip_cnt: Skip first "skip_cnt" CPUs.
        :param cpu_cnt: Count of cpus to return, if 0 then return all.
        :param smt_used: True - we want to use SMT, otherwise false.
        :type node: dict
        :type cpu_node: int
        :type skip_cnt: int
        :type cpu_cnt: int
        :type smt_used: bool
        :returns: Cpu numbers related to numa from argument.
        :rtype: list
        :raises RuntimeError: If we require more cpus than available.
        """

        cpu_list = CpuUtils.cpu_list_per_node(node, cpu_node, smt_used)

        cpu_list_len = len(cpu_list)
        if cpu_cnt + skip_cnt > cpu_list_len:
            raise RuntimeError("cpu_cnt + skip_cnt > length(cpu list).")

        if cpu_cnt == 0:
            cpu_cnt = cpu_list_len - skip_cnt

        if smt_used:
            cpu_list_0 = cpu_list[:cpu_list_len // CpuUtils.NR_OF_THREADS]
            cpu_list_1 = cpu_list[cpu_list_len // CpuUtils.NR_OF_THREADS:]
            cpu_list = [cpu for cpu in cpu_list_0[skip_cnt:skip_cnt + cpu_cnt]]
            cpu_list_ex = [cpu for cpu in
                           cpu_list_1[skip_cnt:skip_cnt + cpu_cnt]]
            cpu_list.extend(cpu_list_ex)
        else:
            cpu_list = [cpu for cpu in cpu_list[skip_cnt:skip_cnt + cpu_cnt]]

        return cpu_list

    @staticmethod
    def cpu_list_per_node_str(node, cpu_node, skip_cnt=0, cpu_cnt=0, sep=",",
                              smt_used=False):
        """Return string of node related list of CPU numbers.

        :param node: Node dictionary with cpuinfo.
        :param cpu_node: Numa node number.
        :param skip_cnt: Skip first "skip_cnt" CPUs.
        :param cpu_cnt: Count of cpus to return, if 0 then return all.
        :param sep: Separator, default: 1,2,3,4,....
        :param smt_used: True - we want to use SMT, otherwise false.
        :type node: dict
        :type cpu_node: int
        :type skip_cnt: int
        :type cpu_cnt: int
        :type sep: str
        :type smt_used: bool
        :returns: Cpu numbers related to numa from argument.
        :rtype: str
        """

        cpu_list = CpuUtils.cpu_slice_of_list_per_node(node, cpu_node,
                                                       skip_cnt=skip_cnt,
                                                       cpu_cnt=cpu_cnt,
                                                       smt_used=smt_used)
        return sep.join(str(cpu) for cpu in cpu_list)

    @staticmethod
    def cpu_range_per_node_str(node, cpu_node, skip_cnt=0, cpu_cnt=0, sep="-",
                               smt_used=False):
        """Return string of node related range of CPU numbers, e.g. 0-4.

        :param node: Node dictionary with cpuinfo.
        :param cpu_node: Numa node number.
        :param skip_cnt: Skip first "skip_cnt" CPUs.
        :param cpu_cnt: Count of cpus to return, if 0 then return all.
        :param sep: Separator, default: "-".
        :param smt_used: True - we want to use SMT, otherwise false.
        :type node: dict
        :type cpu_node: int
        :type skip_cnt: int
        :type cpu_cnt: int
        :type sep: str
        :type smt_used: bool
        :returns: String of node related range of CPU numbers.
        :rtype: str
        """

        cpu_list = CpuUtils.cpu_slice_of_list_per_node(node, cpu_node,
                                                       skip_cnt=skip_cnt,
                                                       cpu_cnt=cpu_cnt,
                                                       smt_used=smt_used)
        if smt_used:
            cpu_list_len = len(cpu_list)
            cpu_list_0 = cpu_list[:cpu_list_len // CpuUtils.NR_OF_THREADS]
            cpu_list_1 = cpu_list[cpu_list_len // CpuUtils.NR_OF_THREADS:]
            cpu_range = "{}{}{},{}{}{}".format(cpu_list_0[0], sep,
                                               cpu_list_0[-1],
                                               cpu_list_1[0], sep,
                                               cpu_list_1[-1])
        else:
            cpu_range = "{}{}{}".format(cpu_list[0], sep, cpu_list[-1])

        return cpu_range

    @staticmethod
    def get_cpu_info_per_node(node):
        """Return node related list of CPU numbers.

        :param node: Node dictionary with cpuinfo.
        :type node: dict
        :returns: Important CPU information.
        :rtype: dict
        """

        cmd = "lscpu"
        ret, stdout, stderr = VPPUtil.exec_command(cmd)
        if ret != 0:
            raise RuntimeError("lscpu command failed on node {} {}."
                               .format(node['host'], stderr))

        cpuinfo = {}
        lines = stdout.split('\n')
        for line in lines:
            if line != '':
                linesplit = re.split(r':\s+', line)
                cpuinfo[linesplit[0]] = linesplit[1]

        cmd = "cat /proc/*/task/*/stat | awk '{print $1" "$2" "$39}'"
        ret, stdout, stderr = VPPUtil.exec_command(cmd)
        if ret != 0:
            raise RuntimeError("cat command failed on node {} {}."
                               .format(node['host'], stderr))

        vpp_processes = {}
        vpp_lines = re.findall(r'\w+\(vpp_\w+\)\w+', stdout)
        for line in vpp_lines:
            linesplit = re.split(r'\w+\(', line)[1].split(')')
            vpp_processes[linesplit[0]] = linesplit[1]

        cpuinfo['vpp_processes'] = vpp_processes

        return cpuinfo
