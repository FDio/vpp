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

"""Library that supports Auto Configuration."""
from __future__ import absolute_import, division, print_function

import logging
import os
import re
import yaml
from ipaddress import ip_address

from vpplib.VPPUtil import VPPUtil
from vpplib.VppPCIUtil import VppPCIUtil
from vpplib.VppHugePageUtil import VppHugePageUtil
from vpplib.CpuUtils import CpuUtils
from vpplib.VppGrubUtil import VppGrubUtil
from vpplib.QemuUtils import QemuUtils

#  Python2/3 compatible
try:
    input = raw_input  # noqa
except NameError:
    pass

__all__ = ["AutoConfig"]

# Constants
MIN_SYSTEM_CPUS = 2
MIN_TOTAL_HUGE_PAGES = 1024
MAX_PERCENT_FOR_HUGE_PAGES = 70

IPERFVM_XML = 'configs/iperf-vm.xml'
IPERFVM_IMAGE = 'images/xenial-mod.img'
IPERFVM_ISO = 'configs/cloud-config.iso'


class AutoConfig(object):
    """Auto Configuration Tools"""

    def __init__(self, rootdir, filename, clean=False):
        """
        The Auto Configure class.

        :param rootdir: The root directory for all the auto configuration files
        :param filename: The autoconfiguration file
        :param clean: When set initialize the nodes from the auto-config file
        :type rootdir: str
        :type filename: str
        :type clean: bool
        """
        self._autoconfig_filename = rootdir + filename
        self._rootdir = rootdir
        self._metadata = {}
        self._nodes = {}
        self._vpp_devices_node = {}
        self._hugepage_config = ""
        self._clean = clean
        self._loadconfig()
        self._sockfilename = ""

    def get_nodes(self):
        """
        Returns the nodes dictionary.

        :returns: The nodes
        :rtype: dictionary
        """

        return self._nodes

    @staticmethod
    def _autoconfig_backup_file(filename):
        """
        Create a backup file.

        :param filename: The file to backup
        :type filename: str
        """

        # Does a copy of the file exist, if not create one
        ofile = filename + '.orig'
        (ret, stdout, stderr) = VPPUtil.exec_command('ls {}'.format(ofile))
        if ret != 0:
            logging.debug(stderr)
            if stdout.strip('\n') != ofile:
                cmd = 'sudo cp {} {}'.format(filename, ofile)
                (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
                if ret != 0:
                    logging.debug(stderr)

    # noinspection PyBroadException
    @staticmethod
    def _ask_user_ipv4():
        """
        Asks the user for a number within a range.
        default is returned if return is entered.

        :returns: IP address with cidr
        :rtype: str
        """

        while True:
            answer = input("Please enter the IPv4 Address [n.n.n.n/n]: ")
            try:
                ipinput = answer.split('/')
                ipaddr = ip_address(ipinput[0])
                if len(ipinput) > 1:
                    plen = answer.split('/')[1]
                else:
                    answer = input("Please enter the netmask [n.n.n.n]: ")
                    plen = ip_address(answer).netmask_bits()
                return '{}/{}'.format(ipaddr, plen)
            except None:
                print("Please enter a valid IPv4 address.")

    @staticmethod
    def _ask_user_range(question, first, last, default):
        """
        Asks the user for a number within a range.
        default is returned if return is entered.

        :param question: Text of a question.
        :param first: First number in the range
        :param last: Last number in the range
        :param default: The value returned when return is entered
        :type question: string
        :type first: int
        :type last: int
        :type default: int
        :returns: The answer to the question
        :rtype: int
        """

        while True:
            answer = input(question)
            if answer == '':
                answer = default
                break
            if re.findall(r'[0-9+]', answer):
                if int(answer) in range(first, last + 1):
                    break
                else:
                    print("Please a value between {} and {} or Return.".
                          format(first, last))
            else:
                print("Please a number between {} and {} or Return.".
                      format(first, last))

        return int(answer)

    @staticmethod
    def _ask_user_yn(question, default):
        """
        Asks the user for a yes or no question.

        :param question: Text of a question.
        :param default: The value returned when return is entered
        :type question: string
        :type default: string
        :returns: The answer to the question
        :rtype: string
        """

        input_valid = False
        default = default.lower()
        answer = ''
        while not input_valid:
            answer = input(question)
            if answer == '':
                answer = default
            if re.findall(r'[YyNn]', answer):
                input_valid = True
                answer = answer[0].lower()
            else:
                print("Please answer Y, N or Return.")

        return answer

    def _loadconfig(self):
        """
        Load the testbed configuration, given the auto configuration file.

        """

        # Get the Topology, from the topology layout file
        topo = {}
        with open(self._autoconfig_filename, 'r') as stream:
            try:
                topo = yaml.load(stream)
                if 'metadata' in topo:
                    self._metadata = topo['metadata']
            except yaml.YAMLError as exc:
                raise RuntimeError(
                    "Couldn't read the Auto config file {}.".format(
                        self._autoconfig_filename, exc))

        systemfile = self._rootdir + self._metadata['system_config_file']
        if self._clean is False and os.path.isfile(systemfile):
            with open(systemfile, 'r') as sysstream:
                try:
                    systopo = yaml.load(sysstream)
                    if 'nodes' in systopo:
                        self._nodes = systopo['nodes']
                except yaml.YAMLError as sysexc:
                    raise RuntimeError(
                        "Couldn't read the System config file {}.".format(
                            systemfile, sysexc))
        else:
            # Get the nodes from Auto Config
            if 'nodes' in topo:
                self._nodes = topo['nodes']

        # Set the root directory in all the nodes
        for i in self._nodes.items():
            node = i[1]
            node['rootdir'] = self._rootdir

    def updateconfig(self):
        """
        Update the testbed configuration, given the auto configuration file.
        We will write the system configuration file with the current node
        information

        """

        # Initialize the yaml data
        ydata = {'metadata': self._metadata, 'nodes': self._nodes}

        # Write the system config file
        filename = self._rootdir + self._metadata['system_config_file']
        with open(filename, 'w') as yamlfile:
            yaml.dump(ydata, yamlfile)

    def _update_auto_config(self):
        """
        Write the auto configuration file with the new configuration data,
        input from the user.

        """

        # Initialize the yaml data
        nodes = {}
        with open(self._autoconfig_filename, 'r') as stream:
            try:
                ydata = yaml.load(stream)
                if 'nodes' in ydata:
                    nodes = ydata['nodes']
            except yaml.YAMLError as exc:
                print(exc)
                return

        for i in nodes.items():
            key = i[0]
            node = i[1]

            # Interfaces
            node['interfaces'] = {}
            for item in self._nodes[key]['interfaces'].items():
                port = item[0]
                interface = item[1]

                node['interfaces'][port] = {}
                addr = '{}'.format(interface['pci_address'])
                node['interfaces'][port]['pci_address'] = addr
                if 'mac_address' in interface:
                    node['interfaces'][port]['mac_address'] = \
                        interface['mac_address']

            if 'total_other_cpus' in self._nodes[key]['cpu']:
                node['cpu']['total_other_cpus'] = \
                    self._nodes[key]['cpu']['total_other_cpus']
            if 'total_vpp_cpus' in self._nodes[key]['cpu']:
                node['cpu']['total_vpp_cpus'] = \
                    self._nodes[key]['cpu']['total_vpp_cpus']
            if 'reserve_vpp_main_core' in self._nodes[key]['cpu']:
                node['cpu']['reserve_vpp_main_core'] = \
                    self._nodes[key]['cpu']['reserve_vpp_main_core']

            # TCP
            if 'active_open_sessions' in self._nodes[key]['tcp']:
                node['tcp']['active_open_sessions'] = \
                    self._nodes[key]['tcp']['active_open_sessions']
            if 'passive_open_sessions' in self._nodes[key]['tcp']:
                node['tcp']['passive_open_sessions'] = \
                    self._nodes[key]['tcp']['passive_open_sessions']

            # Huge pages
            node['hugepages']['total'] = self._nodes[key]['hugepages']['total']

        # Write the auto config config file
        with open(self._autoconfig_filename, 'w') as yamlfile:
            yaml.dump(ydata, yamlfile)

    def apply_huge_pages(self):
        """
        Apply the huge page config

        """

        for i in self._nodes.items():
            node = i[1]

            hpg = VppHugePageUtil(node)
            hpg.hugepages_dryrun_apply()

    @staticmethod
    def _apply_vpp_unix(node):
        """
        Apply the VPP Unix config

        :param node: Node dictionary with cpuinfo.
        :type node: dict
        """

        unix = '  nodaemon\n'
        if 'unix' not in node['vpp']:
            return ''

        unixv = node['vpp']['unix']
        if 'interactive' in unixv:
            interactive = unixv['interactive']
            if interactive is True:
                unix = '  interactive\n'

        return unix.rstrip('\n')

    @staticmethod
    def _apply_vpp_cpu(node):
        """
        Apply the VPP cpu config

        :param node: Node dictionary with cpuinfo.
        :type node: dict
        """

        # Get main core
        cpu = '\n'
        if 'vpp_main_core' in node['cpu']:
            vpp_main_core = node['cpu']['vpp_main_core']
        else:
            vpp_main_core = 0
        if vpp_main_core is not 0:
            cpu += '  main-core {}\n'.format(vpp_main_core)

        # Get workers
        vpp_workers = node['cpu']['vpp_workers']
        vpp_worker_len = len(vpp_workers)
        if vpp_worker_len > 0:
            vpp_worker_str = ''
            for i, worker in enumerate(vpp_workers):
                if i > 0:
                    vpp_worker_str += ','
                if worker[0] == worker[1]:
                    vpp_worker_str += "{}".format(worker[0])
                else:
                    vpp_worker_str += "{}-{}".format(worker[0], worker[1])

            cpu += '  corelist-workers {}\n'.format(vpp_worker_str)

        return cpu

    @staticmethod
    def _apply_vpp_devices(node):
        """
        Apply VPP PCI Device configuration to vpp startup.

        :param node: Node dictionary with cpuinfo.
        :type node: dict
        """

        devices = ''
        ports_per_numa = node['cpu']['ports_per_numa']
        total_mbufs = node['cpu']['total_mbufs']

        for item in ports_per_numa.items():
            value = item[1]
            interfaces = value['interfaces']

            # if 0 was specified for the number of vpp workers, use 1 queue
            num_rx_queues = None
            num_tx_queues = None
            if 'rx_queues' in value:
                num_rx_queues = value['rx_queues']
            if 'tx_queues' in value:
                num_tx_queues = value['tx_queues']

            num_rx_desc = None
            num_tx_desc = None

            # Create the devices string
            for interface in interfaces:
                pci_address = interface['pci_address']
                pci_address = pci_address.lstrip("'").rstrip("'")
                devices += '\n'
                devices += '  dev {} {{ \n'.format(pci_address)
                if num_rx_queues:
                    devices += '    num-rx-queues {}\n'.format(num_rx_queues)
                else:
                    devices += '    num-rx-queues {}\n'.format(1)
                if num_tx_queues:
                    devices += '    num-tx-queues {}\n'.format(num_tx_queues)
                if num_rx_desc:
                    devices += '    num-rx-desc {}\n'.format(num_rx_desc)
                if num_tx_desc:
                    devices += '    num-tx-desc {}\n'.format(num_tx_desc)
                devices += '  }'

        # If the total mbufs is not 0 or less than the default, set num-bufs
        logging.debug("Total mbufs: {}".format(total_mbufs))
        if total_mbufs is not 0 and total_mbufs > 16384:
            devices += '\n  num-mbufs {}'.format(total_mbufs)

        return devices

    @staticmethod
    def _calc_vpp_workers(node, vpp_workers, numa_node, other_cpus_end,
                          total_vpp_workers,
                          reserve_vpp_main_core):
        """
        Calculate the VPP worker information

        :param node: Node dictionary
        :param vpp_workers: List of VPP workers
        :param numa_node: Numa node
        :param other_cpus_end: The end of the cpus allocated for cores
        other than vpp
        :param total_vpp_workers: The number of vpp workers needed
        :param reserve_vpp_main_core: Is there a core needed for
        the vpp main core
        :type node: dict
        :type numa_node: int
        :type other_cpus_end: int
        :type total_vpp_workers: int
        :type reserve_vpp_main_core: bool
        :returns: Is a core still needed for the vpp main core
        :rtype: bool
        """

        # Can we fit the workers in one of these slices
        cpus = node['cpu']['cpus_per_node'][numa_node]
        for cpu in cpus:
            start = cpu[0]
            end = cpu[1]
            if start <= other_cpus_end:
                start = other_cpus_end + 1

            if reserve_vpp_main_core:
                start += 1

            workers_end = start + total_vpp_workers - 1

            if workers_end <= end:
                if reserve_vpp_main_core:
                    node['cpu']['vpp_main_core'] = start - 1
                reserve_vpp_main_core = False
                if total_vpp_workers:
                    vpp_workers.append((start, workers_end))
                break

        # We still need to reserve the main core
        if reserve_vpp_main_core:
            node['cpu']['vpp_main_core'] = other_cpus_end + 1

        return reserve_vpp_main_core

    @staticmethod
    def _calc_desc_and_queues(total_numa_nodes,
                              total_ports_per_numa,
                              total_rx_queues,
                              ports_per_numa_value):
        """
        Calculate the number of descriptors and queues

        :param total_numa_nodes: The total number of numa nodes
        :param total_ports_per_numa: The total number of ports for this
        numa node
        :param total_rx_queues: The total number of rx queues / port
        :param ports_per_numa_value: The value from the ports_per_numa
        dictionary
        :type total_numa_nodes: int
        :type total_ports_per_numa: int
        :type total_rx_queues: int
        :type ports_per_numa_value: dict
        :returns The total number of message buffers
        :rtype: int
        """

        # Get the number of rx queues
        rx_queues = max(1, total_rx_queues)
        tx_queues = rx_queues * total_numa_nodes + 1

        # Get the descriptor entries
        desc_entries = 1024
        ports_per_numa_value['rx_queues'] = rx_queues
        total_mbufs = (((rx_queues * desc_entries) +
                        (tx_queues * desc_entries)) *
                       total_ports_per_numa)
        total_mbufs = total_mbufs

        return total_mbufs

    @staticmethod
    def _create_ports_per_numa(node, interfaces):
        """
        Create a dictionary or ports per numa node
        :param node: Node dictionary
        :param interfaces: All the interfaces to be used by vpp
        :type node: dict
        :type interfaces: dict
        :returns: The ports per numa dictionary
        :rtype: dict
        """

        # Make a list of ports by numa node
        ports_per_numa = {}
        for item in interfaces.items():
            i = item[1]
            if i['numa_node'] not in ports_per_numa:
                ports_per_numa[i['numa_node']] = {'interfaces': []}
                ports_per_numa[i['numa_node']]['interfaces'].append(i)
            else:
                ports_per_numa[i['numa_node']]['interfaces'].append(i)
        node['cpu']['ports_per_numa'] = ports_per_numa

        return ports_per_numa

    def calculate_cpu_parameters(self):
        """
        Calculate the cpu configuration.

        """

        # Calculate the cpu parameters, needed for the
        # vpp_startup and grub configuration
        for i in self._nodes.items():
            node = i[1]

            # get total number of nic ports
            interfaces = node['interfaces']

            # Make a list of ports by numa node
            ports_per_numa = self._create_ports_per_numa(node, interfaces)

            # Get the number of cpus to skip, we never use the first cpu
            other_cpus_start = 1
            other_cpus_end = other_cpus_start + \
                node['cpu']['total_other_cpus'] - 1
            other_workers = None
            if other_cpus_end is not 0:
                other_workers = (other_cpus_start, other_cpus_end)
            node['cpu']['other_workers'] = other_workers

            # Allocate the VPP main core and workers
            vpp_workers = []
            reserve_vpp_main_core = node['cpu']['reserve_vpp_main_core']
            total_vpp_cpus = node['cpu']['total_vpp_cpus']
            total_rx_queues = node['cpu']['total_rx_queues']

            # If total_vpp_cpus is 0 or is less than the numa nodes with ports
            #  then we shouldn't get workers
            total_workers_node = 0
            if len(ports_per_numa):
                total_workers_node = total_vpp_cpus / len(ports_per_numa)
            total_main = 0
            if reserve_vpp_main_core:
                total_main = 1
            total_mbufs = 0
            if total_main + total_workers_node is not 0:
                for item in ports_per_numa.items():
                    numa_node = item[0]
                    value = item[1]

                    # Get the number of descriptors and queues
                    mbufs = self._calc_desc_and_queues(
                        len(ports_per_numa),
                        len(value['interfaces']), total_rx_queues, value)
                    total_mbufs += mbufs

                    # Get the VPP workers
                    reserve_vpp_main_core = self._calc_vpp_workers(
                        node, vpp_workers, numa_node,
                        other_cpus_end, total_workers_node,
                        reserve_vpp_main_core)

                total_mbufs *= 2.5
                total_mbufs = int(total_mbufs)
            else:
                total_mbufs = 0

            # Save the info
            node['cpu']['vpp_workers'] = vpp_workers
            node['cpu']['total_mbufs'] = total_mbufs

        # Write the config
        self.updateconfig()

    @staticmethod
    def _apply_vpp_tcp(node):
        """
        Apply the VPP Unix config

        :param node: Node dictionary with cpuinfo.
        :type node: dict
        """

        active_open_sessions = node['tcp']['active_open_sessions']
        aos = int(active_open_sessions)

        passive_open_sessions = node['tcp']['passive_open_sessions']
        pos = int(passive_open_sessions)

        # Generate the api-segment gid vpp sheit in any case
        if (aos + pos) == 0:
            tcp = '\n'.join([
                "api-segment {",
                "  gid vpp",
                "}"
            ])
            return tcp.rstrip('\n')

        tcp = '\n'.join([
            "# TCP stack-related configuration parameters",
            "# expecting {:d} client sessions, {:d} server sessions\n".format(
                aos, pos),
            "heapsize 4g\n",
            "api-segment {",
            "  global-size 2000M",
            "  api-size 1G",
            "}\n",

            "session {",
            "  event-queue-length {:d}".format(aos + pos),
            "  preallocated-sessions {:d}".format(aos + pos),
            "  v4-session-table-buckets {:d}".format((aos + pos) // 4),
            "  v4-session-table-memory 3g\n"
        ])
        if aos > 0:
            tcp = tcp + "  v4-halfopen-table-buckets {:d}".format(
                (aos + pos) // 4) + "\n"
            tcp = tcp + "  v4-halfopen-table-memory 3g\n"
            tcp = tcp + "  local-endpoints-table-buckets {:d}".format(
                (aos + pos) // 4) + "\n"
            tcp = tcp + "  local-endpoints-table-memory 3g\n"
        tcp = tcp + "}\n\n"

        tcp = tcp + "tcp {\n"
        tcp = tcp + "  preallocated-connections {:d}".format(aos + pos) + "\n"
        if aos > 0:
            tcp = tcp + "  preallocated-half-open-connections {:d}".format(
                aos) + "\n"
        tcp = tcp + "}\n\n"

        return tcp.rstrip('\n')

    def apply_vpp_startup(self):
        """
        Apply the vpp startup configration

        """

        # Apply the VPP startup configruation
        for i in self._nodes.items():
            node = i[1]

            # Get the startup file
            rootdir = node['rootdir']
            sfile = rootdir + node['vpp']['startup_config_file']

            # Get the devices
            devices = self._apply_vpp_devices(node)

            # Get the CPU config
            cpu = self._apply_vpp_cpu(node)

            # Get the unix config
            unix = self._apply_vpp_unix(node)

            # Get the TCP configuration, if any
            tcp = self._apply_vpp_tcp(node)

            # Make a backup if needed
            self._autoconfig_backup_file(sfile)

            # Get the template
            tfile = sfile + '.template'
            (ret, stdout, stderr) = \
                VPPUtil.exec_command('cat {}'.format(tfile))
            if ret != 0:
                raise RuntimeError('Executing cat command failed to node {}'.
                                   format(node['host']))
            startup = stdout.format(unix=unix,
                                    cpu=cpu,
                                    devices=devices,
                                    tcp=tcp)

            (ret, stdout, stderr) = \
                VPPUtil.exec_command('rm {}'.format(sfile))
            if ret != 0:
                logging.debug(stderr)

            cmd = "sudo cat > {0} << EOF\n{1}\n".format(sfile, startup)
            (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
            if ret != 0:
                raise RuntimeError('Writing config failed node {}'.
                                   format(node['host']))

    def apply_grub_cmdline(self):
        """
        Apply the grub cmdline

        """

        for i in self._nodes.items():
            node = i[1]

            # Get the isolated CPUs
            other_workers = node['cpu']['other_workers']
            vpp_workers = node['cpu']['vpp_workers']
            if 'vpp_main_core' in node['cpu']:
                vpp_main_core = node['cpu']['vpp_main_core']
            else:
                vpp_main_core = 0
            all_workers = []
            if other_workers is not None:
                all_workers = [other_workers]
            if vpp_main_core is not 0:
                all_workers += [(vpp_main_core, vpp_main_core)]
            all_workers += vpp_workers
            isolated_cpus = ''
            for idx, worker in enumerate(all_workers):
                if worker is None:
                    continue
                if idx > 0:
                    isolated_cpus += ','
                if worker[0] == worker[1]:
                    isolated_cpus += "{}".format(worker[0])
                else:
                    isolated_cpus += "{}-{}".format(worker[0], worker[1])

            vppgrb = VppGrubUtil(node)
            current_cmdline = vppgrb.get_current_cmdline()
            if 'grub' not in node:
                node['grub'] = {}
            node['grub']['current_cmdline'] = current_cmdline
            node['grub']['default_cmdline'] = \
                vppgrb.apply_cmdline(node, isolated_cpus)

        self.updateconfig()

    def get_hugepages(self):
        """
        Get the hugepage configuration

        """

        for i in self._nodes.items():
            node = i[1]

            hpg = VppHugePageUtil(node)
            max_map_count, shmmax = hpg.get_huge_page_config()
            node['hugepages']['max_map_count'] = max_map_count
            node['hugepages']['shmax'] = shmmax
            total, free, size, memtotal, memfree = hpg.get_actual_huge_pages()
            node['hugepages']['actual_total'] = total
            node['hugepages']['free'] = free
            node['hugepages']['size'] = size
            node['hugepages']['memtotal'] = memtotal
            node['hugepages']['memfree'] = memfree

        self.updateconfig()

    def get_grub(self):
        """
        Get the grub configuration

        """

        for i in self._nodes.items():
            node = i[1]

            vppgrb = VppGrubUtil(node)
            current_cmdline = vppgrb.get_current_cmdline()
            default_cmdline = vppgrb.get_default_cmdline()

            # Get the total number of isolated CPUs
            current_iso_cpus = 0
            iso_cpur = re.findall(r'isolcpus=[\w+\-,]+', current_cmdline)
            iso_cpurl = len(iso_cpur)
            if iso_cpurl > 0:
                iso_cpu_str = iso_cpur[0]
                iso_cpu_str = iso_cpu_str.split('=')[1]
                iso_cpul = iso_cpu_str.split(',')
                for iso_cpu in iso_cpul:
                    isocpuspl = iso_cpu.split('-')
                    if len(isocpuspl) is 1:
                        current_iso_cpus += 1
                    else:
                        first = int(isocpuspl[0])
                        second = int(isocpuspl[1])
                        if first == second:
                            current_iso_cpus += 1
                        else:
                            current_iso_cpus += second - first

            if 'grub' not in node:
                node['grub'] = {}
            node['grub']['current_cmdline'] = current_cmdline
            node['grub']['default_cmdline'] = default_cmdline
            node['grub']['current_iso_cpus'] = current_iso_cpus

        self.updateconfig()

    @staticmethod
    def _get_device(node):
        """
        Get the device configuration for a single node

        :param node: Node dictionary with cpuinfo.
        :type node: dict

        """

        vpp = VppPCIUtil(node)
        vpp.get_all_devices()

        # Save the device information
        node['devices'] = {}
        node['devices']['dpdk_devices'] = vpp.get_dpdk_devices()
        node['devices']['kernel_devices'] = vpp.get_kernel_devices()
        node['devices']['other_devices'] = vpp.get_other_devices()
        node['devices']['linkup_devices'] = vpp.get_link_up_devices()

    def get_devices_per_node(self):
        """
        Get the device configuration for all the nodes

        """

        for i in self._nodes.items():
            node = i[1]
            # Update the interface data

            self._get_device(node)

        self.updateconfig()

    @staticmethod
    def get_cpu_layout(node):
        """
        Get the cpu layout

        using lscpu -p get the cpu layout.
        Returns a list with each item representing a single cpu.

        :param node: Node dictionary.
        :type node: dict
        :returns: The cpu layout
        :rtype: list
        """

        cmd = 'lscpu -p'
        (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
        if ret != 0:
            raise RuntimeError('{} failed on node {} {}'.
                               format(cmd, node['host'], stderr))

        pcpus = []
        lines = stdout.split('\n')
        for line in lines:
            if line == '' or line[0] == '#':
                continue
            linesplit = line.split(',')
            layout = {'cpu': linesplit[0], 'core': linesplit[1],
                      'socket': linesplit[2], 'node': linesplit[3]}

            # cpu, core, socket, node
            pcpus.append(layout)

        return pcpus

    def get_cpu(self):
        """
        Get the cpu configuration

        """

        # Get the CPU layout
        CpuUtils.get_cpu_layout_from_all_nodes(self._nodes)

        for i in self._nodes.items():
            node = i[1]

            # Get the cpu layout
            layout = self.get_cpu_layout(node)
            node['cpu']['layout'] = layout

            cpuinfo = node['cpuinfo']
            smt_enabled = CpuUtils.is_smt_enabled(cpuinfo)
            node['cpu']['smt_enabled'] = smt_enabled

            # We don't want to write the cpuinfo
            node['cpuinfo'] = ""

        # Write the config
        self.updateconfig()

    def discover(self):
        """
        Get the current system configuration.

        """

        # Get the Huge Page configuration
        self.get_hugepages()

        # Get the device configuration
        self.get_devices_per_node()

        # Get the CPU configuration
        self.get_cpu()

        # Get the current grub cmdline
        self.get_grub()

    def _modify_cpu_questions(self, node, total_cpus, numa_nodes):
        """
        Ask the user questions related to the cpu configuration.

        :param node: Node dictionary
        :param total_cpus: The total number of cpus in the system
        :param numa_nodes: The list of numa nodes in the system
        :type node: dict
        :type total_cpus: int
        :type numa_nodes: list
        """

        print("\nYour system has {} core(s) and {} Numa Nodes.".
              format(total_cpus, len(numa_nodes)))
        print("To begin, we suggest not reserving any cores for "
              "VPP or other processes.")
        print("Then to improve performance start reserving cores and "
              "adding queues as needed.")

        max_vpp_cpus = 4
        total_vpp_cpus = 0
        if max_vpp_cpus > 0:
            question = "\nHow many core(s) shall we reserve for " \
                       "VPP [0-{}][0]? ".format(max_vpp_cpus)
            total_vpp_cpus = self._ask_user_range(question, 0, max_vpp_cpus, 0)
            node['cpu']['total_vpp_cpus'] = total_vpp_cpus

        max_other_cores = (total_cpus - total_vpp_cpus) / 2
        question = 'How many core(s) do you want to reserve for ' \
                   'processes other than VPP? [0-{}][0]? '. \
            format(str(max_other_cores))
        total_other_cpus = self._ask_user_range(
            question, 0, max_other_cores, 0)
        node['cpu']['total_other_cpus'] = total_other_cpus

        max_main_cpus = max_vpp_cpus + 1 - total_vpp_cpus
        reserve_vpp_main_core = False
        if max_main_cpus > 0:
            question = "Should we reserve 1 core for the VPP Main thread? "
            question += "[y/N]? "
            answer = self._ask_user_yn(question, 'n')
            if answer == 'y':
                reserve_vpp_main_core = True
            node['cpu']['reserve_vpp_main_core'] = reserve_vpp_main_core
            node['cpu']['vpp_main_core'] = 0

        question = "How many RX queues per port shall we use for " \
                   "VPP [1-4][1]? ".format(max_vpp_cpus)
        total_rx_queues = self._ask_user_range(question, 1, 4, 1)
        node['cpu']['total_rx_queues'] = total_rx_queues

    def modify_cpu(self, ask_questions=True):
        """
        Modify the cpu configuration, asking for the user for the values.

        :param ask_questions: When true ask the user for config parameters

        """

        # Get the CPU layout
        CpuUtils.get_cpu_layout_from_all_nodes(self._nodes)

        for i in self._nodes.items():
            node = i[1]
            total_cpus = 0
            total_cpus_per_slice = 0
            cpus_per_node = {}
            numa_nodes = []
            cores = []
            cpu_layout = self.get_cpu_layout(node)

            # Assume the number of cpus per slice is always the same as the
            # first slice
            first_node = '0'
            for cpu in cpu_layout:
                if cpu['node'] != first_node:
                    break
                total_cpus_per_slice += 1

            # Get the total number of cpus, cores, and numa nodes from the
            # cpu layout
            for cpul in cpu_layout:
                numa_node = cpul['node']
                core = cpul['core']
                cpu = cpul['cpu']
                total_cpus += 1

                if numa_node not in cpus_per_node:
                    cpus_per_node[numa_node] = []
                cpuperslice = int(cpu) % total_cpus_per_slice
                if cpuperslice == 0:
                    cpus_per_node[numa_node].append((int(cpu), int(cpu) +
                                                     total_cpus_per_slice - 1))
                if numa_node not in numa_nodes:
                    numa_nodes.append(numa_node)
                if core not in cores:
                    cores.append(core)
            node['cpu']['cpus_per_node'] = cpus_per_node

            # Ask the user some questions
            if ask_questions and total_cpus >= 8:
                self._modify_cpu_questions(node, total_cpus, numa_nodes)

            # Populate the interfaces with the numa node
            if 'interfaces' in node:
                ikeys = node['interfaces'].keys()
                VPPUtil.get_interfaces_numa_node(node, *tuple(ikeys))

            # We don't want to write the cpuinfo
            node['cpuinfo'] = ""

        # Write the configs
        self._update_auto_config()
        self.updateconfig()

    def _modify_other_devices(self, node,
                              other_devices, kernel_devices, dpdk_devices):
        """
        Modify the devices configuration, asking for the user for the values.

        """

        odevices_len = len(other_devices)
        if odevices_len > 0:
            print("\nThese device(s) are currently NOT being used "
                  "by VPP or the OS.\n")
            VppPCIUtil.show_vpp_devices(other_devices, show_interfaces=False)
            question = "\nWould you like to give any of these devices"
            question += " back to the OS [Y/n]? "
            answer = self._ask_user_yn(question, 'Y')
            if answer == 'y':
                vppd = {}
                for dit in other_devices.items():
                    dvid = dit[0]
                    device = dit[1]
                    question = "Would you like to use device {} for". \
                        format(dvid)
                    question += " the OS [y/N]? "
                    answer = self._ask_user_yn(question, 'n')
                    if answer == 'y':
                        if 'unused' in device and len(
                                device['unused']) != 0 and \
                                device['unused'][0] != '':
                            driver = device['unused'][0]
                            ret = VppPCIUtil.bind_vpp_device(
                                node, driver, dvid)
                            if ret:
                                logging.debug(
                                    'Could not bind device {}'.format(dvid))
                            else:
                                vppd[dvid] = device
                for dit in vppd.items():
                    dvid = dit[0]
                    device = dit[1]
                    kernel_devices[dvid] = device
                    del other_devices[dvid]

        odevices_len = len(other_devices)
        if odevices_len > 0:
            print("\nThese device(s) are still NOT being used "
                  "by VPP or the OS.\n")
            VppPCIUtil.show_vpp_devices(other_devices, show_interfaces=False)
            question = "\nWould you like use any of these for VPP [y/N]? "
            answer = self._ask_user_yn(question, 'N')
            if answer == 'y':
                vppd = {}
                for dit in other_devices.items():
                    dvid = dit[0]
                    device = dit[1]
                    question = "Would you like to use device {} ".format(dvid)
                    question += "for VPP [y/N]? "
                    answer = self._ask_user_yn(question, 'n')
                    if answer == 'y':
                        vppd[dvid] = device
                for dit in vppd.items():
                    dvid = dit[0]
                    device = dit[1]
                    if 'unused' in device and len(device['unused']) != 0 and \
                            device['unused'][0] != '':
                        driver = device['unused'][0]
                        logging.debug(
                            'Binding device {} to driver {}'.format(dvid,
                                                                    driver))
                        ret = VppPCIUtil.bind_vpp_device(node, driver, dvid)
                        if ret:
                            logging.debug(
                                'Could not bind device {}'.format(dvid))
                        else:
                            dpdk_devices[dvid] = device
                            del other_devices[dvid]

    def update_interfaces_config(self):
        """
        Modify the interfaces directly from the config file.

        """

        for i in self._nodes.items():
            node = i[1]
            devices = node['devices']
            all_devices = devices['other_devices']
            all_devices.update(devices['dpdk_devices'])
            all_devices.update(devices['kernel_devices'])

            current_ifcs = {}
            interfaces = {}
            if 'interfaces' in node:
                current_ifcs = node['interfaces']
            if current_ifcs:
                for ifc in current_ifcs.values():
                    dvid = ifc['pci_address']
                    if dvid in all_devices:
                        VppPCIUtil.vpp_create_interface(interfaces, dvid,
                                                        all_devices[dvid])
            node['interfaces'] = interfaces

        self.updateconfig()

    def modify_devices(self):
        """
        Modify the devices configuration, asking for the user for the values.

        """

        for i in self._nodes.items():
            node = i[1]
            devices = node['devices']
            other_devices = devices['other_devices']
            kernel_devices = devices['kernel_devices']
            dpdk_devices = devices['dpdk_devices']

            if other_devices:
                self._modify_other_devices(node, other_devices,
                                           kernel_devices, dpdk_devices)

                # Get the devices again for this node
                self._get_device(node)
                devices = node['devices']
                kernel_devices = devices['kernel_devices']
                dpdk_devices = devices['dpdk_devices']

            klen = len(kernel_devices)
            if klen > 0:
                print("\nThese devices have kernel interfaces, but "
                      "appear to be safe to use with VPP.\n")
                VppPCIUtil.show_vpp_devices(kernel_devices)
                question = "\nWould you like to use any of these " \
                           "device(s) for VPP [y/N]? "
                answer = self._ask_user_yn(question, 'n')
                if answer == 'y':
                    vppd = {}
                    for dit in kernel_devices.items():
                        dvid = dit[0]
                        device = dit[1]
                        question = "Would you like to use device {} ". \
                            format(dvid)
                        question += "for VPP [y/N]? "
                        answer = self._ask_user_yn(question, 'n')
                        if answer == 'y':
                            vppd[dvid] = device
                    for dit in vppd.items():
                        dvid = dit[0]
                        device = dit[1]
                        if 'unused' in device and len(
                                device['unused']) != 0 and device['unused'][
                                0] != '':
                            driver = device['unused'][0]
                            logging.debug(
                                'Binding device {} to driver {}'.format(
                                    dvid, driver))
                            ret = VppPCIUtil.bind_vpp_device(
                                node, driver, dvid)
                            if ret:
                                logging.debug(
                                    'Could not bind device {}'.format(dvid))
                            else:
                                dpdk_devices[dvid] = device
                                del kernel_devices[dvid]

            dlen = len(dpdk_devices)
            if dlen > 0:
                print("\nThese device(s) will be used by VPP.\n")
                VppPCIUtil.show_vpp_devices(dpdk_devices,
                                            show_interfaces=False)
                question = "\nWould you like to remove any of "
                question += "these device(s) [y/N]? "
                answer = self._ask_user_yn(question, 'n')
                if answer == 'y':
                    vppd = {}
                    for dit in dpdk_devices.items():
                        dvid = dit[0]
                        device = dit[1]
                        question = "Would you like to remove {} [y/N]? ". \
                            format(dvid)
                        answer = self._ask_user_yn(question, 'n')
                        if answer == 'y':
                            vppd[dvid] = device
                    for dit in vppd.items():
                        dvid = dit[0]
                        device = dit[1]
                        if 'unused' in device and len(
                                device['unused']) != 0 and device['unused'][
                                0] != '':
                            driver = device['unused'][0]
                            logging.debug(
                                'Binding device {} to driver {}'.format(
                                    dvid, driver))
                            ret = VppPCIUtil.bind_vpp_device(node, driver,
                                                             dvid)
                            if ret:
                                logging.debug(
                                    'Could not bind device {}'.format(dvid))
                            else:
                                kernel_devices[dvid] = device
                                del dpdk_devices[dvid]

            interfaces = {}
            for dit in dpdk_devices.items():
                dvid = dit[0]
                device = dit[1]
                VppPCIUtil.vpp_create_interface(interfaces, dvid, device)
            node['interfaces'] = interfaces

            print("\nThese device(s) will be used by VPP, please "
                  "rerun this option if this is incorrect.\n")
            VppPCIUtil.show_vpp_devices(dpdk_devices, show_interfaces=False)

        self._update_auto_config()
        self.updateconfig()

    def modify_huge_pages(self):
        """
        Modify the huge page configuration, asking for the user for the values.

        """

        for i in self._nodes.items():
            node = i[1]

            total = node['hugepages']['actual_total']
            free = node['hugepages']['free']
            size = node['hugepages']['size']
            memfree = node['hugepages']['memfree'].split(' ')[0]
            hugesize = int(size.split(' ')[0])
            # The max number of huge pages should be no more than
            # 70% of total free memory
            maxpages = (int(memfree) * MAX_PERCENT_FOR_HUGE_PAGES // 100) // \
                hugesize
            print("\nThere currently {} {} huge pages free.".format(
                free, size))
            question = "Do you want to reconfigure the number of " \
                       "huge pages [y/N]? "
            answer = self._ask_user_yn(question, 'n')
            if answer == 'n':
                node['hugepages']['total'] = total
                continue

            print("\nThere currently a total of {} huge pages.".
                  format(total))
            question = "How many huge pages do you want [{} - {}][{}]? ". \
                format(MIN_TOTAL_HUGE_PAGES, maxpages, MIN_TOTAL_HUGE_PAGES)
            answer = self._ask_user_range(question, 1024, maxpages, 1024)
            node['hugepages']['total'] = str(answer)

        # Update auto-config.yaml
        self._update_auto_config()

        # Rediscover just the hugepages
        self.get_hugepages()

    def get_tcp_params(self):
        """
        Get the tcp configuration

        """
        # maybe nothing to do here?
        self.updateconfig()

    def acquire_tcp_params(self):
        """
        Ask the user for TCP stack configuration parameters

        """

        for i in self._nodes.items():
            node = i[1]

            question = "\nHow many active-open / tcp client sessions are " \
                       "expected [0-10000000][0]? "
            answer = self._ask_user_range(question, 0, 10000000, 0)
            # Less than 10K is equivalent to 0
            if int(answer) < 10000:
                answer = 0
            node['tcp']['active_open_sessions'] = answer

            question = "How many passive-open / tcp server sessions are " \
                       "expected [0-10000000][0]? "
            answer = self._ask_user_range(question, 0, 10000000, 0)
            # Less than 10K is equivalent to 0
            if int(answer) < 10000:
                answer = 0
            node['tcp']['passive_open_sessions'] = answer

        # Update auto-config.yaml
        self._update_auto_config()

        # Rediscover tcp parameters
        self.get_tcp_params()

    @staticmethod
    def patch_qemu(node):
        """
        Patch qemu with the correct patches.

        :param node: Node dictionary
        :type node: dict
        """

        print('\nWe are patching the node "{}":\n'.format(node['host']))
        QemuUtils.build_qemu(node, force_install=True, apply_patch=True)

    @staticmethod
    def cpu_info(node):
        """
        print the CPU information

        """

        cpu = CpuUtils.get_cpu_info_per_node(node)

        item = 'Model name'
        if item in cpu:
            print("{:>20}:    {}".format(item, cpu[item]))
        item = 'CPU(s)'
        if item in cpu:
            print("{:>20}:    {}".format(item, cpu[item]))
        item = 'Thread(s) per core'
        if item in cpu:
            print("{:>20}:    {}".format(item, cpu[item]))
        item = 'Core(s) per socket'
        if item in cpu:
            print("{:>20}:    {}".format(item, cpu[item]))
        item = 'Socket(s)'
        if item in cpu:
            print("{:>20}:    {}".format(item, cpu[item]))
        item = 'NUMA node(s)'
        numa_nodes = 0
        if item in cpu:
            numa_nodes = int(cpu[item])
        for i in range(0, numa_nodes):
            item = "NUMA node{} CPU(s)".format(i)
            print("{:>20}:    {}".format(item, cpu[item]))
        item = 'CPU max MHz'
        if item in cpu:
            print("{:>20}:    {}".format(item, cpu[item]))
        item = 'CPU min MHz'
        if item in cpu:
            print("{:>20}:    {}".format(item, cpu[item]))

        if node['cpu']['smt_enabled']:
            smt = 'Enabled'
        else:
            smt = 'Disabled'
        print("{:>20}:    {}".format('SMT', smt))

        # VPP Threads
        print("\nVPP Threads: (Name: Cpu Number)")
        vpp_processes = cpu['vpp_processes']
        for i in vpp_processes.items():
            print("  {:10}: {:4}".format(i[0], i[1]))

    @staticmethod
    def device_info(node):
        """
        Show the device information.

        """

        if 'cpu' in node and 'total_mbufs' in node['cpu']:
            total_mbufs = node['cpu']['total_mbufs']
            if total_mbufs is not 0:
                print("Total Number of Buffers: {}".format(total_mbufs))

        vpp = VppPCIUtil(node)
        vpp.get_all_devices()
        linkup_devs = vpp.get_link_up_devices()
        if len(linkup_devs):
            print("\nDevices with link up (can not be used with VPP):")
            vpp.show_vpp_devices(linkup_devs, show_header=False)
            # for dev in linkup_devs:
            #    print ("    " + dev)
        kernel_devs = vpp.get_kernel_devices()
        if len(kernel_devs):
            print("\nDevices bound to kernel drivers:")
            vpp.show_vpp_devices(kernel_devs, show_header=False)
        else:
            print("\nNo devices bound to kernel drivers")

        dpdk_devs = vpp.get_dpdk_devices()
        if len(dpdk_devs):
            print("\nDevices bound to DPDK drivers:")
            vpp.show_vpp_devices(dpdk_devs, show_interfaces=True,
                                 show_header=False)
        else:
            print("\nNo devices bound to DPDK drivers")

        other_devs = vpp.get_other_devices()
        if len(other_devs):
            print("\nDevices not bound to Kernel or DPDK drivers:")
            vpp.show_vpp_devices(other_devs, show_interfaces=True,
                                 show_header=False)
        else:
            print("\nNo devices not bound to Kernel or DPDK drivers")

        vpputl = VPPUtil()
        interfaces = vpputl.get_hardware(node)
        if interfaces == {}:
            return

        print("\nDevices in use by VPP:")

        if len(interfaces.items()) < 2:
            print("None")
            return

        print("{:30} {:4} {:4} {:7} {:4} {:7}".
              format('Name', 'Numa', 'RXQs',
                     'RXDescs', 'TXQs', 'TXDescs'))
        for intf in sorted(interfaces.items()):
            name = intf[0]
            value = intf[1]
            if name == 'local0':
                continue
            numa = rx_qs = rx_ds = tx_qs = tx_ds = ''
            if 'numa' in value:
                numa = int(value['numa'])
            if 'rx queues' in value:
                rx_qs = int(value['rx queues'])
            if 'rx descs' in value:
                rx_ds = int(value['rx descs'])
            if 'tx queues' in value:
                tx_qs = int(value['tx queues'])
            if 'tx descs' in value:
                tx_ds = int(value['tx descs'])

            print("{:30} {:>4} {:>4} {:>7} {:>4} {:>7}".
                  format(name, numa, rx_qs, rx_ds, tx_qs, tx_ds))

    @staticmethod
    def hugepage_info(node):
        """
        Show the huge page information.

        """

        hpg = VppHugePageUtil(node)
        hpg.show_huge_pages()

    @staticmethod
    def min_system_resources(node):
        """
        Check the system for basic minimum resources, return true if
        there is enough.

        :returns: boolean
        :rtype: dict
        """

        min_sys_res = True

        # CPUs
        if 'layout' in node['cpu']:
            total_cpus = len(node['cpu']['layout'])
            if total_cpus < 2:
                print("\nThere is only {} CPU(s) available on this system. "
                      "This is not enough to run VPP.".format(total_cpus))
                min_sys_res = False

        # System Memory
        if 'free' in node['hugepages'] and \
                'memfree' in node['hugepages'] and \
                'size' in node['hugepages']:
            free = node['hugepages']['free']
            memfree = float(node['hugepages']['memfree'].split(' ')[0])
            hugesize = float(node['hugepages']['size'].split(' ')[0])

            memhugepages = MIN_TOTAL_HUGE_PAGES * hugesize
            percentmemhugepages = (memhugepages / memfree) * 100
            if free is '0' and \
                    percentmemhugepages > MAX_PERCENT_FOR_HUGE_PAGES:
                print(
                    "\nThe System has only {} of free memory. You will not "
                    "be able to allocate enough Huge Pages for VPP.".format(
                        int(
                            memfree))
                )
                min_sys_res = False

        return min_sys_res

    def sys_info(self):
        """
        Print the system information

        """

        for i in self._nodes.items():
            print("\n==============================")
            name = i[0]
            node = i[1]

            print("NODE: {}\n".format(name))

            # CPU
            print("CPU:")
            self.cpu_info(node)

            # Grub
            print("\nGrub Command Line:")
            if 'grub' in node:
                print("  Current: {}".format(
                    node['grub']['current_cmdline']))
                print("  Configured: {}".format(
                    node['grub']['default_cmdline']))

            # Huge Pages
            print("\nHuge Pages:")
            self.hugepage_info(node)

            # Devices
            print("\nDevices:")
            self.device_info(node)

            # Status
            print("\nVPP Service Status:")
            state, errors = VPPUtil.status(node)
            print("  {}".format(state))
            for e in errors:
                print("  {}".format(e))

            # Minimum system resources
            self.min_system_resources(node)

            print("\n==============================")

    def _ipv4_interface_setup_questions(self, node):
        """
        Ask the user some questions and get a list of interfaces
        and IPv4 addresses associated with those interfaces

        :param node: Node dictionary.
        :type node: dict
        :returns: A list or interfaces with ip addresses
        :rtype: dict
        """

        vpputl = VPPUtil()
        interfaces = vpputl.get_hardware(node)
        if interfaces == {}:
            return

        interfaces_with_ip = []
        for intf in sorted(interfaces.items()):
            name = intf[0]
            if name == 'local0':
                continue

            question = "Would you like add address to " \
                       "interface {} [Y/n]? ".format(name)
            answer = self._ask_user_yn(question, 'y')
            if answer == 'y':
                address = {}
                addr = self._ask_user_ipv4()
                address['name'] = name
                address['addr'] = addr
                interfaces_with_ip.append(address)

        return interfaces_with_ip

    def ipv4_interface_setup(self):
        """
        After asking the user some questions, get a list of interfaces
        and IPv4 addresses associated with those interfaces

        """

        for i in self._nodes.items():
            node = i[1]

            # Show the current interfaces with IP addresses
            current_ints = VPPUtil.get_int_ip(node)
            if current_ints is not {}:
                print("\nThese are the current interfaces with IP addresses:")
                for items in sorted(current_ints.items()):
                    name = items[0]
                    value = items[1]
                    if 'address' not in value:
                        address = 'Not Set'
                    else:
                        address = value['address']
                    print("{:30} {:20} {:10}".format(name, address,
                                                     value['state']))
                question = "\nWould you like to keep this configuration " \
                           "[Y/n]? "
                answer = self._ask_user_yn(question, 'y')
                if answer == 'y':
                    continue
            else:
                print("\nThere are currently no interfaces with IP "
                      "addresses.")

            # Create a script that add the ip addresses to the interfaces
            # and brings the interfaces up
            ints_with_addrs = self._ipv4_interface_setup_questions(node)
            content = ''
            for ints in ints_with_addrs:
                name = ints['name']
                addr = ints['addr']
                setipstr = 'set int ip address {} {}\n'.format(name, addr)
                setintupstr = 'set int state {} up\n'.format(name)
                content += setipstr + setintupstr

            # Write the content to the script
            rootdir = node['rootdir']
            filename = rootdir + '/vpp/vpp-config/scripts/set_int_ipv4_and_up'
            with open(filename, 'w+') as sfile:
                sfile.write(content)

            # Execute the script
            cmd = 'vppctl exec {}'.format(filename)
            (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
            if ret != 0:
                logging.debug(stderr)

            print("\nA script as been created at {}".format(filename))
            print("This script can be run using the following:")
            print("vppctl exec {}\n".format(filename))

    def _create_vints_questions(self, node):
        """
        Ask the user some questions and get a list of interfaces
        and IPv4 addresses associated with those interfaces

        :param node: Node dictionary.
        :type node: dict
        :returns: A list or interfaces with ip addresses
        :rtype: list
        """

        vpputl = VPPUtil()
        interfaces = vpputl.get_hardware(node)
        if interfaces == {}:
            return []

        # First delete all the Virtual interfaces
        for intf in sorted(interfaces.items()):
            name = intf[0]
            if name[:7] == 'Virtual':
                cmd = 'vppctl delete vhost-user {}'.format(name)
                (ret, stdout, stderr) = vpputl.exec_command(cmd)
                if ret != 0:
                    logging.debug('{} failed on node {} {}'.format(
                        cmd, node['host'], stderr))

        # Create a virtual interface, for each interface the user wants to use
        interfaces = vpputl.get_hardware(node)
        if interfaces == {}:
            return []
        interfaces_with_virtual_interfaces = []
        inum = 1
        for intf in sorted(interfaces.items()):
            name = intf[0]
            if name == 'local0':
                continue

            question = "Would you like connect this interface {} to " \
                       "the VM [Y/n]? ".format(name)
            answer = self._ask_user_yn(question, 'y')
            if answer == 'y':
                sockfilename = '/var/run/vpp/{}.sock'.format(
                    name.replace('/', '_'))
                if os.path.exists(sockfilename):
                    os.remove(sockfilename)
                cmd = 'vppctl create vhost-user socket {} server'.format(
                    sockfilename)
                (ret, stdout, stderr) = vpputl.exec_command(cmd)
                if ret != 0:
                    raise RuntimeError(
                        "Couldn't execute the command {}, {}.".format(cmd,
                                                                      stderr))
                vintname = stdout.rstrip('\r\n')

                cmd = 'chmod 777 {}'.format(sockfilename)
                (ret, stdout, stderr) = vpputl.exec_command(cmd)
                if ret != 0:
                    raise RuntimeError(
                        "Couldn't execute the command {}, {}.".format(cmd,
                                                                      stderr))

                interface = {'name': name,
                             'virtualinterface': '{}'.format(vintname),
                             'bridge': '{}'.format(inum)}
                inum += 1
                interfaces_with_virtual_interfaces.append(interface)

        return interfaces_with_virtual_interfaces

    def create_and_bridge_virtual_interfaces(self):
        """
        After asking the user some questions, create a VM and connect
        the interfaces to VPP interfaces

        """

        for i in self._nodes.items():
            node = i[1]

            # Show the current bridge and interface configuration
            print("\nThis the current bridge configuration:")
            VPPUtil.show_bridge(node)
            question = "\nWould you like to keep this configuration [Y/n]? "
            answer = self._ask_user_yn(question, 'y')
            if answer == 'y':
                continue

            # Create a script that builds a bridge configuration with
            # physical interfaces and virtual interfaces
            ints_with_vints = self._create_vints_questions(node)
            content = ''
            for intf in ints_with_vints:
                vhoststr = '\n'.join([
                    'comment { The following command creates the socket }',
                    'comment { and returns a virtual interface }',
                    'comment {{ create vhost-user socket '
                    '/var/run/vpp/sock{}.sock server }}\n'.format(
                        intf['bridge'])
                ])

                setintdnstr = 'set interface state {} down\n'.format(
                    intf['name'])

                setintbrstr = 'set interface l2 bridge {} {}\n'.format(
                    intf['name'], intf['bridge'])
                setvintbrstr = 'set interface l2 bridge {} {}\n'.format(
                    intf['virtualinterface'], intf['bridge'])

                # set interface state VirtualEthernet/0/0/0 up
                setintvststr = 'set interface state {} up\n'.format(
                    intf['virtualinterface'])

                # set interface state VirtualEthernet/0/0/0 down
                setintupstr = 'set interface state {} up\n'.format(
                    intf['name'])

                content += vhoststr + setintdnstr + setintbrstr + \
                    setvintbrstr + setintvststr + setintupstr

            # Write the content to the script
            rootdir = node['rootdir']
            filename = rootdir + \
                '/vpp/vpp-config/scripts/create_vms_and_connect_to_vpp'
            with open(filename, 'w+') as sfile:
                sfile.write(content)

            # Execute the script
            cmd = 'vppctl exec {}'.format(filename)
            (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
            if ret != 0:
                logging.debug(stderr)

            print("\nA script as been created at {}".format(filename))
            print("This script can be run using the following:")
            print("vppctl exec {}\n".format(filename))

    def _iperf_vm_questions(self, node):
        """
        Ask the user some questions and get a list of interfaces
        and IPv4 addresses associated with those interfaces

        :param node: Node dictionary.
        :type node: dict
        :returns: A list or interfaces with ip addresses
        :rtype: list
        """

        vpputl = VPPUtil()
        interfaces = vpputl.get_hardware(node)
        if interfaces == {}:
            return []

        # First delete all the Virtual interfaces
        for intf in sorted(interfaces.items()):
            name = intf[0]
            if name[:7] == 'Virtual':
                cmd = 'vppctl delete vhost-user {}'.format(name)
                (ret, stdout, stderr) = vpputl.exec_command(cmd)
                if ret != 0:
                    logging.debug('{} failed on node {} {}'.format(
                        cmd, node['host'], stderr))

        # Create a virtual interface, for each interface the user wants to use
        interfaces = vpputl.get_hardware(node)
        if interfaces == {}:
            return []
        interfaces_with_virtual_interfaces = []
        inum = 1

        while True:
            print('\nPlease pick one interface to connect to the iperf VM.')
            for intf in sorted(interfaces.items()):
                name = intf[0]
                if name == 'local0':
                    continue

                question = "Would you like connect this interface {} to " \
                           "the VM [y/N]? ".format(name)
                answer = self._ask_user_yn(question, 'n')
                if answer == 'y':
                    self._sockfilename = '/var/run/vpp/{}.sock'.format(
                        name.replace('/', '_'))
                    if os.path.exists(self._sockfilename):
                        os.remove(self._sockfilename)
                    cmd = 'vppctl create vhost-user socket {} server'.format(
                        self._sockfilename)
                    (ret, stdout, stderr) = vpputl.exec_command(cmd)
                    if ret != 0:
                        raise RuntimeError(
                            "Couldn't execute the command {}, {}.".format(
                                cmd, stderr))
                    vintname = stdout.rstrip('\r\n')

                    cmd = 'chmod 777 {}'.format(self._sockfilename)
                    (ret, stdout, stderr) = vpputl.exec_command(cmd)
                    if ret != 0:
                        raise RuntimeError(
                            "Couldn't execute the command {}, {}.".format(
                                cmd, stderr))

                    interface = {'name': name,
                                 'virtualinterface': '{}'.format(vintname),
                                 'bridge': '{}'.format(inum)}
                    inum += 1
                    interfaces_with_virtual_interfaces.append(interface)
                    return interfaces_with_virtual_interfaces

    def create_and_bridge_iperf_virtual_interface(self):
        """
        After asking the user some questions, and create and bridge a
        virtual interface to be used with iperf VM

        """

        for i in self._nodes.items():
            node = i[1]

            # Show the current bridge and interface configuration
            print("\nThis the current bridge configuration:")
            ifaces = VPPUtil.show_bridge(node)
            question = "\nWould you like to keep this configuration [Y/n]? "
            answer = self._ask_user_yn(question, 'y')
            if answer == 'y':
                self._sockfilename = '/var/run/vpp/{}.sock'.format(
                    ifaces[0]['name'].replace('/', '_'))
                if os.path.exists(self._sockfilename):
                    continue

            # Create a script that builds a bridge configuration with
            # physical interfaces and virtual interfaces
            ints_with_vints = self._iperf_vm_questions(node)
            content = ''
            for intf in ints_with_vints:
                vhoststr = '\n'.join([
                    'comment { The following command creates the socket }',
                    'comment { and returns a virtual interface }',
                    'comment {{ create vhost-user socket '
                    '/var/run/vpp/sock{}.sock server }}\n'.format(
                        intf['bridge'])
                ])

                setintdnstr = 'set interface state {} down\n'.format(
                    intf['name'])

                setintbrstr = 'set interface l2 bridge {} {}\n'.format(
                    intf['name'], intf['bridge'])
                setvintbrstr = 'set interface l2 bridge {} {}\n'.format(
                    intf['virtualinterface'], intf['bridge'])

                # set interface state VirtualEthernet/0/0/0 up
                setintvststr = 'set interface state {} up\n'.format(
                    intf['virtualinterface'])

                # set interface state VirtualEthernet/0/0/0 down
                setintupstr = 'set interface state {} up\n'.format(
                    intf['name'])

                content += vhoststr + setintdnstr + setintbrstr + \
                    setvintbrstr + setintvststr + setintupstr

            # Write the content to the script
            rootdir = node['rootdir']
            filename = rootdir + '/vpp/vpp-config/scripts/create_iperf_vm'
            with open(filename, 'w+') as sfile:
                sfile.write(content)

            # Execute the script
            cmd = 'vppctl exec {}'.format(filename)
            (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
            if ret != 0:
                logging.debug(stderr)

            print("\nA script as been created at {}".format(filename))
            print("This script can be run using the following:")
            print("vppctl exec {}\n".format(filename))

    @staticmethod
    def destroy_iperf_vm(name):
        """
        After asking the user some questions, create a VM and connect
        the interfaces to VPP interfaces

        :param name: The name of the VM to be be destroyed
        :type name: str
        """

        cmd = 'virsh list'
        (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
        if ret != 0:
            logging.debug(stderr)
            raise RuntimeError(
                "Couldn't execute the command {} : {}".format(cmd, stderr))

        if re.findall(name, stdout):
            cmd = 'virsh destroy {}'.format(name)
            (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
            if ret != 0:
                logging.debug(stderr)
                raise RuntimeError(
                    "Couldn't execute the command {} : {}".format(
                        cmd, stderr))

    def create_iperf_vm(self, vmname):
        """
        After asking the user some questions, create a VM and connect
        the interfaces to VPP interfaces

        """

        # Read the iperf VM template file
        distro = VPPUtil.get_linux_distro()
        if distro[0] == 'Ubuntu':
            tfilename = \
                '{}/vpp/vpp-config/configs/iperf-ubuntu.xml.template'.format(
                    self._rootdir)
        else:
            tfilename = \
                '{}/vpp/vpp-config/configs/iperf-centos.xml.template'.format(
                    self._rootdir)

        with open(tfilename, 'r') as tfile:
            tcontents = tfile.read()
        tfile.close()

        # Add the variables
        imagename = '{}/vpp/vpp-config/{}'.format(
            self._rootdir, IPERFVM_IMAGE)
        isoname = '{}/vpp/vpp-config/{}'.format(self._rootdir, IPERFVM_ISO)
        tcontents = tcontents.format(vmname=vmname, imagename=imagename,
                                     isoname=isoname,
                                     vhostsocketname=self._sockfilename)

        # Write the xml
        ifilename = '{}/vpp/vpp-config/{}'.format(self._rootdir, IPERFVM_XML)
        with open(ifilename, 'w+') as ifile:
            ifile.write(tcontents)
        ifile.close()

        cmd = 'virsh create {}'.format(ifilename)
        (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
        if ret != 0:
            logging.debug(stderr)
            raise RuntimeError(
                "Couldn't execute the command {} : {}".format(cmd, stderr))
