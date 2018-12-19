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

"""VPP PCI Utility libraries"""

import re
import logging

from vpplib.VPPUtil import VPPUtil

DPDK_SCRIPT = "/vpp/vpp-config/scripts/dpdk-devbind.py"

# PCI Device id regular expresssion
PCI_DEV_ID_REGEX = '[0-9A-Fa-f]+:[0-9A-Fa-f]+:[0-9A-Fa-f]+.[0-9A-Fa-f]+'


class VppPCIUtil(object):
    """
    PCI Utilities

    """

    @staticmethod
    def _create_device_list(device_string):
        """
        Returns a list of PCI devices

        :param device_string: The devices string from dpdk_devbind
        :returns: The device list
        :rtype: dictionary
        """

        devices = {}

        ids = re.findall(PCI_DEV_ID_REGEX, device_string)
        descriptions = re.findall(r'\'([\s\S]*?)\'', device_string)
        unused = re.findall(r'unused=\w+|unused=', device_string)

        for i, j in enumerate(ids):
            device = {'description': descriptions[i]}
            if unused:
                device['unused'] = unused[i].split('=')[1].split(',')

            cmd = 'ls /sys/bus/pci/devices/{}/driver/module/drivers'. \
                format(ids[i])
            (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
            if ret == 0:
                device['driver'] = stdout.split(':')[1].rstrip('\n')

            cmd = 'cat /sys/bus/pci/devices/{}/numa_node'.format(ids[i])
            (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
            if ret != 0:
                raise RuntimeError('{} failed {} {}'.
                                   format(cmd, stderr, stdout))
            numa_node = stdout.rstrip('\n')
            if numa_node == '-1':
                device['numa_node'] = '0'
            else:
                device['numa_node'] = numa_node

            interfaces = []
            device['interfaces'] = []
            cmd = 'ls /sys/bus/pci/devices/{}/net'.format(ids[i])
            (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
            if ret == 0:
                interfaces = stdout.rstrip('\n').split()
                device['interfaces'] = interfaces

            l2_addrs = []
            for intf in interfaces:
                cmd = 'cat /sys/bus/pci/devices/{}/net/{}/address'.format(
                    ids[i], intf)
                (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
                if ret != 0:
                    raise RuntimeError('{} failed {} {}'.
                                       format(cmd, stderr, stdout))

                l2_addrs.append(stdout.rstrip('\n'))

            device['l2addr'] = l2_addrs

            devices[ids[i]] = device

        return devices

    def __init__(self, node):
        self._node = node
        self._dpdk_devices = {}
        self._kernel_devices = {}
        self._other_devices = {}
        self._crypto_dpdk_devices = {}
        self._crypto_kernel_devices = {}
        self._crypto_other_devices = {}
        self._link_up_devices = {}

    def get_all_devices(self):
        """
        Returns a list of all the devices

        """

        node = self._node
        rootdir = node['rootdir']
        dpdk_script = rootdir + DPDK_SCRIPT
        cmd = dpdk_script + ' --status'
        (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
        if ret != 0:
            raise RuntimeError('{} failed on node {} {}'.format(
                cmd,
                node['host'],
                stderr))

        # Get the network devices using the DPDK
        # First get everything after using DPDK
        stda = stdout.split('Network devices using DPDK-compatible driver')[1]
        # Then get everything before using kernel driver
        using_dpdk = stda.split('Network devices using kernel driver')[0]
        self._dpdk_devices = self._create_device_list(using_dpdk)

        # Get the network devices using the kernel
        stda = stdout.split('Network devices using kernel driver')[1]
        using_kernel = stda.split('Other network devices')[0]
        self._kernel_devices = self._create_device_list(using_kernel)

        # Get the other network devices
        stda = stdout.split('Other network devices')[1]
        other = stda.split('Crypto devices using DPDK-compatible driver')[0]
        self._other_devices = self._create_device_list(other)

        # Get the crypto devices using the DPDK
        stda = stdout.split('Crypto devices using DPDK-compatible driver')[1]
        crypto_using_dpdk = stda.split('Crypto devices using kernel driver')[0]
        self._crypto_dpdk_devices = self._create_device_list(
            crypto_using_dpdk)

        # Get the network devices using the kernel
        stda = stdout.split('Crypto devices using kernel driver')[1]
        crypto_using_kernel = stda.split('Other crypto devices')[0]
        self._crypto_kernel_devices = self._create_device_list(
            crypto_using_kernel)

        # Get the other network devices
        crypto_other = stdout.split('Other crypto devices')[1]
        self._crypto_other_devices = self._create_device_list(crypto_other)

        # Get the devices used by the kernel
        for devk in self._kernel_devices.items():
            dvid = devk[0]
            device = devk[1]
            for i in device['interfaces']:
                cmd = "ip addr show " + i
                (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
                if ret != 0:
                    raise RuntimeError('{} failed on node {} {}'.format(
                        cmd,
                        node['host'],
                        stderr))
                lstate = re.findall(r'state \w+', stdout)[0].split(' ')[1]

                # Take care of the links that are UP
                if lstate == 'UP':
                    device['linkup'] = True
                    self._link_up_devices[dvid] = device

        for devl in self._link_up_devices.items():
            dvid = devl[0]
            del self._kernel_devices[dvid]

    def get_dpdk_devices(self):
        """
        Returns a list the dpdk devices

        """
        return self._dpdk_devices

    def get_kernel_devices(self):
        """
        Returns a list the kernel devices

        """
        return self._kernel_devices

    def get_other_devices(self):
        """
        Returns a list the other devices

        """
        return self._other_devices

    def get_crypto_dpdk_devices(self):
        """
        Returns a list the crypto dpdk devices

        """
        return self._crypto_dpdk_devices

    def get_crypto_kernel_devices(self):
        """
        Returns a list the crypto kernel devices

        """
        return self._crypto_kernel_devices

    def get_crypto_other_devices(self):
        """
        Returns a list the crypto other devices

        """
        return self._crypto_other_devices

    def get_link_up_devices(self):
        """
        Returns a list the link up devices

        """
        return self._link_up_devices

    @staticmethod
    def vpp_create_interface(interfaces, device_id, device):
        """
        Create an interface using the device is and device

        """

        name = 'port' + str(len(interfaces))
        interfaces[name] = {}
        interfaces[name]['pci_address'] = device_id
        interfaces[name]['numa_node'] = device['numa_node']
        if 'l2addr' in device:
            l2_addrs = device['l2addr']
            for i, j in enumerate(l2_addrs):
                if i > 0:
                    mname = 'mac_address' + str(i + 1)
                    interfaces[name][mname] = l2_addrs[i]
                else:
                    interfaces[name]['mac_address'] = l2_addrs[i]

    @staticmethod
    def show_vpp_devices(devices, show_interfaces=True, show_header=True):
        """
        show the vpp devices specified in the argument

        :param devices: A list of devices
        :param show_interfaces: show the kernel information
        :param show_header: Display the header if true
        :type devices: dict
        :type show_interfaces: bool
        :type show_header: bool
        """

        if show_interfaces:
            header = "{:15} {:25} {:50}".format("PCI ID",
                                                "Kernel Interface(s)",
                                                "Description")
        else:
            header = "{:15} {:50}".format("PCI ID",
                                          "Description")
        dashseparator = ("-" * (len(header) - 2))

        if show_header is True:
            print (header)
            print (dashseparator)
        for dit in devices.items():
            dvid = dit[0]
            device = dit[1]
            if show_interfaces:
                interfaces = device['interfaces']
                interface = ''
                for i, j in enumerate(interfaces):
                    if i > 0:
                        interface += ',' + interfaces[i]
                    else:
                        interface = interfaces[i]

                print ("{:15} {:25} {:50}".format(
                    dvid, interface, device['description']))
            else:
                print ("{:15} {:50}".format(
                    dvid, device['description']))

    @staticmethod
    def unbind_vpp_device(node, device_id):
        """
        unbind the device specified

        :param node: Node dictionary with cpuinfo.
        :param device_id: The device id
        :type node: dict
        :type device_id: string
        """

        rootdir = node['rootdir']
        dpdk_script = rootdir + DPDK_SCRIPT
        cmd = dpdk_script + ' -u ' + ' ' + device_id
        (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
        if ret != 0:
            raise RuntimeError('{} failed on node {} {} {}'.format(
                cmd, node['host'],
                stdout, stderr))

    @staticmethod
    def bind_vpp_device(node, driver, device_id):
        """
        bind the device specified

        :param node: Node dictionary with cpuinfo.
        :param driver: The driver
        :param device_id: The device id
        :type node: dict
        :type driver: string
        :type device_id: string
        :returns ret: Command return code
        """

        rootdir = node['rootdir']
        dpdk_script = rootdir + DPDK_SCRIPT
        cmd = dpdk_script + ' -b ' + driver + ' ' + device_id
        (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
        if ret != 0:
            logging.error('{} failed on node {}'.format(
                cmd, node['host'], stdout, stderr))
            logging.error('{} {}'.format(
                stdout, stderr))

        return ret
