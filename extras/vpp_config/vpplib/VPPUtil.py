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

"""VPP util library"""
import logging
import re
import subprocess
import platform

from collections import Counter

# VPP_VERSION = '1707'
VPP_VERSION = '1710'


class VPPUtil(object):
    """General class for any VPP related methods/functions."""

    @staticmethod
    def exec_command(cmd, timeout=None):
        """Execute a command on the local node.

        :param cmd: Command to run locally.
        :param timeout: Timeout value
        :type cmd: str
        :type timeout: int
        :return return_code, stdout, stderr
        :rtype: tuple(int, str, str)
        """

        logging.info(" Local Command: {}".format(cmd))
        out = ''
        err = ''
        prc = subprocess.Popen(cmd, shell=True, bufsize=1,
                               stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)

        with prc.stdout:
            for line in iter(prc.stdout.readline, b''):
                logging.info("  {}".format(line.strip('\n')))
                out += line

        with prc.stderr:
            for line in iter(prc.stderr.readline, b''):
                logging.warn("  {}".format(line.strip('\n')))
                err += line

        ret = prc.wait()

        return ret, out, err

    def _autoconfig_backup_file(self, filename):
        """
        Create a backup file.

        :param filename: The file to backup
        :type filename: str
        """

        # Does a copy of the file exist, if not create one
        ofile = filename + '.orig'
        (ret, stdout, stderr) = self.exec_command('ls {}'.format(ofile))
        if ret != 0:
            logging.debug(stderr)
            if stdout.strip('\n') != ofile:
                cmd = 'sudo cp {} {}'.format(filename, ofile)
                (ret, stdout, stderr) = self.exec_command(cmd)
                if ret != 0:
                    logging.debug(stderr)

    def _install_vpp_pkg_ubuntu(self, node, pkg):
        """
        Install the VPP packages

        :param node: Node dictionary
        :param pkg: The vpp packages
        :type node: dict
        :type pkg: string
        """

        cmd = 'apt-get -y install {}'.format(pkg)
        (ret, stdout, stderr) = self.exec_command(cmd)
        if ret != 0:
            raise RuntimeError('{} failed on node {} {} {}'.format(
                cmd, node['host'], stdout, stderr))

    def _install_vpp_pkg_centos(self, node, pkg):
        """
        Install the VPP packages

        :param node: Node dictionary
        :param pkg: The vpp packages
        :type node: dict
        :type pkg: string
        """

        cmd = 'yum -y install {}'.format(pkg)
        (ret, stdout, stderr) = self.exec_command(cmd)
        if ret != 0:
            raise RuntimeError('{} failed on node {} {} {}'.format(
                cmd, node['host'], stdout, stderr))

    def _install_vpp_ubuntu(self, node, fdio_release=VPP_VERSION,
                            ubuntu_version='xenial'):
        """
        Install the VPP packages

        :param node: Node dictionary with cpuinfo.
        :param fdio_release: VPP release number
        :param ubuntu_version: Ubuntu Version
        :type node: dict
        :type fdio_release: string
        :type ubuntu_version: string
        """

        # Modify the sources list
        sfile = '/etc/apt/sources.list.d/99fd.io.list'

        # Backup the sources list
        self._autoconfig_backup_file(sfile)

        # Remove the current file
        cmd = 'rm {}'.format(sfile)
        (ret, stdout, stderr) = self.exec_command(cmd)
        if ret != 0:
            logging.debug('{} failed on node {} {}'.format(
                cmd,
                node['host'],
                stderr))

        reps = 'deb [trusted=yes] https://nexus.fd.io/content/'
        # When using a stable branch
        # reps += 'repositories/fd.io.stable.{}.ubuntu.{}.main/ ./\n' \
        #    .format(fdio_release, ubuntu_version)
        reps += 'repositories/fd.io.ubuntu.{}.main/ ./\n' \
            .format(ubuntu_version)

        cmd = 'echo "{0}" | sudo tee {1}'.format(reps, sfile)
        (ret, stdout, stderr) = self.exec_command(cmd)
        if ret != 0:
            raise RuntimeError('{} failed on node {} {}'.format(
                cmd,
                node['host'],
                stderr))

        # Install the package
        cmd = 'apt-get -y update'
        (ret, stdout, stderr) = self.exec_command(cmd)
        if ret != 0:
            raise RuntimeError('{} apt-get update failed on node {} {}'.format(
                cmd,
                node['host'],
                stderr))

        self._install_vpp_pkg_ubuntu(node, 'vpp-lib')
        self._install_vpp_pkg_ubuntu(node, 'vpp')
        self._install_vpp_pkg_ubuntu(node, 'vpp-plugins')
        self._install_vpp_pkg_ubuntu(node, 'vpp-dpdk-dkms')
        self._install_vpp_pkg_ubuntu(node, 'vpp-dpdk-dev')
        self._install_vpp_pkg_ubuntu(node, 'vpp-api-python')
        self._install_vpp_pkg_ubuntu(node, 'vpp-api-java')
        self._install_vpp_pkg_ubuntu(node, 'vpp-api-lua')
        self._install_vpp_pkg_ubuntu(node, 'vpp-dev')
        self._install_vpp_pkg_ubuntu(node, 'vpp-dbg')

    def _install_vpp_centos(self, node, fdio_release=VPP_VERSION,
                            centos_version='centos7'):
        """
        Install the VPP packages

        :param node: Node dictionary with cpuinfo.
        :param fdio_release: VPP release number
        :param centos_version: Ubuntu Version
        :type node: dict
        :type fdio_release: string
        :type centos_version: string
        """

        # Modify the sources list
        sfile = '/etc/yum.repos.d/fdio-release.repo'

        # Backup the sources list
        self._autoconfig_backup_file(sfile)

        # Remove the current file
        cmd = 'rm {}'.format(sfile)
        (ret, stdout, stderr) = self.exec_command(cmd)
        if ret != 0:
            logging.debug('{} failed on node {} {}'.format(
                cmd,
                node['host'],
                stderr))

        reps = '[fdio-stable-{}]\n'.format(fdio_release)
        reps += 'name=fd.io stable/{} branch latest merge\n'.format(fdio_release)
        # When using stable
        # reps += 'baseurl=https://nexus.fd.io/content/repositories/fd.io.stable.{}.{}/\n'.\
        #     format(fdio_release, centos_version)
        reps += 'baseurl=https://nexus.fd.io/content/repositories/fd.io.{}/\n'.\
            format(centos_version)
        reps += 'enabled=1\n'
        reps += 'gpgcheck=0'

        cmd = 'echo "{0}" | sudo tee {1}'.format(reps, sfile)
        (ret, stdout, stderr) = self.exec_command(cmd)
        if ret != 0:
            raise RuntimeError('{} failed on node {} {}'.format(
                cmd,
                node['host'],
                stderr))

        # Install the packages
 
        self._install_vpp_pkg_centos(node, 'vpp-lib')
        self._install_vpp_pkg_centos(node, 'vpp')
        self._install_vpp_pkg_centos(node, 'vpp-plugins')
        # jadfix Check with Ole
        # self._install_vpp_pkg_centos(node, 'vpp-dpdk-devel')
        self._install_vpp_pkg_centos(node, 'vpp-api-python')
        self._install_vpp_pkg_centos(node, 'vpp-api-java')
        self._install_vpp_pkg_centos(node, 'vpp-api-lua')
        self._install_vpp_pkg_centos(node, 'vpp-devel')

    def install_vpp(self, node):
        """
        Install the VPP packages

        :param node: Node dictionary with cpuinfo.
        :type node: dict
        """
        distro = self.get_linux_distro()
        if distro[0] == 'Ubuntu':
            self._install_vpp_ubuntu(node)
        elif distro[0] == 'CentOS Linux':
            logging.info("Install CentOS")
            self._install_vpp_centos(node)
        else:
            return

    def _uninstall_vpp_pkg_ubuntu(self, node, pkg):
        """
        Uninstall the VPP packages

        :param node: Node dictionary
        :param pkg: The vpp packages
        :type node: dict
        :type pkg: string
        """
        cmd = 'dpkg --purge {}'.format(pkg)
        (ret, stdout, stderr) = self.exec_command(cmd)
        if ret != 0:
            raise RuntimeError('{} failed on node {} {} {}'.format(
                cmd, node['host'], stdout, stderr))

    def _uninstall_vpp_pkg_centos(self, node, pkg):
        """
        Uninstall the VPP packages

        :param node: Node dictionary
        :param pkg: The vpp packages
        :type node: dict
        :type pkg: string
        """
        cmd = 'yum -y remove {}'.format(pkg)
        (ret, stdout, stderr) = self.exec_command(cmd)
        if ret != 0:
            raise RuntimeError('{} failed on node {} {} {}'.format(
                cmd, node['host'], stdout, stderr))

    def _uninstall_vpp_ubuntu(self, node):
        """
        Uninstall the VPP packages

        :param node: Node dictionary with cpuinfo.
        :type node: dict
        """
        pkgs = self.get_installed_vpp_pkgs()

        if len(pkgs) > 0:
            if 'version' in pkgs[0]:
                logging.info("Uninstall Ubuntu Packages")
                self._uninstall_vpp_pkg_ubuntu(node, 'vpp-api-python')
                self._uninstall_vpp_pkg_ubuntu(node, 'vpp-api-java')
                self._uninstall_vpp_pkg_ubuntu(node, 'vpp-api-lua')
                self._uninstall_vpp_pkg_ubuntu(node, 'vpp-plugins')
                self._uninstall_vpp_pkg_ubuntu(node, 'vpp-dpdk-dev')
                self._uninstall_vpp_pkg_ubuntu(node, 'vpp-dpdk-dkms')
                self._uninstall_vpp_pkg_ubuntu(node, 'vpp-dev')
                self._uninstall_vpp_pkg_ubuntu(node, 'vpp-dbg')
                self._uninstall_vpp_pkg_ubuntu(node, 'vpp')
                self._uninstall_vpp_pkg_ubuntu(node, 'vpp-lib')
            else:
                logging.info("Uninstall locally installed Ubuntu Packages")
                for pkg in pkgs:
                    self._uninstall_vpp_pkg_ubuntu(node, pkg['name'])
        else:
            logging.error("There are no Ubuntu packages installed")

    def _uninstall_vpp_centos(self, node):
        """
        Uninstall the VPP packages

        :param node: Node dictionary with cpuinfo.
        :type node: dict
            """

        pkgs = self.get_installed_vpp_pkgs()

        if len(pkgs) > 0:
            if 'version' in pkgs[0]:
                logging.info("Uninstall CentOS Packages")
                self._uninstall_vpp_pkg_centos(node, 'vpp-api-python')
                self._uninstall_vpp_pkg_centos(node, 'vpp-api-java')
                self._uninstall_vpp_pkg_centos(node, 'vpp-api-lua')
                self._uninstall_vpp_pkg_centos(node, 'vpp-plugins')
                self._uninstall_vpp_pkg_centos(node, 'vpp-dpdk-devel')
                self._uninstall_vpp_pkg_centos(node, 'vpp-devel')
                self._uninstall_vpp_pkg_centos(node, 'vpp')
                self._uninstall_vpp_pkg_centos(node, 'vpp-lib')
            else:
                logging.info("Uninstall locally installed CentOS Packages")
                for pkg in pkgs:
                    self._uninstall_vpp_pkg_centos(node, pkg['name'])
        else:
            logging.error("There are no CentOS packages installed")

    def uninstall_vpp(self, node):
        """
        Uninstall the VPP packages

        :param node: Node dictionary with cpuinfo.
        :type node: dict
        """

        # First stop VPP
        self.stop(node)

        distro = self.get_linux_distro()
        if distro[0] == 'Ubuntu':
            self._uninstall_vpp_ubuntu(node)
        elif distro[0] == 'CentOS Linux':
            logging.info("Uninstall CentOS")
            self._uninstall_vpp_centos(node)
        else:
            return

    def show_vpp_settings(self, *additional_cmds):
        """
        Print default VPP settings. In case others are needed, can be
        accepted as next parameters (each setting one parameter), preferably
        in form of a string.

        :param additional_cmds: Additional commands that the vpp should print
        settings for.
        :type additional_cmds: tuple
        """
        def_setting_tb_displayed = {
            'IPv6 FIB': 'ip6 fib',
            'IPv4 FIB': 'ip fib',
            'Interface IP': 'int addr',
            'Interfaces': 'int',
            'ARP': 'ip arp',
            'Errors': 'err'
        }

        if additional_cmds:
            for cmd in additional_cmds:
                def_setting_tb_displayed['Custom Setting: {}'.format(cmd)] \
                    = cmd

                for _, value in def_setting_tb_displayed.items():
                    self.exec_command('vppctl sh {}'.format(value))

    @staticmethod
    def get_vms(node):
        """
        Get a list of VMs that are connected to VPP interfaces

        :param node: VPP node.
        :type node: dict
        :returns: Dictionary containing a list of VMs and the interfaces that are connected to VPP
        :rtype: dictionary
        """

        vmdict = {}

        print "Need to implement get vms"
        
        return vmdict

    @staticmethod
    def get_int_ip(node):
        """
        Get the VPP interfaces and IP addresses

        :param node: VPP node.
        :type node: dict
        :returns: Dictionary containing VPP interfaces and IP addresses
        :rtype: dictionary
        """
        interfaces = {}
        cmd = 'vppctl show int addr'
        (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
        if ret != 0:
            return interfaces

        lines = stdout.split('\n')
        if len(lines[0]) is not 0:
            if lines[0].split(' ')[0] == 'FileNotFoundError':
                return interfaces

        name = ''
        for line in lines:
            if len(line) is 0:
                continue

            # If the first character is not whitespace
            # create a new interface
            if len(re.findall(r'\s', line[0])) is 0:
                spl = line.split()
                name = spl[0]
                if name == 'local0':
                    continue
                interfaces[name] = {}
                interfaces[name]['state'] = spl[1].lstrip('(').rstrip('):\r')
            else:
                interfaces[name]['address'] = line.lstrip(' ').rstrip('\r')

        return interfaces

    @staticmethod
    def get_hardware(node):
        """
        Get the VPP hardware information and return it in a
        dictionary

        :param node: VPP node.
        :type node: dict
        :returns: Dictionary containing VPP hardware information
        :rtype: dictionary
        """

        interfaces = {}
        cmd = 'vppctl show hard'
        (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
        if ret != 0:
            return interfaces

        lines = stdout.split('\n')
        if len(lines[0]) is not 0:
            if lines[0].split(' ')[0] == 'FileNotFoundError':
                return interfaces

        for line in lines:
            if len(line) is 0:
                continue

            # If the first character is not whitespace
            # create a new interface
            if len(re.findall(r'\s', line[0])) is 0:
                spl = line.split()
                name = spl[0]
                interfaces[name] = {}
                interfaces[name]['index'] = spl[1]
                interfaces[name]['state'] = spl[2]

            # Ethernet address
            rfall = re.findall(r'Ethernet address', line)
            if rfall:
                spl = line.split()
                interfaces[name]['mac'] = spl[2]

            # Carrier
            rfall = re.findall(r'carrier', line)
            if rfall:
                spl = line.split('carrier ')
                interfaces[name]['carrier'] = spl[1]

            # Socket
            rfall = re.findall(r'cpu socket', line)
            if rfall:
                spl = line.split('cpu socket ')
                interfaces[name]['cpu socket'] = spl[1]

            # Queues and Descriptors
            rfall = re.findall(r'rx queues', line)
            if rfall:
                spl = line.split(',')
                interfaces[name]['rx queues'] = spl[0].lstrip(' ').split(' ')[2]
                interfaces[name]['rx descs'] = spl[1].split(' ')[3]
                interfaces[name]['tx queues'] = spl[2].split(' ')[3]
                interfaces[name]['tx descs'] = spl[3].split(' ')[3]

        return interfaces

    def _get_installed_vpp_pkgs_ubuntu(self):
        """
        Get the VPP hardware information and return it in a
        dictionary

        :returns: List of the packages installed
        :rtype: list
        """

        pkgs = []
        cmd = 'dpkg -l | grep vpp'
        (ret, stdout, stderr) = self.exec_command(cmd)
        if ret != 0:
            return pkgs

        lines = stdout.split('\n')
        for line in lines:
            items = line.split()
            if len(items) < 2:
                continue
            pkg = {'name': items[1], 'version': items[2]}
            pkgs.append(pkg)

        return pkgs

    def _get_installed_vpp_pkgs_centos(self):
        """
        Get the VPP hardware information and return it in a
        dictionary

        :returns: List of the packages installed
        :rtype: list
        """

        pkgs = []
        cmd = 'rpm -qa | grep vpp'
        (ret, stdout, stderr) = self.exec_command(cmd)
        if ret != 0:
            return pkgs

        lines = stdout.split('\n')
        for line in lines:
            if len(line) == 0:
                continue

            items = line.split()
            if len(items) < 2:
                pkg = {'name': items[0]}
            else:
                pkg = {'name': items[1], 'version': items[2]}

            pkgs.append(pkg)

        return pkgs

    def get_installed_vpp_pkgs(self):
        """
        Get the VPP hardware information and return it in a
        dictionary

        :returns: List of the packages installed
        :rtype: list
        """

        distro = self.get_linux_distro()
        if distro[0] == 'Ubuntu':
            pkgs = self._get_installed_vpp_pkgs_ubuntu()
        elif distro[0] == 'CentOS Linux':
            pkgs = self._get_installed_vpp_pkgs_centos()
        else:
            return []

        return pkgs

    @staticmethod
    def get_interfaces_numa_node(node, *iface_keys):
        """Get numa node on which are located most of the interfaces.

        Return numa node with highest count of interfaces provided as arguments.
        Return 0 if the interface does not have numa_node information available.
        If all interfaces have unknown location (-1), then return 0.
        If most of interfaces have unknown location (-1), but there are
        some interfaces with known location, then return the second most
        location of the provided interfaces.

        :param node: Node from DICT__nodes.
        :param iface_keys: Interface keys for lookup.
        :type node: dict
        :type iface_keys: strings
        """
        numa_list = []
        for if_key in iface_keys:
            try:
                numa_list.append(node['interfaces'][if_key].get('numa_node'))
            except KeyError:
                pass

        numa_cnt_mc = Counter(numa_list).most_common()
        numa_cnt_mc_len = len(numa_cnt_mc)
        if numa_cnt_mc_len > 0 and numa_cnt_mc[0][0] != -1:
            return numa_cnt_mc[0][0]
        elif numa_cnt_mc_len > 1 and numa_cnt_mc[0][0] == -1:
            return numa_cnt_mc[1][0]

        return 0

    @staticmethod
    def restart(node):
        """

        Starts vpp for a given node

        :param node: VPP node.
        :type node: dict
        """

        cmd = 'service vpp restart'
        (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
        if ret != 0:
            raise RuntimeError('{} failed on node {} {} {}'.
                               format(cmd, node['host'],
                                      stdout, stderr))

    @staticmethod
    def start(node):
        """

        Starts vpp for a given node

        :param node: VPP node.
        :type node: dict
        """

        cmd = 'service vpp start'
        (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
        if ret != 0:
            raise RuntimeError('{} failed on node {} {} {}'.
                               format(cmd, node['host'],
                                      stdout, stderr))

    @staticmethod
    def stop(node):
        """

        Stops vpp for a given node

        :param node: VPP node.
        :type node: dict
        """

        cmd = 'service vpp stop'
        (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
        if ret != 0:
            raise RuntimeError('{} failed on node {} {} {}'.
                               format(cmd, node['host'],
                                      stdout, stderr))

    @staticmethod
    def status(node):
        """

        Gets VPP status

        :param: node
        :type node: dict
        :returns: status, errors
        :rtype: tuple(str, list)
        """
        errors = []
        vutil = VPPUtil()
        pkgs = vutil.get_installed_vpp_pkgs()
        if len(pkgs) == 0:
            return "Not Installed", errors

        cmd = 'service vpp status'
        (ret, stdout, stderr) = VPPUtil.exec_command(cmd)

        # Get the active status
        state = re.findall(r'Active:[\w (\)]+', stdout)[0].split(' ')
        if len(state) > 2:
            statestr = "{} {}".format(state[1], state[2])
        else:
            statestr = "Invalid"

        # For now we won't look for DPDK errors
        # lines = stdout.split('\n')
        # for line in lines:
        #    if 'EAL' in line or \
        #                     'FAILURE' in line or \
        #                     'failed' in line or \
        #                     'Failed' in line:
        #         errors.append(line.lstrip(' '))

        return statestr, errors

    @staticmethod
    def get_linux_distro():
        """
        Get the linux distribution and check if it is supported

        :returns: linux distro, None if the distro is not supported
        :rtype: list
        """

        distro = platform.linux_distribution()
        if distro[0] == 'Ubuntu' or \
                        distro[0] == 'CentOS Linux' or \
                        distro[:26] == 'Linux Distribution Red Hat':
            return distro
        else:
            raise RuntimeError('Linux Distribution {} is not supported'.format(distro[0]))

    @staticmethod
    def version():
        """

        Gets VPP Version information

        :returns: version
        :rtype: dict
        """

        version = {}
        cmd = 'vppctl show version verbose'
        (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
        if ret != 0:
            return version

        lines = stdout.split('\n')
        if len(lines[0]) is not 0:
            if lines[0].split(' ')[0] == 'FileNotFoundError':
                return version

        for line in lines:
            if len(line) is 0:
                continue
            dct = line.split(':')
            version[dct[0]] = dct[1].lstrip(' ')

        return version

    @staticmethod
    def show_bridge(node):
        """
        Shows the current bridge configuration

        :param node: VPP node.
        :type node: dict
        """

        cmd = 'vppctl show bridge'
        (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
        if ret != 0:
            raise RuntimeError('{} failed on node {} {} {}'.
                               format(cmd, node['host'],
                                      stdout, stderr))
        lines = stdout.split('\r\n')
        bridges = []
        for line in lines:
            if line == 'no bridge-domains in use':
                print line
                return
            if len(line) == 0:
                continue

            lspl = line.lstrip(' ').split()
            if lspl[0] != 'BD-ID':
                bridges.append(lspl[0])

        for bridge in bridges:
            cmd = 'vppctl show bridge {} detail'.format(bridge)
            (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
            if ret != 0:
                raise RuntimeError('{} failed on node {} {} {}'.
                                   format(cmd, node['host'],
                                          stdout, stderr))
            print stdout
