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

"""QEMU utilities library."""
from  __future__ import absolute_import, division

from time import time, sleep
import json
import logging

from vpplib.VPPUtil import VPPUtil
from vpplib.constants import Constants


class NodeType(object):
    """Defines node types used in topology dictionaries."""
    # Device Under Test (this node has VPP running on it)
    DUT = 'DUT'
    # Traffic Generator (this node has traffic generator on it)
    TG = 'TG'
    # Virtual Machine (this node running on DUT node)
    VM = 'VM'


class QemuUtils(object):
    """QEMU utilities."""

    # noinspection PyDictCreation
    def __init__(self, qemu_id=1):
        self._qemu_id = qemu_id
        # Path to QEMU binary
        self._qemu_bin = '/usr/bin/qemu-system-x86_64'
        # QEMU Machine Protocol socket
        self._qmp_sock = '/tmp/qmp{0}.sock'.format(self._qemu_id)
        # QEMU Guest Agent socket
        self._qga_sock = '/tmp/qga{0}.sock'.format(self._qemu_id)
        # QEMU PID file
        self._pid_file = '/tmp/qemu{0}.pid'.format(self._qemu_id)
        self._qemu_opt = {}
        # Default 1 CPU.
        self._qemu_opt['smp'] = '-smp 1,sockets=1,cores=1,threads=1'
        # Daemonize the QEMU process after initialization. Default one
        # management interface.
        self._qemu_opt['options'] = '-cpu host -daemonize -enable-kvm ' \
            '-machine pc,accel=kvm,usb=off,mem-merge=off ' \
            '-net nic,macaddr=52:54:00:00:{0:02x}:ff -balloon none'\
            .format(self._qemu_id)
        self._qemu_opt['ssh_fwd_port'] = 10021 + qemu_id
        # Default serial console port
        self._qemu_opt['serial_port'] = 4555 + qemu_id
        # Default 512MB virtual RAM
        self._qemu_opt['mem_size'] = 512
        # Default huge page mount point, required for Vhost-user interfaces.
        self._qemu_opt['huge_mnt'] = '/mnt/huge'
        # Default do not allocate huge pages.
        self._qemu_opt['huge_allocate'] = False
        # Default image for CSIT virl setup
        self._qemu_opt['disk_image'] = '/var/lib/vm/vhost-nested.img'
        # VM node info dict
        self._vm_info = {
            'type': NodeType.VM,
            'port': self._qemu_opt['ssh_fwd_port'],
            'username': 'cisco',
            'password': 'cisco',
            'interfaces': {},
        }
        # Virtio queue count
        self._qemu_opt['queues'] = 1
        self._vhost_id = 0
        self._ssh = None
        self._node = None
        self._socks = [self._qmp_sock, self._qga_sock]

    def qemu_set_bin(self, path):
        """Set binary path for QEMU.

        :param path: Absolute path in filesystem.
        :type path: str
        """
        self._qemu_bin = path

    def qemu_set_smp(self, cpus, cores, threads, sockets):
        """Set SMP option for QEMU.

        :param cpus: Number of CPUs.
        :param cores: Number of CPU cores on one socket.
        :param threads: Number of threads on one CPU core.
        :param sockets: Number of discrete sockets in the system.
        :type cpus: int
        :type cores: int
        :type threads: int
        :type sockets: int
        """
        self._qemu_opt['smp'] = \
            '-smp {},cores={},threads={},sockets={}'.format(
                cpus, cores, threads, sockets)

    def qemu_set_ssh_fwd_port(self, fwd_port):
        """Set host port for guest SSH forwarding.

        :param fwd_port: Port number on host for guest SSH forwarding.
        :type fwd_port: int
        """
        self._qemu_opt['ssh_fwd_port'] = fwd_port
        self._vm_info['port'] = fwd_port

    def qemu_set_serial_port(self, port):
        """Set serial console port.

        :param port: Serial console port.
        :type port: int
        """
        self._qemu_opt['serial_port'] = port

    def qemu_set_mem_size(self, mem_size):
        """Set virtual RAM size.

        :param mem_size: RAM size in Mega Bytes.
        :type mem_size: int
        """
        self._qemu_opt['mem_size'] = int(mem_size)

    def qemu_set_huge_mnt(self, huge_mnt):
        """Set hugefile mount point.

        :param huge_mnt: System hugefile mount point.
        :type huge_mnt: int
        """
        self._qemu_opt['huge_mnt'] = huge_mnt

    def qemu_set_huge_allocate(self):
        """Set flag to allocate more huge pages if needed."""
        self._qemu_opt['huge_allocate'] = True

    def qemu_set_disk_image(self, disk_image):
        """Set disk image.

        :param disk_image: Path of the disk image.
        :type disk_image: str
        """
        self._qemu_opt['disk_image'] = disk_image

    def qemu_set_affinity(self, *host_cpus):
        """Set qemu affinity by getting thread PIDs via QMP and taskset to list
        of CPU cores.

        :param host_cpus: List of CPU cores.
        :type host_cpus: list
        """
        qemu_cpus = self._qemu_qmp_exec('query-cpus')['return']

        if len(qemu_cpus) != len(host_cpus):
            logging.debug('Host CPU count {0}, Qemu Thread count {1}'.format(
                len(host_cpus), len(qemu_cpus)))
            raise ValueError('Host CPU count must match Qemu Thread count')

        for qemu_cpu, host_cpu in zip(qemu_cpus, host_cpus):
            cmd = 'taskset -pc {0} {1}'.format(host_cpu, qemu_cpu['thread_id'])
            (ret_code, _, stderr) = self._ssh.exec_command_sudo(cmd)
            if int(ret_code) != 0:
                logging.debug('Set affinity failed {0}'.format(stderr))
                raise RuntimeError('Set affinity failed on {0}'.format(
                    self._node['host']))

    def qemu_set_scheduler_policy(self):
        """Set scheduler policy to SCHED_RR with priority 1 for all Qemu CPU
        processes.

       :raises RuntimeError: Set scheduler policy failed.
        """
        qemu_cpus = self._qemu_qmp_exec('query-cpus')['return']

        for qemu_cpu in qemu_cpus:
            cmd = 'chrt -r -p 1 {0}'.format(qemu_cpu['thread_id'])
            (ret_code, _, stderr) = self._ssh.exec_command_sudo(cmd)
            if int(ret_code) != 0:
                logging.debug('Set SCHED_RR failed {0}'.format(stderr))
                raise RuntimeError('Set SCHED_RR failed on {0}'.format(
                    self._node['host']))

    def qemu_set_node(self, node):
        """Set node to run QEMU on.

        :param node: Node to run QEMU on.
        :type node: dict
        """
        self._node = node
        self._vm_info['host'] = node['host']

    def qemu_add_vhost_user_if(self, socket, server=True, mac=None):
        """Add Vhost-user interface.

        :param socket: Path of the unix socket.
        :param server: If True the socket shall be a listening socket.
        :param mac: Vhost-user interface MAC address (optional, otherwise is
            used auto-generated MAC 52:54:00:00:xx:yy).
        :type socket: str
        :type server: bool
        :type mac: str
        """
        self._vhost_id += 1
        # Create unix socket character device.
        chardev = ' -chardev socket,id=char{0},path={1}'.format(self._vhost_id,
                                                                socket)
        if server is True:
            chardev += ',server'
        self._qemu_opt['options'] += chardev
        # Create Vhost-user network backend.
        netdev = (' -netdev vhost-user,id=vhost{0},chardev=char{0},queues={1}'
                  .format(self._vhost_id, self._qemu_opt['queues']))
        self._qemu_opt['options'] += netdev
        # If MAC is not specified use auto-generated MAC address based on
        # template 52:54:00:00:<qemu_id>:<vhost_id>, e.g. vhost1 MAC of QEMU
        #  with ID 1 is 52:54:00:00:01:01
        if mac is None:
            mac = '52:54:00:00:{0:02x}:{1:02x}'.\
                format(self._qemu_id, self._vhost_id)
        extend_options = 'mq=on,csum=off,gso=off,guest_tso4=off,'\
            'guest_tso6=off,guest_ecn=off,mrg_rxbuf=off'
        # Create Virtio network device.
        device = ' -device virtio-net-pci,netdev=vhost{0},mac={1},{2}'.format(
            self._vhost_id, mac, extend_options)
        self._qemu_opt['options'] += device
        # Add interface MAC and socket to the node dict
        if_data = {'mac_address': mac, 'socket': socket}
        if_name = 'vhost{}'.format(self._vhost_id)
        self._vm_info['interfaces'][if_name] = if_data
        # Add socket to the socket list
        self._socks.append(socket)

    def _qemu_qmp_exec(self, cmd):
        """Execute QMP command.

        QMP is JSON based protocol which allows to control QEMU instance.

        :param cmd: QMP command to execute.
        :type cmd: str
        :return: Command output in python representation of JSON format. The
            { "return": {} } response is QMP's success response. An error
            response will contain the "error" keyword instead of "return".
        """
        # To enter command mode, the qmp_capabilities command must be issued.
        qmp_cmd = 'echo "{ \\"execute\\": \\"qmp_capabilities\\" }' \
                  '{ \\"execute\\": \\"' + cmd + \
                  '\\" }" | sudo -S socat - UNIX-CONNECT:' + self._qmp_sock

        (ret_code, stdout, stderr) = self._ssh.exec_command(qmp_cmd)
        if int(ret_code) != 0:
            logging.debug('QMP execute failed {0}'.format(stderr))
            raise RuntimeError('QMP execute "{0}"'
                               ' failed on {1}'.format(
                cmd, self._node['host']))
        logging.debug(stdout)
        # Skip capabilities negotiation messages.
        out_list = stdout.splitlines()
        if len(out_list) < 3:
            raise RuntimeError('Invalid QMP output on {0}'.format(
                self._node['host']))
        return json.loads(out_list[2])

    def _qemu_qga_flush(self):
        """Flush the QGA parser state
        """
        qga_cmd = '(printf "\xFF"; sleep 1) | ' \
                  'sudo -S socat - UNIX-CONNECT:' + \
                  self._qga_sock
        # TODO: probably need something else
        (ret_code, stdout, stderr) = self._ssh.exec_command(qga_cmd)
        if int(ret_code) != 0:
            logging.debug('QGA execute failed {0}'.format(stderr))
            raise RuntimeError('QGA execute "{0}" '
                               'failed on {1}'.format(qga_cmd,
                                                      self._node['host']))
        logging.debug(stdout)
        if not stdout:
            return {}
        return json.loads(stdout.split('\n', 1)[0])

    def _qemu_qga_exec(self, cmd):
        """Execute QGA command.

        QGA provide access to a system-level agent via standard QMP commands.

        :param cmd: QGA command to execute.
        :type cmd: str
        """
        qga_cmd = '(echo "{ \\"execute\\": \\"' + \
                  cmd + \
                  '\\" }"; sleep 1) | sudo -S socat - UNIX-CONNECT:' + \
                  self._qga_sock
        (ret_code, stdout, stderr) = self._ssh.exec_command(qga_cmd)
        if int(ret_code) != 0:
            logging.debug('QGA execute failed {0}'.format(stderr))
            raise RuntimeError('QGA execute "{0}"'
                               ' failed on {1}'.format(
                cmd, self._node['host']))
        logging.debug(stdout)
        if not stdout:
            return {}
        return json.loads(stdout.split('\n', 1)[0])

    def _wait_until_vm_boot(self, timeout=60):
        """Wait until QEMU VM is booted.

        Ping QEMU guest agent each 5s until VM booted or timeout.

        :param timeout: Waiting timeout in seconds (optional, default 60s).
        :type timeout: int
        """
        start = time()
        while True:
            if time() - start > timeout:
                raise RuntimeError('timeout, VM {0} not booted on {1}'.format(
                    self._qemu_opt['disk_image'], self._node['host']))
            out = None
            try:
                self._qemu_qga_flush()
                out = self._qemu_qga_exec('guest-ping')
            except ValueError:
                logging.debug(
                    'QGA guest-ping unexpected output {}'.format(out))
            # Empty output - VM not booted yet
            if not out:
                sleep(5)
            # Non-error return - VM booted
            elif out.get('return') is not None:
                break
            # Skip error and wait
            elif out.get('error') is not None:
                sleep(5)
            else:
                # If there is an unexpected output from QGA guest-info, try
                # again until timeout.
                logging.debug(
                    'QGA guest-ping unexpected output {}'.format(out))

        logging.debug(
            'VM {0} booted on {1}'.format(self._qemu_opt['disk_image'],
                                          self._node['host']))

    def _update_vm_interfaces(self):
        """Update interface names in VM node dict."""
        # Send guest-network-get-interfaces command via QGA, output example:
        # {"return": [{"name": "eth0", "hardware-address": "52:54:00:00:04:01"},
        # {"name": "eth1", "hardware-address": "52:54:00:00:04:02"}]}
        out = self._qemu_qga_exec('guest-network-get-interfaces')
        interfaces = out.get('return')
        mac_name = {}
        if not interfaces:
            raise RuntimeError(
                'Get VM {0} interface list failed on {1}'.format(
                    self._qemu_opt['disk_image'], self._node['host']))
        # Create MAC-name dict
        for interface in interfaces:
            if 'hardware-address' not in interface:
                continue
            mac_name[interface['hardware-address']] = interface['name']
        # Match interface by MAC and save interface name
        for interface in self._vm_info['interfaces'].values():
            mac = interface.get('mac_address')
            if_name = mac_name.get(mac)
            if if_name is None:
                logging.debug(
                    'Interface name for MAC {} not found'.format(mac))
            else:
                interface['name'] = if_name

    def _huge_page_check(self, allocate=False):
        """Huge page check."""
        huge_mnt = self._qemu_opt.get('huge_mnt')
        mem_size = self._qemu_opt.get('mem_size')

        # Get huge pages information
        huge_size = self._get_huge_page_size()
        huge_free = self._get_huge_page_free(huge_size)
        huge_total = self._get_huge_page_total(huge_size)

        # Check if memory reqested by qemu is available on host
        if (mem_size * 1024) > (huge_free * huge_size):
            # If we want to allocate hugepage dynamically
            if allocate:
                mem_needed = abs((huge_free * huge_size) - (mem_size * 1024))
                huge_to_allocate = ((mem_needed // huge_size) * 2) + huge_total
                max_map_count = huge_to_allocate*4
                # Increase maximum number of memory map areas a
                # process may have
                cmd = \
                    'echo "{0}" | sudo tee /proc/sys/vm/max_map_count'.format(
                    max_map_count)
                (ret_code, _, stderr) = self._ssh.exec_command_sudo(cmd)
                # Increase hugepage count
                cmd = \
                    'echo "{0}" | sudo tee /proc/sys/vm/nr_hugepages'.format(
                    huge_to_allocate)
                (ret_code, _, stderr) = self._ssh.exec_command_sudo(cmd)
                if int(ret_code) != 0:
                    logging.debug(
                        'Mount huge pages failed {0}'.format(stderr))
                    raise RuntimeError(
                        'Mount huge pages failed on {0}'.format(
                            self._node['host']))
            # If we do not want to allocate dynamicaly end with error
            else:
                raise RuntimeError(
                    'Not enough free huge pages: {0}, '
                    '{1} MB'.format(huge_free, huge_free * huge_size)
                )
        # Check if huge pages mount point exist
        has_huge_mnt = False
        (_, output, _) = self._ssh.exec_command('cat /proc/mounts')
        for line in output.splitlines():
            # Try to find something like:
            # none /mnt/huge hugetlbfs rw,relatime,pagesize=2048k 0 0
            mount = line.split()
            if mount[2] == 'hugetlbfs' and mount[1] == huge_mnt:
                has_huge_mnt = True
                break
        # If huge page mount point not exist create one
        if not has_huge_mnt:
            cmd = 'mkdir -p {0}'.format(huge_mnt)
            (ret_code, _, stderr) = self._ssh.exec_command_sudo(cmd)
            if int(ret_code) != 0:
                logging.debug('Create mount dir failed: {0}'.format(stderr))
                raise RuntimeError('Create mount dir failed on {0}'.format(
                    self._node['host']))
            cmd = 'mount -t hugetlbfs -o pagesize=2048k none {0}'.format(
                huge_mnt)
            (ret_code, _, stderr) = self._ssh.exec_command_sudo(cmd)
            if int(ret_code) != 0:
                logging.debug('Mount huge pages failed {0}'.format(stderr))
                raise RuntimeError('Mount huge pages failed on {0}'.format(
                    self._node['host']))

    def _get_huge_page_size(self):
        """Get default size of huge pages in system.

        :returns: Default size of free huge pages in system.
        :rtype: int
        :raises: RuntimeError if reading failed for three times.
        """
        # TODO: remove to dedicated library
        cmd_huge_size = "grep Hugepagesize /proc/meminfo | awk '{ print $2 }'"
        for _ in range(3):
            (ret, out, _) = self._ssh.exec_command_sudo(cmd_huge_size)
            if ret == 0:
                try:
                    huge_size = int(out)
                except ValueError:
                    logging.debug('Reading huge page size information failed')
                else:
                    break
        else:
            raise RuntimeError('Getting huge page size information failed.')
        return huge_size

    def _get_huge_page_free(self, huge_size):
        """Get total number of huge pages in system.

        :param huge_size: Size of hugepages.
        :type huge_size: int
        :returns: Number of free huge pages in system.
        :rtype: int
        :raises: RuntimeError if reading failed for three times.
        """
        # TODO: add numa aware option
        # TODO: remove to dedicated library
        cmd_huge_free = 'cat /sys/kernel/mm/hugepages/hugepages-{0}kB/'\
            'free_hugepages'.format(huge_size)
        for _ in range(3):
            (ret, out, _) = self._ssh.exec_command_sudo(cmd_huge_free)
            if ret == 0:
                try:
                    huge_free = int(out)
                except ValueError:
                    logging.debug(
                        'Reading free huge pages information failed')
                else:
                    break
        else:
            raise RuntimeError('Getting free huge pages information failed.')
        return huge_free

    def _get_huge_page_total(self, huge_size):
        """Get total number of huge pages in system.

        :param huge_size: Size of hugepages.
        :type huge_size: int
        :returns: Total number of huge pages in system.
        :rtype: int
        :raises: RuntimeError if reading failed for three times.
        """
        # TODO: add numa aware option
        # TODO: remove to dedicated library
        cmd_huge_total = 'cat /sys/kernel/mm/hugepages/hugepages-{0}kB/'\
            'nr_hugepages'.format(huge_size)
        for _ in range(3):
            (ret, out, _) = self._ssh.exec_command_sudo(cmd_huge_total)
            if ret == 0:
                try:
                    huge_total = int(out)
                except ValueError:
                    logging.debug(
                        'Reading total huge pages information failed')
                else:
                    break
        else:
            raise RuntimeError('Getting total huge pages information failed.')
        return huge_total

    def qemu_start(self):
        """Start QEMU and wait until VM boot.

        :return: VM node info.
        :rtype: dict
        .. note:: First set at least node to run QEMU on.
        .. warning:: Starts only one VM on the node.
        """
        # SSH forwarding
        ssh_fwd = '-net user,hostfwd=tcp::{0}-:22'.format(
            self._qemu_opt.get('ssh_fwd_port'))
        # Memory and huge pages
        mem = '-object memory-backend-file,id=mem,size={0}M,mem-path={1},' \
            'share=on -m {0} -numa node,memdev=mem'.format(
                self._qemu_opt.get('mem_size'), self._qemu_opt.get('huge_mnt'))

        # By default check only if hugepages are available.
        # If 'huge_allocate' is set to true try to allocate as well.
        self._huge_page_check(allocate=self._qemu_opt.get('huge_allocate'))

        # Disk option
        drive = '-drive file={0},format=raw,cache=none,if=virtio'.format(
            self._qemu_opt.get('disk_image'))
        # Setup QMP via unix socket
        qmp = '-qmp unix:{0},server,nowait'.format(self._qmp_sock)
        # Setup serial console
        serial = '-chardev socket,host=127.0.0.1,port={0},id=gnc0,server,' \
            'nowait -device isa-serial,chardev=gnc0'.format(
                self._qemu_opt.get('serial_port'))
        # Setup QGA via chardev (unix socket) and isa-serial channel
        qga = '-chardev socket,path={0},server,nowait,id=qga0 ' \
            '-device isa-serial,chardev=qga0'.format(self._qga_sock)
        # Graphic setup
        graphic = '-monitor none -display none -vga none'
        # PID file
        pid = '-pidfile {}'.format(self._pid_file)

        # Run QEMU
        cmd = '{0} {1} {2} {3} {4} {5} {6} {7} {8} {9} {10}'.format(
            self._qemu_bin, self._qemu_opt.get('smp'), mem, ssh_fwd,
            self._qemu_opt.get('options'),
            drive, qmp, serial, qga, graphic, pid)
        (ret_code, _, stderr) = self._ssh.exec_command_sudo(cmd, timeout=300)
        if int(ret_code) != 0:
            logging.debug('QEMU start failed {0}'.format(stderr))
            raise RuntimeError('QEMU start failed on {0}'.format(
                self._node['host']))
        logging.debug('QEMU running')
        # Wait until VM boot
        try:
            self._wait_until_vm_boot()
        except RuntimeError:
            self.qemu_kill_all()
            self.qemu_clear_socks()
            raise
        # Update interface names in VM node dict
        self._update_vm_interfaces()
        # Return VM node dict
        return self._vm_info

    def qemu_quit(self):
        """Quit the QEMU emulator."""
        out = self._qemu_qmp_exec('quit')
        err = out.get('error')
        if err is not None:
            raise RuntimeError('QEMU quit failed on {0}, error: {1}'.format(
                self._node['host'], json.dumps(err)))

    def qemu_system_powerdown(self):
        """Power down the system (if supported)."""
        out = self._qemu_qmp_exec('system_powerdown')
        err = out.get('error')
        if err is not None:
            raise RuntimeError(
                'QEMU system powerdown failed on {0}, '
                'error: {1}'.format(self._node['host'], json.dumps(err))
            )

    def qemu_system_reset(self):
        """Reset the system."""
        out = self._qemu_qmp_exec('system_reset')
        err = out.get('error')
        if err is not None:
            raise RuntimeError(
                'QEMU system reset failed on {0}, '
                'error: {1}'.format(self._node['host'], json.dumps(err)))

    def qemu_kill(self):
        """Kill qemu process."""
        # Note: in QEMU start phase there are 3 QEMU processes because we
        # daemonize QEMU
        self._ssh.exec_command_sudo('chmod +r {}'.format(self._pid_file))
        self._ssh.exec_command_sudo('kill -SIGKILL $(cat {})'
                                    .format(self._pid_file))
        # Delete PID file
        cmd = 'rm -f {}'.format(self._pid_file)
        self._ssh.exec_command_sudo(cmd)

    def qemu_kill_all(self, node=None):
        """Kill all qemu processes on DUT node if specified.

        :param node: Node to kill all QEMU processes on.
        :type node: dict
        """
        if node:
            self.qemu_set_node(node)
        self._ssh.exec_command_sudo('pkill -SIGKILL qemu')

    def qemu_clear_socks(self):
        """Remove all sockets created by QEMU."""
        # If serial console port still open kill process
        cmd = 'fuser -k {}/tcp'.format(self._qemu_opt.get('serial_port'))
        self._ssh.exec_command_sudo(cmd)
        # Delete all created sockets
        for sock in self._socks:
            cmd = 'rm -f {}'.format(sock)
            self._ssh.exec_command_sudo(cmd)

    def qemu_system_status(self):
        """Return current VM status.

        VM should be in following status:

            - debug: QEMU running on a debugger
            - finish-migrate: paused to finish the migration process
            - inmigrate: waiting for an incoming migration
            - internal-error: internal error has occurred
            - io-error: the last IOP has failed
            - paused: paused
            - postmigrate: paused following a successful migrate
            - prelaunch: QEMU was started with -S and guest has not started
            - restore-vm: paused to restore VM state
            - running: actively running
            - save-vm: paused to save the VM state
            - shutdown: shut down (and -no-shutdown is in use)
            - suspended: suspended (ACPI S3)
            - watchdog: watchdog action has been triggered
            - guest-panicked: panicked as a result of guest OS panic

        :return: VM status.
        :rtype: str
        """
        out = self._qemu_qmp_exec('query-status')
        ret = out.get('return')
        if ret is not None:
            return ret.get('status')
        else:
            err = out.get('error')
            raise RuntimeError(
                'QEMU query-status failed on {0}, '
                'error: {1}'.format(self._node['host'], json.dumps(err)))

    @staticmethod
    def build_qemu(node, force_install=False, apply_patch=False):
        """Build QEMU from sources.

        :param node: Node to build QEMU on.
        :param force_install: If True, then remove previous build.
        :param apply_patch: If True, then apply patches from qemu_patches dir.
        :type node: dict
        :type force_install: bool
        :type apply_patch: bool
        :raises: RuntimeError if building QEMU failed.
        """

        directory = ' --directory={0}'.format(Constants.QEMU_INSTALL_DIR)
        version = ' --version={0}'.format(Constants.QEMU_INSTALL_VERSION)
        force = ' --force' if force_install else ''
        patch = ' --patch' if apply_patch else ''

        (ret_code, stdout, stderr) = VPPUtil. \
            exec_command(
            "sudo -E sh -c '{0}/{1}/qemu_build.sh{2}{3}{4}{5}'".
                format(Constants.REMOTE_FW_DIR, Constants.RESOURCES_LIB_SH,
                       version, directory, force, patch), 1000)

        if int(ret_code) != 0:
            logging.debug('QEMU build failed {0}'.format(stdout + stderr))
            raise RuntimeError('QEMU build failed on {0}'.format(node['host']))
