import ipaddress
import socket
import unittest

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, ICMP

from framework import VppTestCase, VppTestRunner, running_extended_tests
from remote_test import RemoteClass, RemoteVppTestCase
from vpp_memif import remove_all_memif_vpp_config, \
    VppSocketFilename, VppMemif
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_papi import VppEnum

DEFAULT_MEMIF_SOCKET = "%s/memif.sock"


# VppMemif doesn't implement VppInterface.
# Until it does, patch in the interface methods that the testcase uses.
def config_ip4(self):
    try:
        self.ip_prefix
    except AttributeError:
        self.ip_prefix = ipaddress.IPv4Interface(
            "192.168.%d.%d/24" % (self.if_id + 1, self.role + 1)
        )
    return self._test.vapi.sw_interface_add_del_address(
        sw_if_index=self.sw_if_index, prefix=self.ip_prefix)


VppMemif.config_ip4 = config_ip4


class TestMemif(VppTestCase):
    """ Memif Test Case """
    MEMIF_DEFAULT_RING_SIZE = None
    MEMIF_DEFAULT_BUFFER_SIZE = None

    @classmethod
    def force_solo(cls):
        return True

    @classmethod
    def setUpClass(cls):
        # fork new process before client connects to VPP
        cls.remote_test = RemoteClass(RemoteVppTestCase)
        cls.remote_test.start_remote()
        cls.remote_test.set_request_timeout(10)
        super(TestMemif, cls).setUpClass()
        cls.remote_test.setUpClass(cls.tempdir)
        cls.create_pg_interfaces(range(1))
        for pg in cls.pg_interfaces:
            pg.config_ip4()
            pg.admin_up()
            pg.resolve_arp()

        # set defaults from api.
        try:
            cls.MEMIF_DEFAULT_RING_SIZE = cls.vapi.vpp.get_field_options(
                'memif_create', 'ring_size')['default']
            cls.MEMIF_DEFAULT_BUFFER_SIZE = cls.vapi.vpp.get_field_options(
                'memif_create', 'buffer_size')['default']
        except KeyError:
            raise RuntimeError("Can no longer get field default "
                               "value from .api.")

    @classmethod
    def tearDownClass(cls):
        cls.remote_test.tearDownClass()
        cls.remote_test.quit_remote()
        for pg in cls.pg_interfaces:
            pg.unconfig_ip4()
            pg.set_table_ip4(0)
            pg.admin_down()
        super(TestMemif, cls).tearDownClass()

    def tearDown(self):
        remove_all_memif_vpp_config(self)
        remove_all_memif_vpp_config(self.remote_test)
        super(TestMemif, self).tearDown()

    def _check_socket_filename(self, dump, socket_id, filename):
        for d in dump:
            if (d.socket_id == socket_id) and (
                    d.socket_filename == filename):
                return True
        return False

    def test_memif_socket_filename_add_del(self):
        """ Memif socket filename add/del """

        # dump default socket filename
        dump = self.vapi.memif_socket_filename_dump()
        self.assertTrue(
            self._check_socket_filename(
                dump, 0, DEFAULT_MEMIF_SOCKET % self.tempdir))

        memif_sockets = []
        # existing path
        memif_sockets.append(
            VppSocketFilename(
                self, 1, "%s/memif1.sock" % self.tempdir))
        # default path (test tempdir)
        memif_sockets.append(
            VppSocketFilename(
                self,
                2,
                "memif2.sock",
                add_default_folder=True))
        # create new folder in default folder
        memif_sockets.append(
            VppSocketFilename(
                self,
                3,
                "sock/memif3.sock",
                add_default_folder=True))

        for sock in memif_sockets:
            sock.add_vpp_config()
            dump = sock.query_vpp_config()
            self.assertTrue(
                self._check_socket_filename(
                    dump,
                    sock.socket_id,
                    sock.socket_filename))

        for sock in memif_sockets:
            sock.remove_vpp_config()

        dump = self.vapi.memif_socket_filename_dump()
        self.assertTrue(
            self._check_socket_filename(
                dump, 0, DEFAULT_MEMIF_SOCKET % self.tempdir))

    def _create_delete_test_one_interface(self, memif):
        memif.add_vpp_config()

        dump = memif.query_vpp_config()

        self.assertTrue(dump)
        self.assertEqual(dump.sw_if_index, memif.sw_if_index)
        self.assertEqual(dump.role, memif.role)
        self.assertEqual(dump.mode, memif.mode)
        if (memif.socket_id is not None):
            self.assertEqual(dump.socket_id, memif.socket_id)

        memif.remove_vpp_config()

        dump = memif.query_vpp_config()

        self.assertFalse(dump)

    def _connect_test_one_interface(self, memif):
        self.assertTrue(memif.wait_for_link_up(5))
        dump = memif.query_vpp_config()

        if memif.role == VppEnum.vl_api_memif_role_t.MEMIF_ROLE_API_SLAVE:
            self.assertEqual(dump.ring_size,
                             memif.ring_size if memif.ring_size else
                             self.__class__.MEMIF_DEFAULT_RING_SIZE)
            self.assertEqual(dump.buffer_size,
                             memif.buffer_size if memif.buffer_size else
                             self.__class__.MEMIF_DEFAULT_BUFFER_SIZE)
        else:
            self.assertEqual(dump.ring_size, 1)
            self.assertEqual(dump.buffer_size, 0)

    def _connect_test_interface_pair(self, memif0, memif1):
        memif0.add_vpp_config()
        memif1.add_vpp_config()

        memif0.admin_up()
        memif1.admin_up()

        self._connect_test_one_interface(memif0)
        self._connect_test_one_interface(memif1)

        memif0.remove_vpp_config()
        memif1.remove_vpp_config()

    def test_memif_create_delete(self):
        """ Memif create/delete interface """

        memif = VppMemif(
            self,
            VppEnum.vl_api_memif_role_t.MEMIF_ROLE_API_SLAVE,
            VppEnum.vl_api_memif_mode_t.MEMIF_MODE_API_ETHERNET)
        self._create_delete_test_one_interface(memif)
        memif.role = VppEnum.vl_api_memif_role_t.MEMIF_ROLE_API_MASTER
        self._create_delete_test_one_interface(memif)

    def test_memif_create_custom_socket(self):
        """ Memif create with non-default socket filename """

        memif_sockets = []
        # existing path
        memif_sockets.append(
            VppSocketFilename(
                self, 1, "%s/memif1.sock" % self.tempdir))
        # default path (test tempdir)
        memif_sockets.append(
            VppSocketFilename(
                self,
                2,
                "memif2.sock",
                add_default_folder=True))
        # create new folder in default folder
        memif_sockets.append(
            VppSocketFilename(
                self,
                3,
                "sock/memif3.sock",
                add_default_folder=True))

        memif = VppMemif(
            self,
            VppEnum.vl_api_memif_role_t.MEMIF_ROLE_API_SLAVE,
            VppEnum.vl_api_memif_mode_t.MEMIF_MODE_API_ETHERNET)

        for sock in memif_sockets:
            sock.add_vpp_config()
            memif.socket_id = sock.socket_id
            memif.role = VppEnum.vl_api_memif_role_t.MEMIF_ROLE_API_SLAVE
            self._create_delete_test_one_interface(memif)
            memif.role = VppEnum.vl_api_memif_role_t.MEMIF_ROLE_API_MASTER
            self._create_delete_test_one_interface(memif)

    def test_memif_connect(self):
        """ Memif connect """
        memif = VppMemif(
            self,
            VppEnum.vl_api_memif_role_t.MEMIF_ROLE_API_SLAVE,
            VppEnum.vl_api_memif_mode_t.MEMIF_MODE_API_ETHERNET,
            secret="abc")

        remote_socket = VppSocketFilename(self.remote_test, 1,
                                          DEFAULT_MEMIF_SOCKET % self.tempdir)
        remote_socket.add_vpp_config()

        remote_memif = VppMemif(
            self.remote_test,
            VppEnum.vl_api_memif_role_t.MEMIF_ROLE_API_MASTER,
            VppEnum.vl_api_memif_mode_t.MEMIF_MODE_API_ETHERNET,
            socket_id=1,
            secret="abc")

        self._connect_test_interface_pair(memif, remote_memif)

        memif.role = VppEnum.vl_api_memif_role_t.MEMIF_ROLE_API_MASTER
        remote_memif.role = VppEnum.vl_api_memif_role_t.MEMIF_ROLE_API_SLAVE

        self._connect_test_interface_pair(memif, remote_memif)

    def _create_icmp(self, pg, memif, num):
        """return a generator of icmp packets with increasing seq #'s"""
        for i in range(num):
            pkt = (Ether(dst=pg.local_mac, src=pg.remote_mac) /
                   IP(src=pg.remote_ip4,
                      dst=str(memif.ip_prefix.ip)) /
                   ICMP(id=memif.if_id, type='echo-request', seq=i))
            yield pkt

    def _verify_icmp(self, pg, memif, rx, seq):
        ip = rx[IP]
        self.assertEqual(ip.src, str(memif.ip_prefix.ip))
        self.assertEqual(ip.dst, pg.remote_ip4)
        self.assertEqual(ip.proto, socket.IPPROTO_ICMP)
        icmp = rx[ICMP]
        self.assertEqual(icmp.type, 0)  # echo-reply
        self.assertEqual(icmp.id, memif.if_id)
        self.assertEqual(icmp.seq, seq)

    def test_memif_ping(self):
        r""" test ping remote vpp instance over memif0/0


172.16.1.1/24
 +-----+
 | pg0 +-+    192.168.<id+1>.2/24           192.168.<id+1>.1/24
 +-----+  \          slave                         master
          +-----+ +----------+  /memif.sock  +-----------------+ +-----------+
          | vpp +-+ memif0/0 +---------------+ remote_memif0/0 +-+remote vpp |
          +-----+ +----------+               +-----------------+ +-----------+
 +-----+ /
 | pg1 +-+
 +-----+
        """
        memif = VppMemif(
            self,
            VppEnum.vl_api_memif_role_t.MEMIF_ROLE_API_SLAVE,
            VppEnum.vl_api_memif_mode_t.MEMIF_MODE_API_ETHERNET)

        remote_socket = VppSocketFilename(self.remote_test, 1,
                                          DEFAULT_MEMIF_SOCKET % self.tempdir)
        remote_socket.add_vpp_config()

        remote_memif = VppMemif(
            self.remote_test,
            VppEnum.vl_api_memif_role_t.MEMIF_ROLE_API_MASTER,
            VppEnum.vl_api_memif_mode_t.MEMIF_MODE_API_ETHERNET,
            socket_id=1)

        memif.add_vpp_config()
        # we are slave .2/24
        memif.config_ip4()
        memif.admin_up()

        remote_memif.add_vpp_config()
        # remote is master .1/24
        remote_memif.config_ip4()
        remote_memif.admin_up()

        self.assertTrue(memif.wait_for_link_up(5))
        self.assertTrue(remote_memif.wait_for_link_up(5))

        # add route for local vpp.pg0 to remote vpp for reply
        route = VppIpRoute(self.remote_test, self.pg0._local_ip4_subnet,
                           remote_memif.ip_prefix._prefixlen,
                           [VppRoutePath(
                               memif.ip_prefix.ip,
                               0xffffffff)],
                           register=False)
        route.add_vpp_config()

        # create ICMP echo-request from local pg0 to remote memif
        packet_num = 10
        pkts = self._create_icmp(self.pg0, remote_memif, packet_num)
        pkt_list = list(pkts)

        self.pg0.add_stream(pkt_list)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(packet_num, timeout=2)
        seq = 0
        for c in capture:
            self._verify_icmp(self.pg0, remote_memif, c, seq)
            seq += 1

        route.remove_vpp_config()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
