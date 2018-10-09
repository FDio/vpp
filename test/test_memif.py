import unittest

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, ICMP

from framework import VppTestCase, VppTestRunner, running_extended_tests
from remote_test import RemoteClass, RemoteVppTestCase
from vpp_memif import *


class TestMemif(VppTestCase):
    """ Memif Test Case """

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
                    d.socket_filename.rstrip("\0") == filename):
                return True
        return False

    def test_memif_socket_filename_add_del(self):
        """ Memif socket filenale add/del """

        # dump default socket filename
        dump = self.vapi.memif_socket_filename_dump()
        self.assertTrue(
            self._check_socket_filename(
                dump, 0, self.tempdir + "/memif.sock"))

        memif_sockets = []
        # existing path
        memif_sockets.append(
            VppSocketFilename(
                self, 1, self.tempdir + "/memif1.sock"))
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
                dump, 0, self.tempdir + "/memif.sock"))

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

        if memif.role == MEMIF_ROLE.SLAVE:
            self.assertEqual(dump.ring_size, memif.ring_size)
            self.assertEqual(dump.buffer_size, memif.buffer_size)
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

        memif = VppMemif(self, MEMIF_ROLE.SLAVE, MEMIF_MODE.ETHERNET)
        self._create_delete_test_one_interface(memif)
        memif.role = MEMIF_ROLE.MASTER
        self._create_delete_test_one_interface(memif)

    def test_memif_create_custom_socket(self):
        """ Memif create with non-default socket filname """

        memif_sockets = []
        # existing path
        memif_sockets.append(
            VppSocketFilename(
                self, 1, self.tempdir + "/memif1.sock"))
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

        memif = VppMemif(self, MEMIF_ROLE.SLAVE, MEMIF_MODE.ETHERNET)

        for sock in memif_sockets:
            sock.add_vpp_config()
            memif.socket_id = sock.socket_id
            memif.role = MEMIF_ROLE.SLAVE
            self._create_delete_test_one_interface(memif)
            memif.role = MEMIF_ROLE.MASTER
            self._create_delete_test_one_interface(memif)

    def test_memif_connect(self):
        """ Memif connect """
        memif = VppMemif(self, MEMIF_ROLE.SLAVE,  MEMIF_MODE.ETHERNET,
                         ring_size=1024, buffer_size=2048)

        remote_socket = VppSocketFilename(self.remote_test, 1,
                                          self.tempdir + "/memif.sock")
        remote_socket.add_vpp_config()

        remote_memif = VppMemif(self.remote_test, MEMIF_ROLE.MASTER,
                                MEMIF_MODE.ETHERNET, socket_id=1,
                                ring_size=1024, buffer_size=2048)

        self._connect_test_interface_pair(memif, remote_memif)

        memif.role = MEMIF_ROLE.MASTER
        remote_memif.role = MEMIF_ROLE.SLAVE

        self._connect_test_interface_pair(memif, remote_memif)

    def _create_icmp(self, pg, memif, num):
        pkts = []
        for i in range(num):
            pkt = (Ether(dst=pg.local_mac, src=pg.remote_mac) /
                   IP(src=pg.remote_ip4, dst=memif.ip4_addr) /
                   ICMP(id=memif.if_id, type='echo-request', seq=i))
            pkts.append(pkt)
        return pkts

    def _verify_icmp(self, pg, memif, rx, seq):
        ip = rx[IP]
        self.assertEqual(ip.src, memif.ip4_addr)
        self.assertEqual(ip.dst, pg.remote_ip4)
        self.assertEqual(ip.proto, 1)
        icmp = rx[ICMP]
        self.assertEqual(icmp.type, 0)  # echo-reply
        self.assertEqual(icmp.id, memif.if_id)
        self.assertEqual(icmp.seq, seq)

    def test_memif_ping(self):
        """ Memif ping """
        memif = VppMemif(self, MEMIF_ROLE.SLAVE,  MEMIF_MODE.ETHERNET)

        remote_socket = VppSocketFilename(self.remote_test, 1,
                                          self.tempdir + "/memif.sock")
        remote_socket.add_vpp_config()

        remote_memif = VppMemif(self.remote_test, MEMIF_ROLE.MASTER,
                                MEMIF_MODE.ETHERNET, socket_id=1)

        memif.add_vpp_config()
        memif.config_ip4()
        memif.admin_up()

        remote_memif.add_vpp_config()
        remote_memif.config_ip4()
        remote_memif.admin_up()

        self.assertTrue(memif.wait_for_link_up(5))
        self.assertTrue(remote_memif.wait_for_link_up(5))

        # add routing to remote vpp
        dst_addr = socket.inet_pton(socket.AF_INET, self.pg0._local_ip4_subnet)
        dst_addr_len = 24
        next_hop_addr = socket.inet_pton(socket.AF_INET, memif.ip4_addr)
        self.remote_test.vapi.ip_add_del_route(
            dst_addr, dst_addr_len, next_hop_addr)

        # create ICMP echo-request from local pg to remote memif
        packet_num = 10
        pkts = self._create_icmp(self.pg0, remote_memif, packet_num)

        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(packet_num, timeout=2)
        seq = 0
        for c in capture:
            self._verify_icmp(self.pg0, remote_memif, c, seq)
            seq += 1


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
