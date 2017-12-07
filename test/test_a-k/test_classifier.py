#!/usr/bin/env python

import unittest
import socket
import binascii

from framework import VppTestCase, VppTestRunner

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from util import ppp


class TestClassifier(VppTestCase):
    """ Classifier Test Case """

    def setUp(self):
        """
        Perform test setup before test case.

        **Config:**
            - create 4 pg interfaces
                - untagged pg0/pg1/pg2 interface
                    pg0 -------> pg1 (IP ACL)
                           \
                            ---> pg2 (MAC ACL))
                             \
                              -> pg3 (PBR)
            - setup interfaces:
                - put it into UP state
                - set IPv4 addresses
                - resolve neighbor address using ARP

        :ivar list interfaces: pg interfaces.
        :ivar list pg_if_packet_sizes: packet sizes in test.
        :ivar dict acl_tbl_idx: ACL table index.
        :ivar int pbr_vrfid: VRF id for PBR test.
        """
        super(TestClassifier, self).setUp()

        # create 4 pg interfaces
        self.create_pg_interfaces(range(4))

        # packet sizes to test
        self.pg_if_packet_sizes = [64, 9018]

        self.interfaces = list(self.pg_interfaces)

        # ACL & PBR vars
        self.acl_tbl_idx = {}
        self.pbr_vrfid = 200

        # setup all interfaces
        for intf in self.interfaces:
            intf.admin_up()
            intf.config_ip4()
            intf.resolve_arp()

    def tearDown(self):
        """Run standard test teardown and acl related log."""
        super(TestClassifier, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.cli("show classify table verbose"))
            self.logger.info(self.vapi.cli("show ip fib"))

    def config_pbr_fib_entry(self, intf, is_add=1):
        """Configure fib entry to route traffic toward PBR VRF table

        :param VppInterface intf: destination interface to be routed for PBR.

        """
        addr_len = 24
        self.vapi.ip_add_del_route(intf.local_ip4n,
                                   addr_len,
                                   intf.remote_ip4n,
                                   table_id=self.pbr_vrfid,
                                   is_add=is_add)

    def create_stream(self, src_if, dst_if, packet_sizes):
        """Create input packet stream for defined interfaces.

        :param VppInterface src_if: Source Interface for packet stream.
        :param VppInterface dst_if: Destination Interface for packet stream.
        :param list packet_sizes: packet size to test.
        """
        pkts = []
        for size in packet_sizes:
            info = self.create_packet_info(src_if, dst_if)
            payload = self.info_to_payload(info)
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4) /
                 UDP(sport=1234, dport=5678) /
                 Raw(payload))
            info.data = p.copy()
            self.extend_packet(p, size)
            pkts.append(p)
        return pkts

    def verify_capture(self, dst_if, capture):
        """Verify captured input packet stream for defined interface.

        :param VppInterface dst_if: Interface to verify captured packet stream.
        :param list capture: Captured packet stream.
        """
        self.logger.info("Verifying capture on interface %s" % dst_if.name)
        last_info = dict()
        for i in self.interfaces:
            last_info[i.sw_if_index] = None
        dst_sw_if_index = dst_if.sw_if_index
        for packet in capture:
            try:
                ip = packet[IP]
                udp = packet[UDP]
                payload_info = self.payload_to_info(str(packet[Raw]))
                packet_index = payload_info.index
                self.assertEqual(payload_info.dst, dst_sw_if_index)
                self.logger.debug(
                    "Got packet on port %s: src=%u (id=%u)" %
                    (dst_if.name, payload_info.src, packet_index))
                next_info = self.get_next_packet_info_for_interface2(
                    payload_info.src, dst_sw_if_index,
                    last_info[payload_info.src])
                last_info[payload_info.src] = next_info
                self.assertTrue(next_info is not None)
                self.assertEqual(packet_index, next_info.index)
                saved_packet = next_info.data
                # Check standard fields
                self.assertEqual(ip.src, saved_packet[IP].src)
                self.assertEqual(ip.dst, saved_packet[IP].dst)
                self.assertEqual(udp.sport, saved_packet[UDP].sport)
                self.assertEqual(udp.dport, saved_packet[UDP].dport)
            except:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        for i in self.interfaces:
            remaining_packet = self.get_next_packet_info_for_interface2(
                i.sw_if_index, dst_sw_if_index, last_info[i.sw_if_index])
            self.assertTrue(remaining_packet is None,
                            "Interface %s: Packet expected from interface %s "
                            "didn't arrive" % (dst_if.name, i.name))

    def verify_vrf(self, vrf_id):
        """
        Check if the FIB table / VRF ID is configured.

        :param int vrf_id: The FIB table / VRF ID to be verified.
        :return: 1 if the FIB table / VRF ID is configured, otherwise return 0.
        """
        ip_fib_dump = self.vapi.ip_fib_dump()
        vrf_count = 0
        for ip_fib_details in ip_fib_dump:
            if ip_fib_details[2] == vrf_id:
                vrf_count += 1
        if vrf_count == 0:
            self.logger.info("IPv4 VRF ID %d is not configured" % vrf_id)
            return 0
        else:
            self.logger.info("IPv4 VRF ID %d is configured" % vrf_id)
            return 1

    @staticmethod
    def build_ip_mask(proto='', src_ip='', dst_ip='',
                      src_port='', dst_port=''):
        """Build IP ACL mask data with hexstring format

        :param str proto: protocol number <0-ff>
        :param str src_ip: source ip address <0-ffffffff>
        :param str dst_ip: destination ip address <0-ffffffff>
        :param str src_port: source port number <0-ffff>
        :param str dst_port: destination port number <0-ffff>
        """

        return ('{:0>20}{:0>12}{:0>8}{:0>12}{:0>4}'.format(
            proto, src_ip, dst_ip, src_port, dst_port)).rstrip('0')

    @staticmethod
    def build_ip_match(proto='', src_ip='', dst_ip='',
                       src_port='', dst_port=''):
        """Build IP ACL match data with hexstring format

        :param str proto: protocol number with valid option "<0-ff>"
        :param str src_ip: source ip address with format of "x.x.x.x"
        :param str dst_ip: destination ip address with format of "x.x.x.x"
        :param str src_port: source port number <0-ffff>
        :param str dst_port: destination port number <0-ffff>
        """
        if src_ip:
            src_ip = socket.inet_aton(src_ip).encode('hex')
        if dst_ip:
            dst_ip = socket.inet_aton(dst_ip).encode('hex')

        return ('{:0>20}{:0>12}{:0>8}{:0>12}{:0>4}'.format(
            proto, src_ip, dst_ip, src_port, dst_port)).rstrip('0')

    @staticmethod
    def build_mac_mask(dst_mac='', src_mac='', ether_type=''):
        """Build MAC ACL mask data with hexstring format

        :param str dst_mac: source MAC address <0-ffffffffffff>
        :param str src_mac: destination MAC address <0-ffffffffffff>
        :param str ether_type: ethernet type <0-ffff>
        """

        return ('{:0>12}{:0>12}{:0>4}'.format(dst_mac, src_mac,
                                              ether_type)).rstrip('0')

    @staticmethod
    def build_mac_match(dst_mac='', src_mac='', ether_type=''):
        """Build MAC ACL match data with hexstring format

        :param str dst_mac: source MAC address <x:x:x:x:x:x>
        :param str src_mac: destination MAC address <x:x:x:x:x:x>
        :param str ether_type: ethernet type <0-ffff>
        """
        if dst_mac:
            dst_mac = dst_mac.replace(':', '')
        if src_mac:
            src_mac = src_mac.replace(':', '')

        return ('{:0>12}{:0>12}{:0>4}'.format(dst_mac, src_mac,
                                              ether_type)).rstrip('0')

    def create_classify_table(self, key, mask, data_offset=0, is_add=1):
        """Create Classify Table

        :param str key: key for classify table (ex, ACL name).
        :param str mask: mask value for interested traffic.
        :param int match_n_vectors:
        :param int is_add: option to configure classify table.
            - create(1) or delete(0)
        """
        r = self.vapi.classify_add_del_table(
            is_add,
            binascii.unhexlify(mask),
            match_n_vectors=(len(mask) - 1) // 32 + 1,
            miss_next_index=0,
            current_data_flag=1,
            current_data_offset=data_offset)
        self.assertIsNotNone(r, msg='No response msg for add_del_table')
        self.acl_tbl_idx[key] = r.new_table_index

    def create_classify_session(self, intf, table_index, match,
                                pbr_option=0, vrfid=0, is_add=1):
        """Create Classify Session

        :param VppInterface intf: Interface to apply classify session.
        :param int table_index: table index to identify classify table.
        :param str match: matched value for interested traffic.
        :param int pbr_action: enable/disable PBR feature.
        :param int vrfid: VRF id.
        :param int is_add: option to configure classify session.
            - create(1) or delete(0)
        """
        r = self.vapi.classify_add_del_session(
            is_add,
            table_index,
            binascii.unhexlify(match),
            opaque_index=0,
            action=pbr_option,
            metadata=vrfid)
        self.assertIsNotNone(r, msg='No response msg for add_del_session')

    def input_acl_set_interface(self, intf, table_index, is_add=1):
        """Configure Input ACL interface

        :param VppInterface intf: Interface to apply Input ACL feature.
        :param int table_index: table index to identify classify table.
        :param int is_add: option to configure classify session.
            - enable(1) or disable(0)
        """
        r = self.vapi.input_acl_set_interface(
            is_add,
            intf.sw_if_index,
            ip4_table_index=table_index)
        self.assertIsNotNone(r, msg='No response msg for acl_set_interface')

    def test_acl_ip(self):
        """ IP ACL test

        Test scenario for basic IP ACL with source IP
            - Create IPv4 stream for pg0 -> pg1 interface.
            - Create ACL with source IP address.
            - Send and verify received packets on pg1 interface.
        """

        # Basic ACL testing with source IP
        pkts = self.create_stream(self.pg0, self.pg1, self.pg_if_packet_sizes)
        self.pg0.add_stream(pkts)

        self.create_classify_table('ip', self.build_ip_mask(src_ip='ffffffff'))
        self.create_classify_session(
            self.pg0, self.acl_tbl_idx.get('ip'),
            self.build_ip_match(src_ip=self.pg0.remote_ip4))
        self.input_acl_set_interface(self.pg0, self.acl_tbl_idx.get('ip'))

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg1.get_capture(len(pkts))
        self.verify_capture(self.pg1, pkts)
        self.input_acl_set_interface(self.pg0, self.acl_tbl_idx.get('ip'), 0)
        self.pg0.assert_nothing_captured(remark="packets forwarded")
        self.pg2.assert_nothing_captured(remark="packets forwarded")
        self.pg3.assert_nothing_captured(remark="packets forwarded")

    def test_acl_mac(self):
        """ MAC ACL test

        Test scenario for basic MAC ACL with source MAC
            - Create IPv4 stream for pg0 -> pg2 interface.
            - Create ACL with source MAC address.
            - Send and verify received packets on pg2 interface.
        """

        # Basic ACL testing with source MAC
        pkts = self.create_stream(self.pg0, self.pg2, self.pg_if_packet_sizes)
        self.pg0.add_stream(pkts)

        self.create_classify_table('mac',
                                   self.build_mac_mask(src_mac='ffffffffffff'),
                                   data_offset=-14)
        self.create_classify_session(
            self.pg0, self.acl_tbl_idx.get('mac'),
            self.build_mac_match(src_mac=self.pg0.remote_mac))
        self.input_acl_set_interface(self.pg0, self.acl_tbl_idx.get('mac'))

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg2.get_capture(len(pkts))
        self.verify_capture(self.pg2, pkts)
        self.input_acl_set_interface(self.pg0, self.acl_tbl_idx.get('mac'), 0)
        self.pg0.assert_nothing_captured(remark="packets forwarded")
        self.pg1.assert_nothing_captured(remark="packets forwarded")
        self.pg3.assert_nothing_captured(remark="packets forwarded")

    def test_acl_pbr(self):
        """ IP PBR test

        Test scenario for PBR with source IP
            - Create IPv4 stream for pg0 -> pg3 interface.
            - Configure PBR fib entry for packet forwarding.
            - Send and verify received packets on pg3 interface.
        """

        # PBR testing with source IP
        pkts = self.create_stream(self.pg0, self.pg3, self.pg_if_packet_sizes)
        self.pg0.add_stream(pkts)

        self.create_classify_table(
            'pbr', self.build_ip_mask(
                src_ip='ffffffff'))
        pbr_option = 1
        # this will create the VRF/table in which we will insert the route
        self.create_classify_session(
            self.pg0, self.acl_tbl_idx.get('pbr'),
            self.build_ip_match(src_ip=self.pg0.remote_ip4),
            pbr_option, self.pbr_vrfid)
        self.assertTrue(self.verify_vrf(self.pbr_vrfid))
        self.config_pbr_fib_entry(self.pg3)
        self.input_acl_set_interface(self.pg0, self.acl_tbl_idx.get('pbr'))

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg3.get_capture(len(pkts))
        self.verify_capture(self.pg3, pkts)
        self.input_acl_set_interface(self.pg0, self.acl_tbl_idx.get('pbr'), 0)
        self.pg0.assert_nothing_captured(remark="packets forwarded")
        self.pg1.assert_nothing_captured(remark="packets forwarded")
        self.pg2.assert_nothing_captured(remark="packets forwarded")

        # remove the classify session and the route
        self.config_pbr_fib_entry(self.pg3, is_add=0)
        self.create_classify_session(
            self.pg0, self.acl_tbl_idx.get('pbr'),
            self.build_ip_match(src_ip=self.pg0.remote_ip4),
            pbr_option, self.pbr_vrfid, is_add=0)

        # and the table should be gone.
        self.assertFalse(self.verify_vrf(self.pbr_vrfid))

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
