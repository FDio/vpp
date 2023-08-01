#!/usr/bin/env python3
"""NAT44 ED output-feature tests"""

import random
import unittest
from scapy.layers.inet import ICMP, Ether, IP, TCP
from scapy.packet import Raw
from scapy.data import IP_PROTOS
from framework import VppTestCase, VppTestRunner
from vpp_papi import VppEnum


def get_nat44_ed_in2out_worker_index(ip, vpp_worker_count):
    if 0 == vpp_worker_count:
        return 0
    numeric = socket.inet_aton(ip)
    numeric = struct.unpack("!L", numeric)[0]
    numeric = socket.htonl(numeric)
    h = numeric + (numeric >> 8) + (numeric >> 16) + (numeric >> 24)
    return 1 + h % vpp_worker_count


class TestNAT44EDOutput(VppTestCase):
    """NAT44 ED output feature Test Case"""

    max_sessions = 1024

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_pg_interfaces(range(2))
        cls.interfaces = list(cls.pg_interfaces)

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        for i in self.interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
        self.vapi.nat44_ed_plugin_enable_disable(sessions=self.max_sessions, enable=1)

    def tearDown(self):
        if not self.vpp_dead:
            self.logger.debug(self.vapi.cli("show nat44 sessions"))
        super().tearDown()
        if not self.vpp_dead:
            for i in self.pg_interfaces:
                i.unconfig_ip4()
                i.admin_down()
            self.vapi.nat44_ed_plugin_enable_disable(enable=0)

    def test_static_dynamic(self):
        """Create static mapping which matches existing dynamic mapping"""

        config = self.vapi.nat44_show_running_config()
        old_timeouts = config.timeouts
        new_transitory = 2
        self.vapi.nat_set_timeouts(
            udp=old_timeouts.udp,
            tcp_established=old_timeouts.tcp_established,
            icmp=old_timeouts.icmp,
            tcp_transitory=new_transitory,
        )

        local_host = self.pg0.remote_ip4
        remote_host = self.pg1.remote_ip4
        nat_intf = self.pg1
        outside_addr = nat_intf.local_ip4

        self.vapi.nat44_add_del_address_range(
            first_ip_address=outside_addr,
            last_ip_address=outside_addr,
            vrf_id=0xFFFFFFFF,
            is_add=1,
            flags=0,
        )
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index, is_add=1
        )
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=VppEnum.vl_api_nat_config_flags_t.NAT_IS_INSIDE,
            is_add=1,
        )
        self.vapi.nat44_ed_add_del_output_interface(
            sw_if_index=self.pg1.sw_if_index, is_add=1
        )

        thread_index = get_nat44_ed_in2out_worker_index(
            local_host, self.vpp_worker_count
        )
        port_per_thread = int((0xFFFF - 1024) / max(1, self.vpp_worker_count))
        local_sport = 1024 + random.randint(1, port_per_thread)
        if self.vpp_worker_count > 0:
            local_sport += port_per_thread * (thread_index - 1)

        remote_dport = 10000

        pg0 = self.pg0
        pg1 = self.pg1

        # first setup a dynamic TCP session

        # SYN packet in->out
        p = (
            Ether(src=pg0.remote_mac, dst=pg0.local_mac)
            / IP(src=local_host, dst=remote_host)
            / TCP(sport=local_sport, dport=remote_dport, flags="S")
        )
        p = self.send_and_expect(pg0, [p], pg1)[0]

        self.assertEqual(p[IP].src, outside_addr)
        self.assertEqual(p[TCP].sport, local_sport)
        outside_port = p[TCP].sport

        # SYN+ACK packet out->in
        p = (
            Ether(src=pg1.remote_mac, dst=pg1.local_mac)
            / IP(src=remote_host, dst=outside_addr)
            / TCP(sport=remote_dport, dport=outside_port, flags="SA")
        )
        self.send_and_expect(pg1, [p], pg0)

        # ACK packet in->out
        p = (
            Ether(src=pg0.remote_mac, dst=pg0.local_mac)
            / IP(src=local_host, dst=remote_host)
            / TCP(sport=local_sport, dport=remote_dport, flags="A")
        )
        self.send_and_expect(pg0, [p], pg1)

        # now we have a session up, create a conflicting static mapping
        self.vapi.nat44_add_del_static_mapping(
            is_add=1,
            local_ip_address=local_host,
            external_ip_address=outside_addr,
            external_sw_if_index=0xFFFFFFFF,
            local_port=local_sport,
            external_port=outside_port,
            protocol=IP_PROTOS.tcp,
            flags=VppEnum.vl_api_nat_config_flags_t.NAT_IS_OUT2IN_ONLY,
        )

        sessions = self.vapi.nat44_user_session_dump(local_host, 0)
        self.assertEqual(1, len(sessions))

        # now send some more data over existing session - it should pass

        # in->out
        p = (
            Ether(src=pg0.remote_mac, dst=pg0.local_mac)
            / IP(src=local_host, dst=remote_host)
            / TCP(sport=local_sport, dport=remote_dport)
            / Raw("zippity zap")
        )
        self.send_and_expect(pg0, [p], pg1)

        # out->in
        p = (
            Ether(src=pg1.remote_mac, dst=pg1.local_mac)
            / IP(src=remote_host, dst=outside_addr)
            / TCP(sport=remote_dport, dport=outside_port)
            / Raw("flippity flop")
        )
        self.send_and_expect(pg1, [p], pg0)

        # now close the session

        # FIN packet in -> out
        p = (
            Ether(src=pg0.remote_mac, dst=pg0.local_mac)
            / IP(src=local_host, dst=remote_host)
            / TCP(sport=local_sport, dport=remote_dport, flags="FA", seq=100, ack=300)
        )
        self.send_and_expect(pg0, [p], pg1)

        # FIN+ACK packet out -> in
        p = (
            Ether(src=pg1.remote_mac, dst=pg1.local_mac)
            / IP(src=remote_host, dst=outside_addr)
            / TCP(sport=remote_dport, dport=outside_port, flags="FA", seq=300, ack=101)
        )
        self.send_and_expect(pg1, [p], pg0)

        # ACK packet in -> out
        p = (
            Ether(src=pg0.remote_mac, dst=pg0.local_mac)
            / IP(src=local_host, dst=remote_host)
            / TCP(sport=local_sport, dport=remote_dport, flags="A", seq=101, ack=301)
        )
        self.send_and_expect(pg0, [p], pg1)

        # session now in transitory timeout
        # try SYN packet in->out - should be dropped
        p = (
            Ether(src=pg0.remote_mac, dst=pg0.local_mac)
            / IP(src=local_host, dst=remote_host)
            / TCP(sport=local_sport, dport=remote_dport, flags="S")
        )
        pg0.add_stream(p)
        self.pg_enable_capture()
        self.pg_start()

        self.sleep(new_transitory, "wait for transitory timeout")
        pg0.assert_nothing_captured(0)

        # session should still exist
        sessions = self.vapi.nat44_user_session_dump(pg0.remote_ip4, 0)
        self.assertEqual(1, len(sessions))

        # send FIN+ACK packet in->out - will cause session to be wiped
        # but won't create a new session
        p = (
            Ether(src=pg0.remote_mac, dst=pg0.local_mac)
            / IP(src=local_host, dst=remote_host)
            / TCP(sport=local_sport, dport=remote_dport, flags="FA", seq=300, ack=101)
        )
        pg0.add_stream(p)
        self.pg_enable_capture()
        self.pg_start()
        pg1.assert_nothing_captured(0)

        sessions = self.vapi.nat44_user_session_dump(pg0.remote_ip4, 0)
        self.assertEqual(0, len(sessions))

        # create a new session and make sure the outside port is remapped
        # SYN packet in->out

        p = (
            Ether(src=pg0.remote_mac, dst=pg0.local_mac)
            / IP(src=local_host, dst=remote_host)
            / TCP(sport=local_sport, dport=remote_dport, flags="S")
        )
        p = self.send_and_expect(pg0, [p], pg1)[0]

        self.assertEqual(p[IP].src, outside_addr)
        self.assertNotEqual(p[TCP].sport, local_sport)

        # make sure static mapping works and creates a new session
        # SYN packet out->in
        p = (
            Ether(src=pg1.remote_mac, dst=pg1.local_mac)
            / IP(src=remote_host, dst=outside_addr)
            / TCP(sport=remote_dport, dport=outside_port, flags="S")
        )
        self.send_and_expect(pg1, [p], pg0)

        sessions = self.vapi.nat44_user_session_dump(pg0.remote_ip4, 0)
        self.assertEqual(2, len(sessions))


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
