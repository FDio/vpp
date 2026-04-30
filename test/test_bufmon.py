from asfframework import VppTestRunner
from framework import VppTestCase
import unittest
from config import config
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.layers.inet import IP, UDP
from random import randint
from util import ppp
from vpp_papi import mac_pton


@unittest.skipIf("bufmon" in config.excluded_plugins, "Exclude bufmon plugin tests")
class TestBufmon(VppTestCase):
    """bufmon plugin test"""

    @classmethod
    def setUpClass(cls):
        super(TestBufmon, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(3))
            for i in cls.pg_interfaces:
                i.config_ip4()
                i.resolve_arp()
                i.admin_up()
        except Exception:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()
        super(TestBufmon, cls).tearDownClass()

    # https://fd.io/docs/vpp/master/developer/tests/overview.html#example-how-to-add-a-new-test
    def create_stream(self, src_if, dst_if, count):
        packets = []
        for i in range(count):
            info = self.create_packet_info(src_if, dst_if)
            payload = self.info_to_payload(info)
            p = (
                Ether(dst=src_if.local_mac, src=src_if.remote_mac)
                / IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4)
                / UDP(sport=randint(49152, 65535), dport=5678)
                / Raw(payload)
            )
            info.data = p.copy()
            packets.append(p)
        return packets

    def verify_capture(self, src_if, dst_if, capture):
        packet_info = None
        for packet in capture:
            try:
                ip = packet[IP]
                udp = packet[UDP]
                # convert the payload to packet info object
                payload_info = self.payload_to_info(packet[Raw])
                # make sure the indexes match
                self.assert_equal(
                    payload_info.src, src_if.sw_if_index, "source sw_if_index"
                )
                self.assert_equal(
                    payload_info.dst, dst_if.sw_if_index, "destination sw_if_index"
                )
                packet_info = self.get_next_packet_info_for_interface2(
                    src_if.sw_if_index, dst_if.sw_if_index, packet_info
                )
                # make sure we didn't run out of saved packets
                self.assertIsNotNone(packet_info)
                self.assert_equal(
                    payload_info.index, packet_info.index, "packet info index"
                )
                saved_packet = packet_info.data  # fetch the saved packet
                # assert the values match
                self.assert_equal(ip.src, saved_packet[IP].src, "IP source address")
                # ... more assertions here
                self.assert_equal(udp.sport, saved_packet[UDP].sport, "UDP source port")
            except Exception:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        remaining_packet = self.get_next_packet_info_for_interface2(
            src_if.sw_if_index, dst_if.sw_if_index, packet_info
        )
        self.assertIsNone(
            remaining_packet,
            "Interface %s: Packet expected from interface "
            "%s didn't arrive" % (dst_if.name, src_if.name),
        )

    def get_node_stats(self, reply, node_name):
        for line in reply.splitlines():
            if node_name in line:
                fields = line.split()
                if len(fields) == 6:
                    return tuple(int(f) for f in fields[1:])
        return None

    def test_bufmon(self):
        self.vapi.cli("set buffer traces on")

        reply = self.vapi.cli("show buffer traces status")
        self.assertIn("buffers tracing is on", reply)

        packets = self.create_stream(self.pg0, self.pg1, 5)
        self.pg0.add_stream(packets)
        self.pg0.enable_capture()
        self.pg1.enable_capture()
        self.pg_start()

        capture = self.pg1.get_capture()
        self.pg0.assert_nothing_captured()
        self.verify_capture(self.pg0, self.pg1, capture)

        expected = [
            "pg-input",
            "ip4-input",
            "ip4-rewrite",
            "ip4-lookup",
            "ethernet-input",
            "pg1-tx",
            "pg1-output",
        ]
        reply = self.vapi.cli("show buffer traces verbose")
        for entry in expected:
            self.assertIn(entry, reply)

        # not verbose, skips nodes w/o buffered buffers
        reply = self.vapi.cli("show buffer traces")
        self.assertNotIn("pg-input", reply)

        self.vapi.cli("clear buffer traces")
        reply = self.vapi.cli("show buffer traces verbose")
        self.assertNotIn("pg-input", reply)

    def test_pending_frame_accounting_l2_bridge(self):
        """l2-fwd and l2-flood both feed l2-output in the same drain round,
        and both push to pg1-output. The second l2-output dispatch appends
        to the already-pending pg1-output next-frame; without the snapshot
        fix those vectors are missing from pnd->out."""
        bd_id = 1
        dst_unicast = "00:11:22:33:44:55"

        # put pg0/pg1/pg2 in one bridge domain; disable learning so the
        # static l2fib entry is the only known-unicast destination.
        # setUpClass configured IPv4 on these interfaces; drop it for the
        # duration of the test so bridging takes effect.
        for i in self.pg_interfaces:
            i.unconfig_ip4()
        self.vapi.bridge_domain_add_del_v2(
            bd_id=bd_id, flood=1, uu_flood=1, forward=1, learn=0, is_add=1
        )
        for i in self.pg_interfaces:
            self.vapi.sw_interface_set_l2_bridge(
                rx_sw_if_index=i.sw_if_index, bd_id=bd_id
            )
        # pre-program the known-unicast MAC on pg1 so l2-fwd takes it
        self.vapi.l2fib_add_del(
            mac_pton(dst_unicast), bd_id, self.pg1.sw_if_index, static_mac=1
        )

        try:
            # known-unicast pg0 -> pg1 via l2-fwd -> l2-output -> pg1-output
            k = 64
            known = [
                Ether(dst=dst_unicast, src=self.pg0.remote_mac) / Raw(b"K" * 64)
                for _ in range(k)
            ]
            # broadcast pg0 -> flood via l2-flood -> l2-output ->
            # (pg1-output, pg2-output)
            b = 64
            bcast = [
                Ether(dst="ff:ff:ff:ff:ff:ff", src=self.pg0.remote_mac) / Raw(b"B" * 64)
                for _ in range(b)
            ]

            self.vapi.cli("clear buffer traces")
            self.vapi.cli("set buffer traces on")

            self.pg0.add_stream(known + bcast)
            for i in self.pg_interfaces:
                i.enable_capture()
            self.pg_start()

            # sanity: pg1 receives known-unicast + broadcast, pg2 receives
            # only the broadcast replica. If these mismatch, the bridge
            # topology is wrong and the counter expectation below would be
            # misleading.
            self.assertEqual(len(self.pg1.get_capture(k + b)), k + b)
            self.assertEqual(len(self.pg2.get_capture(b)), b)
            self.pg0.assert_nothing_captured()

            reply = self.vapi.cli("show buffer traces verbose")

            # l2-flood is where the miscount used to hide: when l2-flood
            # dispatches it is not yet the owner of l2-output's next_frame
            # (l2-fwd wrote there first), so the buffers it appends after
            # the ownership swap were not credited to pnd->out.
            alloc, free, in_, out, buffered = self.get_node_stats(reply, "l2-flood")
            self.assertEqual(in_, b, "l2-flood in=%d expected=%d" % (in_, b))
            # Each broadcast packet produces 2 output buffers (original +
            # one clone) that all go to l2-output.
            self.assertEqual(out, 2 * b, "l2-flood out=%d expected=%d" % (out, 2 * b))
            self.assertEqual(alloc, b, "l2-flood alloc=%d expected=%d" % (alloc, b))
            self.assertEqual(free, 0, "l2-flood free=%d expected=0" % free)
            self.assertEqual(buffered, 0, "l2-flood buffered=%d expected=0" % buffered)

            # l2-output is pure transit (no alloc/free) and sees every
            # buffer exactly once in and once out.
            alloc, free, in_, out, buffered = self.get_node_stats(reply, "l2-output")
            self.assertEqual(alloc, 0, "l2-output alloc=%d expected=0" % alloc)
            self.assertEqual(free, 0, "l2-output free=%d expected=0" % free)
            self.assertEqual(
                in_, k + 2 * b, "l2-output in=%d expected=%d" % (in_, k + 2 * b)
            )
            self.assertEqual(
                out, k + 2 * b, "l2-output out=%d expected=%d" % (out, k + 2 * b)
            )
            self.assertEqual(buffered, 0, "l2-output buffered=%d expected=0" % buffered)

            self.vapi.cli("set buffer traces off")
        finally:
            self.vapi.l2fib_add_del(
                mac_pton(dst_unicast), bd_id, self.pg1.sw_if_index, is_add=0
            )
            for i in self.pg_interfaces:
                self.vapi.sw_interface_set_l2_bridge(
                    rx_sw_if_index=i.sw_if_index, bd_id=bd_id, enable=0
                )
            self.vapi.bridge_domain_add_del_v2(bd_id=bd_id, is_add=0)
            for i in self.pg_interfaces:
                i.config_ip4()
                i.resolve_arp()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
