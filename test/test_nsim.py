from framework import VppTestCase
from asfframework import VppTestRunner
from config import config
import unittest
import re

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from random import randint
from util import ppp


def create_stream(self, src_if, dst_if, count):
    packets = []
    for i in range(count):
        # create packet info stored in the test case instance
        info = self.create_packet_info(src_if, dst_if)
        # convert the info into packet payload
        payload = self.info_to_payload(info)
        # create the packet itself
        p = (
            Ether(dst=src_if.local_mac, src=src_if.remote_mac)
            / IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4)
            / UDP(sport=randint(49152, 65535), dport=5678)
            / Raw(payload)
        )
        # store a copy of the packet in the packet info
        info.data = p.copy()
        # append the packet to the list
        packets.append(p)

    # return the created packet list
    return packets


def verify_capture(self, src_if, dst_if, capture, reply):
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

    # find timestamps and get actual delay
    pattern = r"\d{2}:\d{2}:\d{2}:\d{6}"
    timestamps = re.findall(pattern, reply)
    actual_delay = int(timestamps[2][9:]) - int(timestamps[0][9:])
    self.assertTrue(
        actual_delay >= 100000, f"Delay is lower than expected: {actual_delay} < 100000"
    )


@unittest.skipIf("nsim" in config.excluded_plugins, "Exclude NSIM plugin tests")
class TestNsimCli(VppTestCase):
    """NSIM plugin tests [CLI]"""

    @classmethod
    def setUpClass(cls):
        super(TestNsimCli, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            for i in cls.pg_interfaces:
                i.config_ip4()
                i.resolve_arp()
                i.admin_up()
        except Exception:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.vapi.cli("nsim cross-connect enable-disable pg0 pg1 disable")
        cls.vapi.cli("nsim output-feature enable-disable pg0 disable")
        for i in cls.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()
        super(TestNsimCli, cls).tearDownClass()

    def test_nsim_delay(self):
        """Add 100ms delay"""
        packets = create_stream(self, self.pg0, self.pg1, 5)
        self.pg0.add_stream(packets)
        self.pg0.enable_capture()
        self.pg1.enable_capture()

        self.vapi.cli(
            "set nsim delay 100.0 ms bandwidth 1 gbit packet-size 128 drop-fraction 0.0"
        )
        self.vapi.cli("nsim cross-connect enable-disable pg0 pg1")
        self.vapi.cli("nsim output-feature enable-disable pg0")

        self.pg_start()
        capture = self.pg1.get_capture()
        self.pg0.assert_nothing_captured()
        reply = self.vapi.cli("show trace")
        verify_capture(self, self.pg0, self.pg1, capture, reply)
        self.assertIn("nsim", reply)
        reply = self.vapi.cli("show nsim")
        self.assertIn("delay: 100.0 ms", reply)

    def test_nsim_drop(self):
        """Drop all packets"""
        packets = create_stream(self, self.pg0, self.pg1, 5)
        self.pg0.add_stream(packets)
        self.vapi.cli("clear trace")
        # test fails if running test-debug and no delay is set ("invalid delay 0.00")
        self.vapi.cli(
            "set nsim delay 1 us bandwidth 1 gbit packet-size 128 drop-fraction 1.0 packets-per-drop 0"
        )

        self.pg_start()
        self.pg1.assert_nothing_captured()
        reply = self.vapi.cli("show nsim")
        self.assertIn("drop fraction: 1.0", reply)
        reply = self.vapi.cli("show trace")
        self.assertIn("sw_if_index -1", reply)


@unittest.skipIf("nsim" in config.excluded_plugins, "Exclude NSIM plugin tests")
class TestNsimApi(VppTestCase):
    """NSIM plugin tests [API]"""

    @classmethod
    def setUpClass(cls):
        super(TestNsimApi, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            for i in cls.pg_interfaces:
                i.config_ip4()
                i.resolve_arp()
                i.admin_up()
        except Exception:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.vapi.nsim_cross_connect_enable_disable(
            enable_disable=False, sw_if_index0=1, sw_if_index1=2
        )
        cls.vapi.nsim_output_feature_enable_disable(enable_disable=False, sw_if_index=1)
        for i in cls.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()
        super(TestNsimApi, cls).tearDownClass()

    def test_nsim_delay(self):
        """Add 100ms delay"""
        packets = create_stream(self, self.pg0, self.pg1, 5)
        self.pg0.add_stream(packets)
        self.pg0.enable_capture()
        self.pg1.enable_capture()

        # "show nsim" shows 99.9ms if delay is exactly 100000
        self.vapi.nsim_configure2(
            delay_in_usec=100001,
            average_packet_size=128,
            bandwidth_in_bits_per_second=100000000000,
            packets_per_drop=0,
            packets_per_reorder=0,
        )
        self.vapi.nsim_cross_connect_enable_disable(
            enable_disable=True, sw_if_index0=1, sw_if_index1=2
        )
        self.vapi.nsim_output_feature_enable_disable(enable_disable=True, sw_if_index=1)
        self.pg_start()
        capture = self.pg1.get_capture()
        reply = self.vapi.cli("show trace")
        verify_capture(self, self.pg0, self.pg1, capture, reply)
        self.assertIn("nsim", reply)
        reply = self.vapi.cli("show nsim")
        self.assertIn("delay: 100.0 ms", reply)


# has to be separated, otherwise we get "VPP API client: read failed"
# when configuring NSIM (nsim_configure2) and then VPP crashes on teardown
@unittest.skipIf("nsim" in config.excluded_plugins, "Exclude NSIM plugin tests")
class TestNsimApi2(VppTestCase):
    """NSIM plugin tests [API]"""

    @classmethod
    def setUpClass(cls):
        super(TestNsimApi2, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            for i in cls.pg_interfaces:
                i.config_ip4()
                i.resolve_arp()
                i.admin_up()
        except Exception:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.vapi.nsim_cross_connect_enable_disable(
            enable_disable=False, sw_if_index0=1, sw_if_index1=2
        )
        cls.vapi.nsim_output_feature_enable_disable(enable_disable=False, sw_if_index=1)
        for i in cls.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()
        super(TestNsimApi2, cls).tearDownClass()

    def test_nsim_drop(self):
        """Drop all packets"""
        packets = create_stream(self, self.pg0, self.pg1, 5)
        self.pg0.add_stream(packets)
        self.pg0.enable_capture()
        self.pg1.enable_capture()
        self.vapi.cli("clear trace")

        self.vapi.nsim_configure2(
            delay_in_usec=10,
            average_packet_size=128,
            bandwidth_in_bits_per_second=100000000,
            packets_per_drop=1,
            packets_per_reorder=0,
        )
        self.vapi.nsim_cross_connect_enable_disable(
            enable_disable=True, sw_if_index0=1, sw_if_index1=2
        )
        self.vapi.nsim_output_feature_enable_disable(enable_disable=True, sw_if_index=1)

        self.pg_start()
        self.pg1.assert_nothing_captured()
        reply = self.vapi.cli("show nsim")
        self.assertIn("drop fraction: 1.0", reply)
        reply = self.vapi.cli("show trace")
        self.assertIn("sw_if_index -1", reply)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
