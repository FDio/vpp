from framework import VppTestCase
from asfframework import VppTestRunner
from config import config
import unittest
import re
import time

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

    def timestamp_us(value):
        hours, minutes, seconds, usecs = (int(part) for part in value.split(":"))
        return (((hours * 60) + minutes) * 60 + seconds) * 1_000_000 + usecs

    actual_delay = timestamp_us(timestamps[2]) - timestamp_us(timestamps[0])
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
        cls.vapi.cli("nsim cross-connect enable-disable pg0 pg1 disable")
        cls.vapi.cli("nsim output-feature enable-disable pg0 disable")
        for i in cls.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()
        super(TestNsimCli, cls).tearDownClass()

    def tearDown(self):
        self.vapi.cli("nsim cross-connect enable-disable pg0 pg1 disable")
        self.vapi.cli("nsim output-feature enable-disable pg0 disable")
        super().tearDown()

    def enable_cross_connect(self):
        self.vapi.cli("nsim cross-connect enable-disable pg0 pg1")

    def send_and_capture(self, count, timeout=2):
        packets = create_stream(self, self.pg0, self.pg1, count)
        self.pg0.add_stream(packets)
        self.pg1.enable_capture()
        self.pg_start()
        return self.pg1.get_capture(count, timeout=timeout)

    def send_plain_and_capture(self, count, expected_count=None, timeout=2):
        packets = [
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)
            / UDP(sport=49152 + index, dport=5678)
            / Raw(bytes([index]))
            for index in range(count)
        ]
        self.pg0.add_stream(packets)
        self.pg1.enable_capture()
        self.pg_start()
        return self.pg1.get_capture(expected_count or count, timeout=timeout)

    def test_nsim_delay(self):
        """Add 100ms delay and serialize queued packets"""
        self.vapi.cli("clear trace")
        packets = create_stream(self, self.pg0, self.pg1, 5)
        self.pg0.add_stream(packets)
        self.pg0.enable_capture()
        self.pg1.enable_capture()

        self.vapi.cli(
            "set nsim delay 100.0 ms bandwidth 100 kbps buffer 100 ms "
            "packet-size 128 drop-fraction 0.0"
        )
        self.vapi.cli("nsim cross-connect enable-disable pg0 pg1")
        self.vapi.cli("nsim output-feature enable-disable pg0")

        self.pg_start()
        capture = self.pg1.get_capture(timeout=1)
        self.pg0.assert_nothing_captured()
        reply = self.vapi.cli("show trace")
        verify_capture(self, self.pg0, self.pg1, capture, reply)
        tx_times = [
            float(value) for value in re.findall(r"NSIM: tx time ([0-9.]*)", reply)
        ]
        self.assertGreaterEqual(max(tx_times) - min(tx_times), 0.03)
        serialization_span = float(capture[-1].time - capture[0].time)
        self.assertGreaterEqual(
            serialization_span,
            0.03,
            f"Queued packets were released too early: {serialization_span}s",
        )
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
        self.enable_cross_connect()

        self.pg_start()
        self.pg1.assert_nothing_captured()
        reply = self.vapi.cli("show nsim")
        self.assertIn("uniform: drop fraction 1", reply)
        reply = self.vapi.cli("show trace")
        self.assertIn("simulated network loss", reply)

    def test_one_shot_loss(self):
        """The existing one-shot loss model remains available per worker"""
        self.vapi.cli(
            "set nsim delay 1 ms bandwidth 8 mbps packet-size 1000 "
            "drop-once after 0 ms for 100 ms"
        )
        self.enable_cross_connect()

        packets = create_stream(self, self.pg0, self.pg1, 3)
        self.pg0.add_stream(packets)
        self.pg1.enable_capture()
        self.pg_start()
        self.pg1.assert_nothing_captured()

        reply = self.vapi.cli("show nsim verbose")
        self.assertIn("one-shot (statistical): after 0.0 ms for 100.0 ms", reply)
        self.assertIn("done 0, 3 packets dropped", reply)

    def test_rate_cycle_uses_service_time(self):
        """Queued packets straddling a rate transition use both rates"""
        self.vapi.cli(
            "set nsim delay 1 ms bandwidth 800 kbps buffer 100 ms "
            "packet-size 1000 rate-cycle bandwidth 400 kbps "
            "good 15 ms bad 100 ms seed 7"
        )
        self.enable_cross_connect()
        capture = self.send_and_capture(3)

        first_gap = float(capture[1].time - capture[0].time)
        second_gap = float(capture[2].time - capture[1].time)
        # Packet one takes 10 ms. Packet two starts 5 ms before the transition,
        # then serializes its remaining half at the 20 ms/packet bad rate.
        self.assertGreater(first_gap, 0.012)
        self.assertLess(first_gap, 0.019)
        self.assertGreater(second_gap, 0.017)
        self.assertLess(second_gap, 0.026)

        reply = self.vapi.cli("show nsim verbose")
        self.assertIn("cycle:", reply)
        self.assertRegex(
            reply, r"rate service tail: cycle:.*\(bad, [1-9]\d* tracked transitions"
        )
        self.assertRegex(
            reply,
            r"rate service starts: good 2 packets \(2000 nominal bytes\), "
            r"bad 1 packets \(1000 nominal bytes\), straddled 1",
        )

    def test_markov_idle_catchup(self):
        """A Markov model samples elapsed idle time instead of flipping once"""
        self.vapi.cli(
            "set nsim delay 1 ms bandwidth 8 mbps buffer 100 ms "
            "packet-size 1000 rate-stall bandwidth 4 mbps "
            "every 10 ms for 10 ms seed 5"
        )
        self.enable_cross_connect()
        self.send_plain_and_capture(1)
        time.sleep(0.05)
        self.send_plain_and_capture(1)

        reply = self.vapi.cli("show nsim verbose")
        # With this seed the analytically sampled state after the idle period is
        # good. A single unconditional transition would leave it bad.
        self.assertRegex(
            reply,
            r"rate service tail: markov .*\(good, 1 tracked transitions, 1 catchups\)",
        )

    def test_markov_packet_service_is_bounded(self):
        """Pathological Markov dwell times use bounded service integration"""
        self.vapi.cli(
            "set nsim delay 1 ms bandwidth 8 mbps buffer 20 ms "
            "packet-size 1000 rate-stall bandwidth 4 mbps "
            "every 1 us for 1 us seed 6"
        )
        self.enable_cross_connect()
        self.send_plain_and_capture(1)
        self.assertRegex(
            self.vapi.cli("show nsim verbose"),
            r"[1-9]\d* bounded service approximations",
        )

    def test_release_batching(self):
        """Release batching preserves FIFO order and aligns departures"""
        self.vapi.cli(
            "set nsim delay 1 ms bandwidth 8 mbps buffer 20 ms "
            "packet-size 1000 batch-interval 5.5 ms seed 11"
        )
        self.enable_cross_connect()
        capture = self.send_and_capture(7)

        indexes = [self.payload_to_info(packet[Raw]).index for packet in capture]
        self.assertEqual(indexes, sorted(indexes))
        self.assertLess(float(capture[5].time - capture[0].time), 0.002)
        boundary_gap = float(capture[6].time - capture[5].time)
        self.assertGreater(boundary_gap, 0.003)
        self.assertLess(boundary_gap, 0.009)

        reply = self.vapi.cli("show nsim verbose")
        self.assertIn("batch interval: 5.5 ms", reply)
        self.assertRegex(
            reply,
            r"batching: delayed 7 batches 2 extended 0 budget deferrals 0 "
            r"max gap 5.5 ms max batch 6",
        )

    def test_release_batch_packet_budget(self):
        """A batch packet budget is a finite packet-rate service limit"""
        self.vapi.cli(
            "set nsim delay 1 ms bandwidth 8 mbps buffer 20 ms "
            "packet-size 1000 batch-interval 5 ms batch-packets 2 seed 12"
        )
        self.enable_cross_connect()
        capture = self.send_and_capture(20)

        indexes = [self.payload_to_info(packet[Raw]).index for packet in capture]
        self.assertEqual(indexes, sorted(indexes))
        self.assertLess(float(capture[1].time - capture[0].time), 0.002)
        self.assertGreater(float(capture[2].time - capture[1].time), 0.003)
        self.assertLess(float(capture[3].time - capture[2].time), 0.002)
        self.assertGreater(float(capture[4].time - capture[3].time), 0.003)
        self.assertGreater(float(capture[-1].time - capture[0].time), 0.035)

        reply = self.vapi.cli("show nsim verbose")
        self.assertIn("batch packet budget: 2 (base capacity 400.0 packets/s)", reply)
        self.assertRegex(
            reply,
            r"batches 10 extended 0 budget deferrals 9 max gap 5.0 ms max batch 2",
        )

    def test_release_batch_gap_distribution(self):
        """Weighted release gaps extend a batch and reserve holding space"""
        self.vapi.cli(
            "set nsim delay 1 ms bandwidth 8 mbps buffer 20 ms "
            "packet-size 1000 batch-interval 5 ms "
            "batch-gap 15 ms probability 1.0 seed 13"
        )
        reply = self.vapi.cli("show nsim verbose")
        self.assertIn("batch gap distribution: 15.0 ms 1.00000 base 0.00000", reply)
        # Queue, propagation and batch holding all require physical storage.
        self.assertIn("worker wheel size: 37", reply)

        self.enable_cross_connect()
        capture = self.send_and_capture(20)
        indexes = [self.payload_to_info(packet[Raw]).index for packet in capture]
        self.assertEqual(indexes, sorted(indexes))
        release_gaps = [
            float(capture[index].time - capture[index - 1].time)
            for index in range(1, len(capture))
        ]
        self.assertGreater(max(release_gaps), 0.010)
        self.assertEqual(sum(gap > 0.005 for gap in release_gaps), 1)

        reply = self.vapi.cli("show nsim verbose")
        self.assertRegex(
            reply, r"batches 2 extended 2 budget deferrals 0 max gap 15.0 ms"
        )
        self.assertRegex(reply, r"batch gap samples: 15.0 ms 2 base 0 mean 15.0 ms")

    def test_fixed_rate_reorder(self):
        """Fixed-rate late reordering remains available without other models"""
        self.vapi.cli(
            "set nsim delay 1 ms bandwidth 8 mbps buffer 20 ms "
            "packet-size 1000 reorder-fraction 1.0 reorder-delay 5 ms seed 17"
        )
        self.enable_cross_connect()
        capture = self.send_plain_and_capture(5)
        self.assertEqual([packet[Raw].load[0] for packet in capture], list(range(5)))
        self.assertIn("reorder fraction: 1.00000", self.vapi.cli("show nsim verbose"))
        self.assertRegex(
            self.vapi.cli("show errors"), r"\s+5\s+nsim\s+Packets reordered"
        )

    def test_reorder_wheel_overflow_is_queue_drop(self):
        """A full reorder wheel is not reported as simulated loss"""
        self.vapi.cli("clear errors")
        self.vapi.cli(
            "set nsim delay 100 ms bandwidth 512 kbps packet-size 64 "
            "reorder-fraction 1.0 reorder-delay 100 ms seed 18"
        )
        self.enable_cross_connect()
        # Shared storage includes base and reorder delay: 200 packets plus the
        # ring sentinel. It must not double because there are two wheels.
        capture = self.send_plain_and_capture(250, expected_count=201)
        self.assertEqual(len(capture), 201)

        reply = self.vapi.cli("show nsim verbose")
        self.assertRegex(reply, r"counters: packets 250 drops 0 queue-full [1-9]\d*")
        errors = self.vapi.cli("show errors")
        self.assertRegex(
            errors, r"\s+[1-9]\d*\s+nsim\s+Packets dropped due to lack of spac"
        )
        self.assertNotRegex(
            errors, r"\s+[1-9]\d*\s+nsim\s+Network loss simulation drop packets"
        )
        trace = self.vapi.cli("show trace max 1000")
        self.assertIn("scheduler storage full", trace)
        self.assertNotIn("simulated network loss", trace)

    def test_batch_capacity_and_reconfiguration_guard(self):
        """Batch holding space is separate and live nsim cannot be replaced"""
        self.vapi.cli(
            "set nsim delay 1 ms bandwidth 8 mbps buffer 10 ms "
            "packet-size 1000 batch-interval 5 ms seed 19"
        )
        reply = self.vapi.cli("show nsim verbose")
        # Physical storage includes the queue, propagation pipe, batch hold and
        # ring sentinel. Downstream holding does not enlarge queue admission.
        self.assertIn("worker bottleneck queue size: 11", reply)
        self.assertIn("worker wheel size: 17", reply)

        self.enable_cross_connect()
        capture = self.send_plain_and_capture(20, expected_count=11)
        self.assertEqual(len(capture), 11)
        reply = self.vapi.cli("show nsim verbose")
        self.assertIn(
            "worker bottleneck queue size: 11 packets "
            "(11000 nominal bytes, 11.0 ms)",
            reply,
        )
        self.assertRegex(
            reply,
            r"peaks: queue 11/11 service backlog 1[01]\.\d+ ms storage 11/17",
        )
        response = self.vapi.cli_return_response(
            "set nsim delay 2 ms bandwidth 8 mbps packet-size 1000"
        )
        self.assertNotEqual(response.retval, 0)
        self.assertIn("disable nsim before reconfiguring it", response.reply)

    def test_cross_connect_state(self):
        """A second pair cannot invalidate the active cross-connect"""
        self.vapi.cli("set nsim delay 1 ms bandwidth 8 mbps packet-size 1000")
        self.enable_cross_connect()

        for command in (
            "nsim cross-connect enable-disable pg0 pg2",
            "nsim cross-connect enable-disable pg0 pg2 disable",
        ):
            response = self.vapi.cli_return_response(command)
            self.assertNotEqual(response.retval, 0)

        reply = self.vapi.cli("show nsim")
        self.assertIn("pg0 and pg1", reply)

    def test_unknown_input_rejected(self):
        """Unknown input cannot partially replace a configuration"""
        self.vapi.cli("set nsim delay 1 ms bandwidth 8 mbps packet-size 1000")
        self.assertIn("poll main thread: 0", self.vapi.cli("show nsim verbose"))
        response = self.vapi.cli_return_response(
            "set nsim delay 2 ms bandwidth 8 mbps packet-size 1000 "
            "poll-main-thread unsupported"
        )
        self.assertNotEqual(response.retval, 0)
        self.assertIn("unknown input", response.reply)
        reply = self.vapi.cli("show nsim verbose")
        self.assertIn("delay: 1.0 ms", reply)
        self.assertIn("poll main thread: 0", reply)

    def test_invalid_model_values_rejected(self):
        """Negative times and incomplete rate stalls are not defaulted"""
        commands = (
            "set nsim delay 1 ms bandwidth 8 mbps buffer -1 ms packet-size 1000",
            "set nsim delay 1 ms bandwidth 8 mbps buffer 10 ms packet-size 1000 "
            "rate-stall bandwidth 4 mbps every 0 ms for 1 ms",
            "set nsim delay -1 ms bandwidth 8 mbps packet-size 1000",
            "set nsim delay 1 ms bandwidth -8 mbps packet-size 1000",
            "set nsim delay 1 ms bandwidth 8 mbps packet-size 1000 "
            "packets-per-reorder -1",
            "set nsim delay 1 ms bandwidth 8 mbps packet-size 1000 "
            "batch-interval 5 ms reorder-fraction 0.1",
        )
        for command in commands:
            response = self.vapi.cli_return_response(command)
            self.assertNotEqual(response.retval, 0, command)

        response = self.vapi.cli_return_response(
            "set nsim delay 1 ms bandwidth 8 mbps packet-size 1"
        )
        self.assertNotEqual(response.retval, 0)
        self.assertIn("invalid packet size 1", response.reply)


@unittest.skipIf("nsim" in config.excluded_plugins, "Exclude NSIM plugin tests")
class TestNsimWorkers(VppTestCase):
    """NSIM per-worker model state"""

    vpp_worker_count = 2

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            for interface in cls.pg_interfaces:
                interface.admin_up()
        except Exception:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.vapi.cli("nsim cross-connect enable-disable pg0 pg1 disable")
        for interface in cls.pg_interfaces:
            interface.admin_down()
        super().tearDownClass()

    def test_worker_state_and_rng_streams(self):
        command = (
            "set nsim delay 1 ms bandwidth 8 mbps buffer 10 ms "
            "packet-size 1000 rate-cycle bandwidth 4 mbps "
            "good 10 ms bad 10 ms seed 12345"
        )
        self.vapi.cli(command)
        first = self.vapi.cli("show nsim verbose")
        workers = re.findall(
            r"worker (\d+): queue 0/(\d+).*seeds loss (\d+) reorder (\d+) "
            r"reorder-delay (\d+) rate (\d+) batch (\d+)",
            first,
        )
        self.assertEqual(len(workers), 2)
        self.assertEqual(workers[0][1], workers[1][1])
        for worker in workers:
            self.assertEqual(len(set(worker[2:])), 5)
        self.assertNotEqual(workers[0][2:], workers[1][2:])

        self.vapi.cli(command)
        second = self.vapi.cli("show nsim verbose")
        self.assertEqual(
            workers,
            re.findall(
                r"worker (\d+): queue 0/(\d+).*seeds loss (\d+) reorder (\d+) "
                r"reorder-delay (\d+) rate (\d+) batch (\d+)",
                second,
            ),
        )

        self.vapi.cli("nsim cross-connect enable-disable pg0 pg1")
        for worker, count in ((0, 1), (1, 3)):
            packets = [
                Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
                / IP(src="192.0.2.1", dst="192.0.2.2")
                / UDP(sport=49152 + index, dport=5678)
                / Raw(bytes([index]))
                for index in range(count)
            ]
            self.pg_send(self.pg0, packets, worker=worker)

        reply = self.vapi.cli("show nsim verbose")
        counters = {
            int(worker): int(packets)
            for worker, packets in re.findall(
                r"worker (\d+):.*\n  counters: packets (\d+)",
                reply,
            )
        }
        self.assertEqual(counters, {1: 1, 2: 3})
        self.assertEqual(reply.count("rate service tail:"), 2)


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
        capture = self.pg1.get_capture(timeout=1)
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
        self.assertIn("uniform: drop fraction 1", reply)
        reply = self.vapi.cli("show trace")
        self.assertIn("simulated network loss", reply)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
