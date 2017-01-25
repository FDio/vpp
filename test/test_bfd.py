#!/usr/bin/env python

import unittest
import time
from random import randint
from bfd import *
from framework import *
from util import ppp

us_in_sec = 1000000


class BFDAPITestCase(VppTestCase):
    """Bidirectional Forwarding Detection (BFD) - API"""

    @classmethod
    def setUpClass(cls):
        super(BFDAPITestCase, cls).setUpClass()

        try:
            cls.create_pg_interfaces(range(2))
            for i in cls.pg_interfaces:
                i.config_ip4()
                i.resolve_arp()

        except Exception:
            super(BFDAPITestCase, cls).tearDownClass()
            raise

    def test_add_bfd(self):
        """ create a BFD session """
        session = VppBFDUDPSession(self, self.pg0, self.pg0.remote_ip4)
        session.add_vpp_config()
        self.logger.debug("Session state is %s" % str(session.state))
        session.remove_vpp_config()
        session = VppBFDUDPSession(self, self.pg0, self.pg0.remote_ip4)
        session.add_vpp_config()
        self.logger.debug("Session state is %s" % str(session.state))
        session.remove_vpp_config()

    def test_double_add(self):
        """ create the same BFD session twice (negative case) """
        session = VppBFDUDPSession(self, self.pg0, self.pg0.remote_ip4)
        session.add_vpp_config()

        with self.vapi.expect_negative_api_retval():
            session.add_vpp_config()

        session.remove_vpp_config()

    def test_add_two(self):
        """ create two BFD sessions """
        session1 = VppBFDUDPSession(self, self.pg0, self.pg0.remote_ip4)
        session1.add_vpp_config()
        session2 = VppBFDUDPSession(self, self.pg1, self.pg1.remote_ip4)
        session2.add_vpp_config()
        self.assertNotEqual(session1.bs_index, session2.bs_index,
                            "Different BFD sessions share bs_index (%s)" %
                            session1.bs_index)


class BFDTestSession(object):
    """ BFD session as seen from test framework side """

    def __init__(self, test, interface, af, detect_mult=3):
        self.test = test
        self.af = af
        self.interface = interface
        self.udp_sport = 50000
        self.bfd_values = {
            'my_discriminator': 0,
            'desired_min_tx_interval': 100000,
            'detect_mult': detect_mult,
            'diag': BFDDiagCode.no_diagnostic,
        }

    def update(self, **kwargs):
        self.bfd_values.update(kwargs)

    def create_packet(self):
        if self.af == AF_INET6:
            packet = (Ether(src=self.interface.remote_mac,
                            dst=self.interface.local_mac) /
                      IPv6(src=self.interface.remote_ip6,
                           dst=self.interface.local_ip6,
                           hlim=255) /
                      UDP(sport=self.udp_sport, dport=BFD.udp_dport) /
                      BFD())
        else:
            packet = (Ether(src=self.interface.remote_mac,
                            dst=self.interface.local_mac) /
                      IP(src=self.interface.remote_ip4,
                         dst=self.interface.local_ip4,
                         ttl=255) /
                      UDP(sport=self.udp_sport, dport=BFD.udp_dport) /
                      BFD())
        self.test.logger.debug("BFD: Creating packet")
        for name, value in self.bfd_values.iteritems():
            self.test.logger.debug("BFD: setting packet.%s=%s", name, value)
            packet[BFD].setfieldval(name, value)
        return packet

    def send_packet(self):
        p = self.create_packet()
        self.test.logger.debug(ppp("Sending packet:", p))
        self.test.pg0.add_stream([p])
        self.test.pg_start()

    def verify_packet(self, packet):
        """ Verify correctness of BFD layer. """
        bfd = packet[BFD]
        self.test.assert_equal(bfd.version, 1, "BFD version")
        self.test.assert_equal(bfd.your_discriminator,
                               self.bfd_values['my_discriminator'],
                               "BFD - your discriminator")


class BFDCommonCode:
    """Common code used by both IPv4 and IPv6 Test Cases"""

    def tearDown(self):
        self.vapi.collect_events()  # clear the event queue
        if not self.vpp_dead:
            self.vapi.want_bfd_events(enable_disable=0)
            self.vpp_session.remove_vpp_config()

    def bfd_session_up(self):
        self.pg_enable_capture([self.pg0])
        self.logger.info("BFD: Waiting for slow hello")
        p, timeout = self.wait_for_bfd_packet(2)
        self.logger.info("BFD: Sending Init")
        self.test_session.update(my_discriminator=randint(0, 40000000),
                                 your_discriminator=p[BFD].my_discriminator,
                                 state=BFDState.init,
                                 required_min_rx_interval=100000)
        self.test_session.send_packet()
        self.logger.info("BFD: Waiting for event")
        e = self.vapi.wait_for_event(1, "bfd_udp_session_details")
        self.verify_event(e, expected_state=BFDState.up)
        self.logger.info("BFD: Session is Up")
        self.test_session.update(state=BFDState.up)

    def verify_ip(self, packet):
        """ Verify correctness of IP layer. """
        if self.vpp_session.af == AF_INET6:
            ip = packet[IPv6]
            local_ip = self.pg0.local_ip6
            remote_ip = self.pg0.remote_ip6
            self.assert_equal(ip.hlim, 255, "IPv6 hop limit")
        else:
            ip = packet[IP]
            local_ip = self.pg0.local_ip4
            remote_ip = self.pg0.remote_ip4
            self.assert_equal(ip.ttl, 255, "IPv4 TTL")
        self.assert_equal(ip.src, local_ip, "IP source address")
        self.assert_equal(ip.dst, remote_ip, "IP destination address")

    def verify_udp(self, packet):
        """ Verify correctness of UDP layer. """
        udp = packet[UDP]
        self.assert_equal(udp.dport, BFD.udp_dport, "UDP destination port")
        self.assert_in_range(udp.sport, BFD.udp_sport_min, BFD.udp_sport_max,
                             "UDP source port")

    def verify_event(self, event, expected_state):
        """ Verify correctness of event values. """
        e = event
        self.logger.debug("BFD: Event: %s" % repr(e))
        self.assert_equal(e.bs_index, self.vpp_session.bs_index,
                          "BFD session index")
        self.assert_equal(
            e.sw_if_index,
            self.vpp_session.interface.sw_if_index,
            "BFD interface index")
        is_ipv6 = 0
        if self.vpp_session.af == AF_INET6:
            is_ipv6 = 1
        self.assert_equal(e.is_ipv6, is_ipv6, "is_ipv6")
        if self.vpp_session.af == AF_INET:
            self.assert_equal(e.local_addr[:4], self.vpp_session.local_addr_n,
                              "Local IPv4 address")
            self.assert_equal(e.peer_addr[:4], self.vpp_session.peer_addr_n,
                              "Peer IPv4 address")
        else:
            self.assert_equal(e.local_addr, self.vpp_session.local_addr_n,
                              "Local IPv6 address")
            self.assert_equal(e.peer_addr, self.vpp_session.peer_addr_n,
                              "Peer IPv6 address")
        self.assert_equal(e.state, expected_state, BFDState)

    def wait_for_bfd_packet(self, timeout=1):
        """ wait for BFD packet

        :param timeout: how long to wait max

        :returns: tuple (packet, time spent waiting for packet)
        """
        self.logger.info("BFD: Waiting for BFD packet")
        before = time.time()
        p = self.pg0.wait_for_packet(timeout=timeout)
        after = time.time()
        self.logger.debug(ppp("Got packet:", p))
        bfd = p[BFD]
        if bfd is None:
            raise Exception(ppp("Unexpected or invalid BFD packet:", p))
        if bfd.payload:
            raise Exception(ppp("Unexpected payload in BFD packet:", bfd))
        self.verify_ip(p)
        self.verify_udp(p)
        self.test_session.verify_packet(p)
        return p, after - before

    def test_session_up(self):
        """ bring BFD session up """
        self.bfd_session_up()

    def test_hold_up(self):
        """ hold BFD session up """
        self.bfd_session_up()
        for i in range(5):
            self.wait_for_bfd_packet()
            self.test_session.send_packet()


class BFD4TestCase(VppTestCase, BFDCommonCode):
    """Bidirectional Forwarding Detection (BFD)"""

    @classmethod
    def setUpClass(cls):
        super(BFD4TestCase, cls).setUpClass()
        try:
            cls.create_pg_interfaces([0])
            cls.pg0.config_ip4()
            cls.pg0.generate_remote_hosts()
            cls.pg0.configure_ipv4_neighbors()
            cls.pg0.admin_up()
            cls.pg0.resolve_arp()

        except Exception:
            super(BFD4TestCase, cls).tearDownClass()
            raise

    def setUp(self):
        super(BFD4TestCase, self).setUp()
        self.vapi.want_bfd_events()
        try:
            self.vpp_session = VppBFDUDPSession(self, self.pg0,
                                                self.pg0.remote_ip4)
            self.vpp_session.add_vpp_config()
            self.vpp_session.admin_up()
            self.test_session = BFDTestSession(self, self.pg0, AF_INET)
        except:
            self.vapi.want_bfd_events(enable_disable=0)
            raise

    def tearDown(self):
        BFDCommonCode.tearDown(self)
        super(BFD4TestCase, self).tearDown()

    def test_slow_timer(self):
        """ verify slow periodic control frames while session down """
        self.pg_enable_capture([self.pg0])
        expected_packets = 3
        self.logger.info("BFD: Waiting for %d BFD packets" % expected_packets)
        self.wait_for_bfd_packet(2)
        for i in range(expected_packets):
            before = time.time()
            self.wait_for_bfd_packet(2)
            after = time.time()
            # spec says the range should be <0.75, 1>, allow extra 0.05 margin
            # to work around timing issues
            self.assert_in_range(
                after - before, 0.70, 1.05, "time between slow packets")
            before = after

    def test_zero_remote_min_rx(self):
        """ no packets when zero BFD RemoteMinRxInterval """
        self.pg_enable_capture([self.pg0])
        p, timeout = self.wait_for_bfd_packet(2)
        self.test_session.update(my_discriminator=randint(0, 40000000),
                                 your_discriminator=p[BFD].my_discriminator,
                                 state=BFDState.init,
                                 required_min_rx_interval=0)
        self.test_session.send_packet()
        e = self.vapi.wait_for_event(1, "bfd_udp_session_details")
        self.verify_event(e, expected_state=BFDState.up)

        try:
            p = self.pg0.wait_for_packet(timeout=1)
        except:
            return
        raise Exception(ppp("Received unexpected BFD packet:", p))

    def test_conn_down(self):
        """ verify session goes down after inactivity """
        self.bfd_session_up()
        self.wait_for_bfd_packet()
        self.assert_equal(len(self.vapi.collect_events()), 0,
                          "number of bfd events")
        self.wait_for_bfd_packet()
        self.assert_equal(len(self.vapi.collect_events()), 0,
                          "number of bfd events")
        e = self.vapi.wait_for_event(1, "bfd_udp_session_details")
        self.verify_event(e, expected_state=BFDState.down)

    def test_large_required_min_rx(self):
        """ large remote RequiredMinRxInterval """
        self.bfd_session_up()
        interval = 3000000
        self.test_session.update(required_min_rx_interval=interval)
        self.test_session.send_packet()
        now = time.time()
        count = 0
        while time.time() < now + interval / us_in_sec:
            try:
                p = self.wait_for_bfd_packet()
                if count > 1:
                    self.logger.error(ppp("Received unexpected packet:", p))
                count += 1
            except:
                pass
        self.assert_in_range(count, 0, 1, "number of packets received")

    def test_immediate_remote_min_rx_reduce(self):
        """ immediately honor remote min rx reduction """
        self.vpp_session.remove_vpp_config()
        self.vpp_session = VppBFDUDPSession(
            self, self.pg0, self.pg0.remote_ip4, desired_min_tx=10000)
        self.vpp_session.add_vpp_config()
        self.test_session.update(desired_min_tx_interval=1000000,
                                 required_min_rx_interval=1000000)
        self.bfd_session_up()
        self.wait_for_bfd_packet()
        interval = 100000
        self.test_session.update(required_min_rx_interval=interval)
        self.test_session.send_packet()
        p, ttp = self.wait_for_bfd_packet()
        # allow extra 10% to work around timing issues, first packet is special
        self.assert_in_range(ttp, 0, 1.10 * interval / us_in_sec,
                             "time between BFD packets")
        p, ttp = self.wait_for_bfd_packet()
        self.assert_in_range(ttp, .9 * .75 * interval / us_in_sec,
                             1.10 * interval / us_in_sec,
                             "time between BFD packets")
        p, ttp = self.wait_for_bfd_packet()
        self.assert_in_range(ttp, .9 * .75 * interval / us_in_sec,
                             1.10 * interval / us_in_sec,
                             "time between BFD packets")


class BFD6TestCase(VppTestCase, BFDCommonCode):
    """Bidirectional Forwarding Detection (BFD) (IPv6) """

    @classmethod
    def setUpClass(cls):
        super(BFD6TestCase, cls).setUpClass()
        try:
            cls.create_pg_interfaces([0])
            cls.pg0.config_ip6()
            cls.pg0.configure_ipv6_neighbors()
            cls.pg0.admin_up()
            cls.pg0.resolve_ndp()

        except Exception:
            super(BFD6TestCase, cls).tearDownClass()
            raise

    def setUp(self):
        super(BFD6TestCase, self).setUp()
        self.vapi.want_bfd_events()
        try:
            self.vpp_session = VppBFDUDPSession(self, self.pg0,
                                                self.pg0.remote_ip6,
                                                af=AF_INET6)
            self.vpp_session.add_vpp_config()
            self.vpp_session.admin_up()
            self.test_session = BFDTestSession(self, self.pg0, AF_INET6)
            self.logger.debug(self.vapi.cli("show adj nbr"))
        except:
            self.vapi.want_bfd_events(enable_disable=0)
            raise

    def tearDown(self):
        BFDCommonCode.tearDown(self)
        super(BFD6TestCase, self).tearDown()

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
