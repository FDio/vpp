#!/usr/bin/env python

import unittest
import time
from random import randint
from bfd import *
from framework import *
from util import ppp


class BFDCLITestCase(VppTestCase):
    """Bidirectional Forwarding Detection (BFD) - CLI"""

    @classmethod
    def setUpClass(cls):
        super(BFDCLITestCase, cls).setUpClass()

        try:
            cls.create_pg_interfaces([0])
            cls.pg0.config_ip4()
            cls.pg0.resolve_arp()

        except Exception:
            super(BFDCLITestCase, cls).tearDownClass()
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
        try:
            session.add_vpp_config()
        except:
            session.remove_vpp_config()
            return
        session.remove_vpp_config()
        raise Exception("Expected failure while adding duplicate "
                        "configuration")


def create_packet(interface, ttl=255, src_port=50000, **kwargs):
    p = (Ether(src=interface.remote_mac, dst=interface.local_mac) /
         IP(src=interface.remote_ip4, dst=interface.local_ip4, ttl=ttl) /
         UDP(sport=src_port, dport=BFD.udp_dport) /
         BFD(*kwargs))
    return p


def verify_ip(test, packet, local_ip, remote_ip):
    """ Verify correctness of IP layer. """
    ip = packet[IP]
    test.assert_equal(ip.src, local_ip, "IP source address")
    test.assert_equal(ip.dst, remote_ip, "IP destination address")
    test.assert_equal(ip.ttl, 255, "IP TTL")


def verify_udp(test, packet):
    """ Verify correctness of UDP layer. """
    udp = packet[UDP]
    test.assert_equal(udp.dport, BFD.udp_dport, "UDP destination port")
    test.assert_in_range(udp.sport, BFD.udp_sport_min, BFD.udp_sport_max,
                         "UDP source port")


class BFDTestSession(object):

    def __init__(self, test, interface, detect_mult=3):
        self.test = test
        self.interface = interface
        self.bfd_values = {
            'my_discriminator': 0,
            'desired_min_tx_interval': 500000,
            'detect_mult': detect_mult,
            'diag': BFDDiagCode.no_diagnostic,
        }

    def update(self, **kwargs):
        self.bfd_values.update(kwargs)

    def create_packet(self):
        packet = create_packet(self.interface)
        for name, value in self.bfd_values.iteritems():
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


class BFDTestCase(VppTestCase):
    """Bidirectional Forwarding Detection (BFD)"""

    @classmethod
    def setUpClass(cls):
        super(BFDTestCase, cls).setUpClass()
        try:
            cls.create_pg_interfaces([0, 1])
            cls.pg0.config_ip4()
            cls.pg0.generate_remote_hosts()
            cls.pg0.configure_ipv4_neighbors()
            cls.pg0.admin_up()
            cls.pg0.resolve_arp()

        except Exception:
            super(BFDTestCase, cls).tearDownClass()
            raise

    def setUp(self):
        self.vapi.want_bfd_events()
        self.vpp_session = VppBFDUDPSession(self, self.pg0, self.pg0.remote_ip4)
        self.vpp_session.add_vpp_config()
        self.vpp_session.admin_up()
        self.test_session = BFDTestSession(self, self.pg0)

    def tearDown(self):
        self.vapi.want_bfd_events(enable_disable=0)
        if not self.vpp_dead:
            self.vpp_session.remove_vpp_config()
        super(BFDTestCase, self).tearDown()

    def verify_event(self, event, expected_state):
        """ Verify correctness of event values. """
        e = event
        self.logger.debug("Event: %s" % repr(e))
        self.assert_equal(e.bs_index, self.vpp_session.bs_index,
                          "BFD session index")
        self.assert_equal(e.sw_if_index, self.vpp_session.interface.sw_if_index,
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
        p = self.pg0.wait_for_packet(timeout=timeout)
        bfd = p[BFD]
        if bfd is None:
            raise Exception(ppp("Unexpected or invalid BFD packet:", p))
        if bfd.payload:
            raise Exception(ppp("Unexpected payload in BFD packet:", bfd))
        verify_ip(self, p, self.pg0.local_ip4, self.pg0.remote_ip4)
        verify_udp(self, p)
        self.test_session.verify_packet(p)
        return p

    def test_slow_timer(self):
        """ Slow timer """

        self.pg_enable_capture([self.pg0])
        expected_packets = 10
        self.logger.info("Waiting for %d BFD packets" % expected_packets)
        self.wait_for_bfd_packet()
        for i in range(expected_packets):
            before = time.time()
            self.wait_for_bfd_packet()
            after = time.time()
            self.assert_in_range(
                after - before, 0.75, 1, "time between slow packets")
            before = after

    def test_zero_remote_min_rx(self):
        """ Zero RemoteMinRxInterval """
        self.pg_enable_capture([self.pg0])
        p = self.wait_for_bfd_packet()
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

    def bfd_conn_up(self):
        self.pg_enable_capture([self.pg0])
        self.logger.info("Waiting for slow hello")
        p = self.wait_for_bfd_packet()
        self.logger.info("Sending Init")
        self.test_session.update(my_discriminator=randint(0, 40000000),
                                 your_discriminator=p[BFD].my_discriminator,
                                 state=BFDState.init,
                                 required_min_rx_interval=500000)
        self.test_session.send_packet()
        self.logger.info("Waiting for event")
        e = self.vapi.wait_for_event(1, "bfd_udp_session_details")
        self.verify_event(e, expected_state=BFDState.up)
        self.logger.info("Session is Up")
        self.test_session.update(state=BFDState.up)

    def test_conn_up(self):
        """ Basic connection up """
        self.bfd_conn_up()

    def test_hold_up(self):
        """ Hold BFD up """
        self.bfd_conn_up()
        for i in range(5):
            self.wait_for_bfd_packet()
            self.test_session.send_packet()

    def test_conn_down(self):
        """ Session down after inactivity """
        self.bfd_conn_up()
        self.wait_for_bfd_packet()
        self.assert_equal(
            0, len(self.vapi.collect_events()),
            "number of bfd events")
        self.wait_for_bfd_packet()
        self.assert_equal(
            0, len(self.vapi.collect_events()),
            "number of bfd events")
        e = self.vapi.wait_for_event(1, "bfd_udp_session_details")
        self.verify_event(e, expected_state=BFDState.down)

    @unittest.skip("this test is not working yet")
    def test_large_required_min_rx(self):
        self.bfd_conn_up()
        interval = 5000000
        self.test_session.update(required_min_rx_interval=interval)
        self.test_session.send_packet()
        now = time.time()
        count = 1
        while time.time() < now + interval / 1000000:
            try:
                p = self.wait_for_bfd_packet()
                if count > 1:
                    self.logger.error(ppp("Received unexpected packet:", p))
                count += 1
            except:
                pass
        self.assert_equal(count, 1, "number of packets received")


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
