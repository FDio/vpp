#!/usr/bin/env python
""" BFD tests """

from __future__ import division
import unittest
import hashlib
import binascii
import time
from struct import pack, unpack
from random import randint, shuffle, getrandbits
from socket import AF_INET, AF_INET6, inet_ntop
from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import UDP, IP
from scapy.layers.inet6 import IPv6
from bfd import VppBFDAuthKey, BFD, BFDAuthType, VppBFDUDPSession, \
    BFDDiagCode, BFDState, BFD_vpp_echo
from framework import VppTestCase, VppTestRunner, running_extended_tests
from vpp_pg_interface import CaptureTimeoutError, is_ipv6_misc
from vpp_lo_interface import VppLoInterface
from util import ppp
from vpp_papi_provider import UnexpectedApiReturnValueError
from vpp_ip_route import VppIpRoute, VppRoutePath, DpoProto

USEC_IN_SEC = 1000000


class AuthKeyFactory(object):
    """Factory class for creating auth keys with unique conf key ID"""

    def __init__(self):
        self._conf_key_ids = {}

    def create_random_key(self, test, auth_type=BFDAuthType.keyed_sha1):
        """ create a random key with unique conf key id """
        conf_key_id = randint(0, 0xFFFFFFFF)
        while conf_key_id in self._conf_key_ids:
            conf_key_id = randint(0, 0xFFFFFFFF)
        self._conf_key_ids[conf_key_id] = 1
        key = str(bytearray([randint(0, 255) for _ in range(randint(1, 20))]))
        return VppBFDAuthKey(test=test, auth_type=auth_type,
                             conf_key_id=conf_key_id, key=key)

@unittest.skipUnless(running_extended_tests(), "part of extended tests")
class BFDTestSession(object):
    """ BFD session as seen from test framework side """

    def __init__(self, test, interface, af, detect_mult=3, sha1_key=None,
                 bfd_key_id=None, our_seq_number=None):
        self.test = test
        self.af = af
        self.sha1_key = sha1_key
        self.bfd_key_id = bfd_key_id
        self.interface = interface
        self.udp_sport = randint(49152, 65535)
        if our_seq_number is None:
            self.our_seq_number = randint(0, 40000000)
        else:
            self.our_seq_number = our_seq_number
        self.vpp_seq_number = None
        self.my_discriminator = 0
        self.desired_min_tx = 300000
        self.required_min_rx = 300000
        self.required_min_echo_rx = None
        self.detect_mult = detect_mult
        self.diag = BFDDiagCode.no_diagnostic
        self.your_discriminator = None
        self.state = BFDState.down
        self.auth_type = BFDAuthType.no_auth

    def inc_seq_num(self):
        """ increment sequence number, wrapping if needed """
        if self.our_seq_number == 0xFFFFFFFF:
            self.our_seq_number = 0
        else:
            self.our_seq_number += 1

    def update(self, my_discriminator=None, your_discriminator=None,
               desired_min_tx=None, required_min_rx=None,
               required_min_echo_rx=None, detect_mult=None,
               diag=None, state=None, auth_type=None):
        """ update BFD parameters associated with session """
        if my_discriminator is not None:
            self.my_discriminator = my_discriminator
        if your_discriminator is not None:
            self.your_discriminator = your_discriminator
        if required_min_rx is not None:
            self.required_min_rx = required_min_rx
        if required_min_echo_rx is not None:
            self.required_min_echo_rx = required_min_echo_rx
        if desired_min_tx is not None:
            self.desired_min_tx = desired_min_tx
        if detect_mult is not None:
            self.detect_mult = detect_mult
        if diag is not None:
            self.diag = diag
        if state is not None:
            self.state = state
        if auth_type is not None:
            self.auth_type = auth_type

    def fill_packet_fields(self, packet):
        """ set packet fields with known values in packet """
        bfd = packet[BFD]
        if self.my_discriminator:
            self.test.logger.debug("BFD: setting packet.my_discriminator=%s",
                                   self.my_discriminator)
            bfd.my_discriminator = self.my_discriminator
        if self.your_discriminator:
            self.test.logger.debug("BFD: setting packet.your_discriminator=%s",
                                   self.your_discriminator)
            bfd.your_discriminator = self.your_discriminator
        if self.required_min_rx:
            self.test.logger.debug(
                "BFD: setting packet.required_min_rx_interval=%s",
                self.required_min_rx)
            bfd.required_min_rx_interval = self.required_min_rx
        if self.required_min_echo_rx:
            self.test.logger.debug(
                "BFD: setting packet.required_min_echo_rx=%s",
                self.required_min_echo_rx)
            bfd.required_min_echo_rx_interval = self.required_min_echo_rx
        if self.desired_min_tx:
            self.test.logger.debug(
                "BFD: setting packet.desired_min_tx_interval=%s",
                self.desired_min_tx)
            bfd.desired_min_tx_interval = self.desired_min_tx
        if self.detect_mult:
            self.test.logger.debug(
                "BFD: setting packet.detect_mult=%s", self.detect_mult)
            bfd.detect_mult = self.detect_mult
        if self.diag:
            self.test.logger.debug("BFD: setting packet.diag=%s", self.diag)
            bfd.diag = self.diag
        if self.state:
            self.test.logger.debug("BFD: setting packet.state=%s", self.state)
            bfd.state = self.state
        if self.auth_type:
            # this is used by a negative test-case
            self.test.logger.debug("BFD: setting packet.auth_type=%s",
                                   self.auth_type)
            bfd.auth_type = self.auth_type

    def create_packet(self):
        """ create a BFD packet, reflecting the current state of session """
        if self.sha1_key:
            bfd = BFD(flags="A")
            bfd.auth_type = self.sha1_key.auth_type
            bfd.auth_len = BFD.sha1_auth_len
            bfd.auth_key_id = self.bfd_key_id
            bfd.auth_seq_num = self.our_seq_number
            bfd.length = BFD.sha1_auth_len + BFD.bfd_pkt_len
        else:
            bfd = BFD()
        if self.af == AF_INET6:
            packet = (Ether(src=self.interface.remote_mac,
                            dst=self.interface.local_mac) /
                      IPv6(src=self.interface.remote_ip6,
                           dst=self.interface.local_ip6,
                           hlim=255) /
                      UDP(sport=self.udp_sport, dport=BFD.udp_dport) /
                      bfd)
        else:
            packet = (Ether(src=self.interface.remote_mac,
                            dst=self.interface.local_mac) /
                      IP(src=self.interface.remote_ip4,
                         dst=self.interface.local_ip4,
                         ttl=255) /
                      UDP(sport=self.udp_sport, dport=BFD.udp_dport) /
                      bfd)
        self.test.logger.debug("BFD: Creating packet")
        self.fill_packet_fields(packet)
        if self.sha1_key:
            hash_material = str(packet[BFD])[:32] + self.sha1_key.key + \
                            "\0" * (20 - len(self.sha1_key.key))
            self.test.logger.debug("BFD: Calculated SHA1 hash: %s" %
                                   hashlib.sha1(hash_material).hexdigest())
            packet[BFD].auth_key_hash = hashlib.sha1(hash_material).digest()
        return packet

    def send_packet(self, packet=None, interface=None):
        """ send packet on interface, creating the packet if needed """
        if packet is None:
            packet = self.create_packet()
        if interface is None:
            interface = self.test.pg0
        self.test.logger.debug(ppp("Sending packet:", packet))
        interface.add_stream(packet)
        self.test.pg_start()

    def verify_sha1_auth(self, packet):
        """ Verify correctness of authentication in BFD layer. """
        bfd = packet[BFD]
        self.test.assert_equal(bfd.auth_len, 28, "Auth section length")
        self.test.assert_equal(bfd.auth_type, self.sha1_key.auth_type,
                               BFDAuthType)
        self.test.assert_equal(bfd.auth_key_id, self.bfd_key_id, "Key ID")
        self.test.assert_equal(bfd.auth_reserved, 0, "Reserved")
        if self.vpp_seq_number is None:
            self.vpp_seq_number = bfd.auth_seq_num
            self.test.logger.debug("Received initial sequence number: %s" %
                                   self.vpp_seq_number)
        else:
            recvd_seq_num = bfd.auth_seq_num
            self.test.logger.debug("Received followup sequence number: %s" %
                                   recvd_seq_num)
            if self.vpp_seq_number < 0xffffffff:
                if self.sha1_key.auth_type == \
                        BFDAuthType.meticulous_keyed_sha1:
                    self.test.assert_equal(recvd_seq_num,
                                           self.vpp_seq_number + 1,
                                           "BFD sequence number")
                else:
                    self.test.assert_in_range(recvd_seq_num,
                                              self.vpp_seq_number,
                                              self.vpp_seq_number + 1,
                                              "BFD sequence number")
            else:
                if self.sha1_key.auth_type == \
                        BFDAuthType.meticulous_keyed_sha1:
                    self.test.assert_equal(recvd_seq_num, 0,
                                           "BFD sequence number")
                else:
                    self.test.assertIn(recvd_seq_num, (self.vpp_seq_number, 0),
                                       "BFD sequence number not one of "
                                       "(%s, 0)" % self.vpp_seq_number)
            self.vpp_seq_number = recvd_seq_num
        # last 20 bytes represent the hash - so replace them with the key,
        # pad the result with zeros and hash the result
        hash_material = bfd.original[:-20] + self.sha1_key.key + \
                        "\0" * (20 - len(self.sha1_key.key))
        expected_hash = hashlib.sha1(hash_material).hexdigest()
        self.test.assert_equal(binascii.hexlify(bfd.auth_key_hash),
                               expected_hash, "Auth key hash")

    def verify_bfd(self, packet):
        """ Verify correctness of BFD layer. """
        bfd = packet[BFD]
        self.test.assert_equal(bfd.version, 1, "BFD version")
        self.test.assert_equal(bfd.your_discriminator,
                               self.my_discriminator,
                               "BFD - your discriminator")
        if self.sha1_key:
            self.verify_sha1_auth(packet)


def bfd_session_up(test):
    """ Bring BFD session up """
    test.logger.info("BFD: Waiting for slow hello")
    p = wait_for_bfd_packet(test, 2)
    old_offset = None
    if hasattr(test, 'vpp_clock_offset'):
        old_offset = test.vpp_clock_offset
    test.vpp_clock_offset = time.time() - p.time
    print("BFD: Calculated vpp clock offset: %s",
                      test.vpp_clock_offset)
    if old_offset:
        test.assertAlmostEqual(
            old_offset, test.vpp_clock_offset, delta=0.5,
            msg="vpp clock offset not stable (new: %s, old: %s)" %
            (test.vpp_clock_offset, old_offset))
    print("BFD: Sending Init")
    test.test_session.update(my_discriminator=randint(0, 40000000),
                             your_discriminator=p[BFD].my_discriminator,
                             state=BFDState.init)
    if test.test_session.sha1_key and test.test_session.sha1_key.auth_type == \
            BFDAuthType.meticulous_keyed_sha1:
        test.test_session.inc_seq_num()
    test.test_session.send_packet()
    print("BFD: Waiting for event")
    e = test.vapi.wait_for_event(1, "bfd_udp_session_details")
    verify_event(test, e, expected_state=BFDState.up)
    print("BFD: Session is Up")
    test.test_session.update(state=BFDState.up)
    if test.test_session.sha1_key and test.test_session.sha1_key.auth_type == \
            BFDAuthType.meticulous_keyed_sha1:
        test.test_session.inc_seq_num()
    test.test_session.send_packet()
    test.assert_equal(test.vpp_session.state, BFDState.up, BFDState)


def bfd_session_down(test):
    """ Bring BFD session down """
    test.assert_equal(test.vpp_session.state, BFDState.up, BFDState)
    test.test_session.update(state=BFDState.down)
    if test.test_session.sha1_key and test.test_session.sha1_key.auth_type == \
            BFDAuthType.meticulous_keyed_sha1:
        test.test_session.inc_seq_num()
    test.test_session.send_packet()
    print("BFD: Waiting for event")
    e = test.vapi.wait_for_event(1, "bfd_udp_session_details")
    verify_event(test, e, expected_state=BFDState.down)
    print("BFD: Session is Down")
    test.assert_equal(test.vpp_session.state, BFDState.down, BFDState)


def verify_bfd_session_config(test, session, state=None):
    dump = session.get_bfd_udp_session_dump_entry()
    test.assertIsNotNone(dump)
    # since dump is not none, we have verified that sw_if_index and addresses
    # are valid (in get_bfd_udp_session_dump_entry)
    if state:
        test.assert_equal(dump.state, state, "session state")
    test.assert_equal(dump.required_min_rx, session.required_min_rx,
                      "required min rx interval")
    test.assert_equal(dump.desired_min_tx, session.desired_min_tx,
                      "desired min tx interval")
    test.assert_equal(dump.detect_mult, session.detect_mult,
                      "detect multiplier")
    if session.sha1_key is None:
        test.assert_equal(dump.is_authenticated, 0, "is_authenticated flag")
    else:
        test.assert_equal(dump.is_authenticated, 1, "is_authenticated flag")
        test.assert_equal(dump.bfd_key_id, session.bfd_key_id,
                          "bfd key id")
        test.assert_equal(dump.conf_key_id,
                          session.sha1_key.conf_key_id,
                          "config key id")


def verify_ip(test, packet):
    """ Verify correctness of IP layer. """
    if test.vpp_session.af == AF_INET6:
        ip = packet[IPv6]
        local_ip = test.pg0.local_ip6
        remote_ip = test.pg0.remote_ip6
        test.assert_equal(ip.hlim, 255, "IPv6 hop limit")
    else:
        ip = packet[IP]
        local_ip = test.pg0.local_ip4
        remote_ip = test.pg0.remote_ip4
        test.assert_equal(ip.ttl, 255, "IPv4 TTL")
    test.assert_equal(ip.src, local_ip, "IP source address")
    test.assert_equal(ip.dst, remote_ip, "IP destination address")


def verify_udp(test, packet):
    """ Verify correctness of UDP layer. """
    udp = packet[UDP]
    test.assert_equal(udp.dport, BFD.udp_dport, "UDP destination port")
    test.assert_in_range(udp.sport, BFD.udp_sport_min, BFD.udp_sport_max,
                         "UDP source port")


def verify_event(test, event, expected_state):
    """ Verify correctness of event values. """
    e = event
    print("BFD: Event: %s" % repr(e))
    test.assert_equal(e.sw_if_index,
                      test.vpp_session.interface.sw_if_index,
                      "BFD interface index")
    is_ipv6 = 0
    if test.vpp_session.af == AF_INET6:
        is_ipv6 = 1
    test.assert_equal(e.is_ipv6, is_ipv6, "is_ipv6")
    if test.vpp_session.af == AF_INET:
        test.assert_equal(e.local_addr[:4], test.vpp_session.local_addr_n,
                          "Local IPv4 address")
        test.assert_equal(e.peer_addr[:4], test.vpp_session.peer_addr_n,
                          "Peer IPv4 address")
    else:
        test.assert_equal(e.local_addr, test.vpp_session.local_addr_n,
                          "Local IPv6 address")
        test.assert_equal(e.peer_addr, test.vpp_session.peer_addr_n,
                          "Peer IPv6 address")
    test.assert_equal(e.state, expected_state, BFDState)


def wait_for_bfd_packet(test, timeout=1, pcap_time_min=None):
    """ wait for BFD packet and verify its correctness

    :param timeout: how long to wait
    :param pcap_time_min: ignore packets with pcap timestamp lower than this

    :returns: tuple (packet, time spent waiting for packet)
    """
    print("BFD: Waiting for BFD packet")
    deadline = time.time() + timeout
    counter = 0
    while True:
        counter += 1
        # sanity check
        test.assert_in_range(counter, 0, 100, "number of packets ignored")
        time_left = deadline - time.time()
        if time_left < 0:
            raise CaptureTimeoutError("Packet did not arrive within timeout")
        p = test.pg0.wait_for_packet(timeout=time_left)
        print(ppp("BFD: Got packet:", p))
        if pcap_time_min is not None and p.time < pcap_time_min:
            test.logger.debug(ppp("BFD: ignoring packet (pcap time %s < "
                                  "pcap time min %s):" %
                                  (p.time, pcap_time_min), p))
        else:
            break
    bfd = p[BFD]
    if bfd is None:
        raise Exception(ppp("Unexpected or invalid BFD packet:", p))
    if bfd.payload:
        raise Exception(ppp("Unexpected payload in BFD packet:", bfd))
    verify_ip(test, p)
    verify_udp(test, p)
    test.test_session.verify_bfd(p)
    return p


class BFD4TestCase(VppTestCase):
    """Bidirectional Forwarding Detection (BFD)"""

    pg0 = None
    vpp_clock_offset = None
    vpp_session = None
    test_session = None

    @classmethod
    def setUpClass(cls):
        super(BFD4TestCase, cls).setUpClass()
        try:
            cls.create_pg_interfaces([0])
            cls.create_loopback_interfaces([0])
            cls.loopback0 = cls.lo_interfaces[0]
            cls.loopback0.config_ip4()
            cls.loopback0.admin_up()
            cls.pg0.config_ip4()
            cls.pg0.configure_ipv4_neighbors()
            cls.pg0.admin_up()
            cls.pg0.resolve_arp()

        except Exception:
            super(BFD4TestCase, cls).tearDownClass()
            raise

    def setUp(self):
        super(BFD4TestCase, self).setUp()
        self.factory = AuthKeyFactory()
        self.vapi.want_bfd_events()
        self.pg0.enable_capture()
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
        if not self.vpp_dead:
            self.vapi.want_bfd_events(enable_disable=0)
        self.vapi.collect_events()  # clear the event queue
        super(BFD4TestCase, self).tearDown()

    def test_session_up(self):
        """ bring BFD session up """
        bfd_session_up(self)

    def test_session_up_by_ip(self):
        """ bring BFD session up - first frame looked up by address pair """
        print("BFD: Sending Slow control frame")
        self.test_session.update(my_discriminator=randint(0, 40000000))
        self.test_session.send_packet()
        self.pg0.enable_capture()
        p = self.pg0.wait_for_packet(1)
        self.assert_equal(p[BFD].your_discriminator,
                          self.test_session.my_discriminator,
                          "BFD - your discriminator")
        self.assert_equal(p[BFD].state, BFDState.init, BFDState)
        self.test_session.update(your_discriminator=p[BFD].my_discriminator,
                                 state=BFDState.up)
        print("BFD: Waiting for event")
        e = self.vapi.wait_for_event(1, "bfd_udp_session_details")
        verify_event(self, e, expected_state=BFDState.init)
        print("BFD: Sending Up")
        self.test_session.send_packet()
        print("BFD: Waiting for event")
        e = self.vapi.wait_for_event(1, "bfd_udp_session_details")
        verify_event(self, e, expected_state=BFDState.up)
        print("BFD: Session is Up")
        self.test_session.update(state=BFDState.up)
        self.test_session.send_packet()
        self.assert_equal(self.vpp_session.state, BFDState.up, BFDState)

    def test_session_down(self):
        """ bring BFD session down """
        bfd_session_up(self)
        bfd_session_down(self)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
