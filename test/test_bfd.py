#!/usr/bin/env python
""" BFD tests """

from __future__ import division
import unittest
import hashlib
import binascii
import time
from random import randint, shuffle
from socket import AF_INET, AF_INET6
from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import UDP, IP
from scapy.layers.inet6 import IPv6
from bfd import VppBFDAuthKey, BFD, BFDAuthType, VppBFDUDPSession, \
    BFDDiagCode, BFDState
from framework import VppTestCase, VppTestRunner
from vpp_pg_interface import CaptureTimeoutError
from util import ppp

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


class BFDAPITestCase(VppTestCase):
    """Bidirectional Forwarding Detection (BFD) - API"""

    pg0 = None
    pg1 = None

    @classmethod
    def setUpClass(cls):
        super(BFDAPITestCase, cls).setUpClass()

        try:
            cls.create_pg_interfaces(range(2))
            for i in cls.pg_interfaces:
                i.config_ip4()
                i.config_ip6()
                i.resolve_arp()

        except Exception:
            super(BFDAPITestCase, cls).tearDownClass()
            raise

    def setUp(self):
        super(BFDAPITestCase, self).setUp()
        self.factory = AuthKeyFactory()

    def test_add_bfd(self):
        """ create a BFD session """
        session = VppBFDUDPSession(self, self.pg0, self.pg0.remote_ip4)
        session.add_vpp_config()
        self.logger.debug("Session state is %s", session.state)
        session.remove_vpp_config()
        session.add_vpp_config()
        self.logger.debug("Session state is %s", session.state)
        session.remove_vpp_config()

    def test_double_add(self):
        """ create the same BFD session twice (negative case) """
        session = VppBFDUDPSession(self, self.pg0, self.pg0.remote_ip4)
        session.add_vpp_config()

        with self.vapi.expect_negative_api_retval():
            session.add_vpp_config()

        session.remove_vpp_config()

    def test_add_bfd6(self):
        """ create IPv6 BFD session """
        session = VppBFDUDPSession(
            self, self.pg0, self.pg0.remote_ip6, af=AF_INET6)
        session.add_vpp_config()
        self.logger.debug("Session state is %s", session.state)
        session.remove_vpp_config()
        session.add_vpp_config()
        self.logger.debug("Session state is %s", session.state)
        session.remove_vpp_config()

    def test_mod_bfd(self):
        """ modify BFD session parameters """
        session = VppBFDUDPSession(self, self.pg0, self.pg0.remote_ip4,
                                   desired_min_tx=50000,
                                   required_min_rx=10000,
                                   detect_mult=1)
        session.add_vpp_config()
        s = session.get_bfd_udp_session_dump_entry()
        self.assert_equal(session.desired_min_tx,
                          s.desired_min_tx,
                          "desired min transmit interval")
        self.assert_equal(session.required_min_rx,
                          s.required_min_rx,
                          "required min receive interval")
        self.assert_equal(session.detect_mult, s.detect_mult, "detect mult")
        session.modify_parameters(desired_min_tx=session.desired_min_tx * 2,
                                  required_min_rx=session.required_min_rx * 2,
                                  detect_mult=session.detect_mult * 2)
        s = session.get_bfd_udp_session_dump_entry()
        self.assert_equal(session.desired_min_tx,
                          s.desired_min_tx,
                          "desired min transmit interval")
        self.assert_equal(session.required_min_rx,
                          s.required_min_rx,
                          "required min receive interval")
        self.assert_equal(session.detect_mult, s.detect_mult, "detect mult")

    def test_add_sha1_keys(self):
        """ add SHA1 keys """
        key_count = 10
        keys = [self.factory.create_random_key(
            self) for i in range(0, key_count)]
        for key in keys:
            self.assertFalse(key.query_vpp_config())
        for key in keys:
            key.add_vpp_config()
        for key in keys:
            self.assertTrue(key.query_vpp_config())
        # remove randomly
        indexes = range(key_count)
        shuffle(indexes)
        removed = []
        for i in indexes:
            key = keys[i]
            key.remove_vpp_config()
            removed.append(i)
            for j in range(key_count):
                key = keys[j]
                if j in removed:
                    self.assertFalse(key.query_vpp_config())
                else:
                    self.assertTrue(key.query_vpp_config())
        # should be removed now
        for key in keys:
            self.assertFalse(key.query_vpp_config())
        # add back and remove again
        for key in keys:
            key.add_vpp_config()
        for key in keys:
            self.assertTrue(key.query_vpp_config())
        for key in keys:
            key.remove_vpp_config()
        for key in keys:
            self.assertFalse(key.query_vpp_config())

    def test_add_bfd_sha1(self):
        """ create a BFD session (SHA1) """
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        session = VppBFDUDPSession(self, self.pg0, self.pg0.remote_ip4,
                                   sha1_key=key)
        session.add_vpp_config()
        self.logger.debug("Session state is %s", session.state)
        session.remove_vpp_config()
        session.add_vpp_config()
        self.logger.debug("Session state is %s", session.state)
        session.remove_vpp_config()

    def test_double_add_sha1(self):
        """ create the same BFD session twice (negative case) (SHA1) """
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        session = VppBFDUDPSession(self, self.pg0, self.pg0.remote_ip4,
                                   sha1_key=key)
        session.add_vpp_config()
        with self.assertRaises(Exception):
            session.add_vpp_config()

    def test_add_auth_nonexistent_key(self):
        """ create BFD session using non-existent SHA1 (negative case) """
        session = VppBFDUDPSession(
            self, self.pg0, self.pg0.remote_ip4,
            sha1_key=self.factory.create_random_key(self))
        with self.assertRaises(Exception):
            session.add_vpp_config()

    def test_shared_sha1_key(self):
        """ share single SHA1 key between multiple BFD sessions """
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        sessions = [
            VppBFDUDPSession(self, self.pg0, self.pg0.remote_ip4,
                             sha1_key=key),
            VppBFDUDPSession(self, self.pg0, self.pg0.remote_ip6,
                             sha1_key=key, af=AF_INET6),
            VppBFDUDPSession(self, self.pg1, self.pg1.remote_ip4,
                             sha1_key=key),
            VppBFDUDPSession(self, self.pg1, self.pg1.remote_ip6,
                             sha1_key=key, af=AF_INET6)]
        for s in sessions:
            s.add_vpp_config()
        removed = 0
        for s in sessions:
            e = key.get_bfd_auth_keys_dump_entry()
            self.assert_equal(e.use_count, len(sessions) - removed,
                              "Use count for shared key")
            s.remove_vpp_config()
            removed += 1
        e = key.get_bfd_auth_keys_dump_entry()
        self.assert_equal(e.use_count, len(sessions) - removed,
                          "Use count for shared key")

    def test_activate_auth(self):
        """ activate SHA1 authentication """
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        session = VppBFDUDPSession(self, self.pg0, self.pg0.remote_ip4)
        session.add_vpp_config()
        session.activate_auth(key)

    def test_deactivate_auth(self):
        """ deactivate SHA1 authentication """
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        session = VppBFDUDPSession(self, self.pg0, self.pg0.remote_ip4)
        session.add_vpp_config()
        session.activate_auth(key)
        session.deactivate_auth()

    def test_change_key(self):
        """ change SHA1 key """
        key1 = self.factory.create_random_key(self)
        key2 = self.factory.create_random_key(self)
        while key2.conf_key_id == key1.conf_key_id:
            key2 = self.factory.create_random_key(self)
        key1.add_vpp_config()
        key2.add_vpp_config()
        session = VppBFDUDPSession(self, self.pg0, self.pg0.remote_ip4,
                                   sha1_key=key1)
        session.add_vpp_config()
        session.activate_auth(key2)


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
        self.desired_min_tx = 100000
        self.required_min_rx = 100000
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
               desired_min_tx=None, required_min_rx=None, detect_mult=None,
               diag=None, state=None, auth_type=None):
        """ update BFD parameters associated with session """
        if my_discriminator:
            self.my_discriminator = my_discriminator
        if your_discriminator:
            self.your_discriminator = your_discriminator
        if required_min_rx:
            self.required_min_rx = required_min_rx
        if desired_min_tx:
            self.desired_min_tx = desired_min_tx
        if detect_mult:
            self.detect_mult = detect_mult
        if diag:
            self.diag = diag
        if state:
            self.state = state
        if auth_type:
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
    test.logger.debug("BFD: Calculated vpp clock offset: %s",
                      test.vpp_clock_offset)
    if old_offset:
        test.assertAlmostEqual(
            old_offset, test.vpp_clock_offset, delta=0.1,
            msg="vpp clock offset not stable (new: %s, old: %s)" %
            (test.vpp_clock_offset, old_offset))
    test.logger.info("BFD: Sending Init")
    test.test_session.update(my_discriminator=randint(0, 40000000),
                             your_discriminator=p[BFD].my_discriminator,
                             state=BFDState.init)
    test.test_session.send_packet()
    test.logger.info("BFD: Waiting for event")
    e = test.vapi.wait_for_event(1, "bfd_udp_session_details")
    verify_event(test, e, expected_state=BFDState.up)
    test.logger.info("BFD: Session is Up")
    test.test_session.update(state=BFDState.up)
    test.test_session.send_packet()
    test.assert_equal(test.vpp_session.state, BFDState.up, BFDState)


def bfd_session_down(test):
    """ Bring BFD session down """
    test.assert_equal(test.vpp_session.state, BFDState.up, BFDState)
    test.test_session.update(state=BFDState.down)
    test.test_session.send_packet()
    test.logger.info("BFD: Waiting for event")
    e = test.vapi.wait_for_event(1, "bfd_udp_session_details")
    verify_event(test, e, expected_state=BFDState.down)
    test.logger.info("BFD: Session is Down")
    test.assert_equal(test.vpp_session.state, BFDState.down, BFDState)


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
    test.logger.debug("BFD: Event: %s" % repr(e))
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
    test.logger.info("BFD: Waiting for BFD packet")
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
        test.logger.debug(ppp("BFD: Got packet:", p))
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

    def test_session_down(self):
        """ bring BFD session down """
        bfd_session_up(self)
        bfd_session_down(self)

    def test_hold_up(self):
        """ hold BFD session up """
        bfd_session_up(self)
        for dummy in range(self.test_session.detect_mult * 2):
            wait_for_bfd_packet(self)
            self.test_session.send_packet()
        self.assert_equal(len(self.vapi.collect_events()), 0,
                          "number of bfd events")

    def test_slow_timer(self):
        """ verify slow periodic control frames while session down """
        packet_count = 3
        self.logger.info("BFD: Waiting for %d BFD packets", packet_count)
        prev_packet = wait_for_bfd_packet(self, 2)
        for dummy in range(packet_count):
            next_packet = wait_for_bfd_packet(self, 2)
            time_diff = next_packet.time - prev_packet.time
            # spec says the range should be <0.75, 1>, allow extra 0.05 margin
            # to work around timing issues
            self.assert_in_range(
                time_diff, 0.70, 1.05, "time between slow packets")
            prev_packet = next_packet

    def test_zero_remote_min_rx(self):
        """ no packets when zero remote required min rx interval """
        bfd_session_up(self)
        self.test_session.update(required_min_rx=0)
        self.test_session.send_packet()
        cap = 2 * self.vpp_session.desired_min_tx *\
            self.test_session.detect_mult
        time_mark = time.time()
        count = 0
        # busy wait here, trying to collect a packet or event, vpp is not
        # allowed to send packets and the session will timeout first - so the
        # Up->Down event must arrive before any packets do
        while time.time() < time_mark + cap / USEC_IN_SEC:
            try:
                p = wait_for_bfd_packet(
                    self, timeout=0,
                    pcap_time_min=time_mark - self.vpp_clock_offset)
                self.logger.error(ppp("Received unexpected packet:", p))
                count += 1
            except CaptureTimeoutError:
                pass
            events = self.vapi.collect_events()
            if len(events) > 0:
                verify_event(self, events[0], BFDState.down)
                break
        self.assert_equal(count, 0, "number of packets received")

    def test_conn_down(self):
        """ verify session goes down after inactivity """
        bfd_session_up(self)
        for dummy in range(self.test_session.detect_mult):
            wait_for_bfd_packet(self)
            self.assert_equal(len(self.vapi.collect_events()), 0,
                              "number of bfd events")
        e = self.vapi.wait_for_event(1, "bfd_udp_session_details")
        verify_event(self, e, expected_state=BFDState.down)

    def test_large_required_min_rx(self):
        """ large remote required min rx interval """
        bfd_session_up(self)
        p = wait_for_bfd_packet(self)
        interval = 3000000
        self.test_session.update(required_min_rx=interval)
        self.test_session.send_packet()
        time_mark = time.time()
        count = 0
        # busy wait here, trying to collect a packet or event, vpp is not
        # allowed to send packets and the session will timeout first - so the
        # Up->Down event must arrive before any packets do
        while time.time() < time_mark + interval / USEC_IN_SEC:
            try:
                p = wait_for_bfd_packet(self, timeout=0)
                # if vpp managed to send a packet before we did the session
                # session update, then that's fine, ignore it
                if p.time < time_mark - self.vpp_clock_offset:
                    continue
                self.logger.error(ppp("Received unexpected packet:", p))
                count += 1
            except CaptureTimeoutError:
                pass
            events = self.vapi.collect_events()
            if len(events) > 0:
                verify_event(self, events[0], BFDState.down)
                break
        self.assert_equal(count, 0, "number of packets received")

    def test_immediate_remote_min_rx_reduction(self):
        """ immediately honor remote required min rx reduction """
        self.vpp_session.remove_vpp_config()
        self.vpp_session = VppBFDUDPSession(
            self, self.pg0, self.pg0.remote_ip4, desired_min_tx=10000)
        self.pg0.enable_capture()
        self.vpp_session.add_vpp_config()
        self.test_session.update(desired_min_tx=1000000,
                                 required_min_rx=1000000)
        bfd_session_up(self)
        reference_packet = wait_for_bfd_packet(self)
        time_mark = time.time()
        interval = 300000
        self.test_session.update(required_min_rx=interval)
        self.test_session.send_packet()
        extra_time = time.time() - time_mark
        p = wait_for_bfd_packet(self)
        # first packet is allowed to be late by time we spent doing the update
        # calculated in extra_time
        self.assert_in_range(p.time - reference_packet.time,
                             .95 * 0.75 * interval / USEC_IN_SEC,
                             1.05 * interval / USEC_IN_SEC + extra_time,
                             "time between BFD packets")
        reference_packet = p
        for dummy in range(3):
            p = wait_for_bfd_packet(self)
            diff = p.time - reference_packet.time
            self.assert_in_range(diff, .95 * .75 * interval / USEC_IN_SEC,
                                 1.05 * interval / USEC_IN_SEC,
                                 "time between BFD packets")
            reference_packet = p

    def test_modify_req_min_rx_double(self):
        """ modify session - double required min rx """
        bfd_session_up(self)
        p = wait_for_bfd_packet(self)
        self.test_session.update(desired_min_tx=10000,
                                 required_min_rx=10000)
        self.test_session.send_packet()
        # double required min rx
        self.vpp_session.modify_parameters(
            required_min_rx=2 * self.vpp_session.required_min_rx)
        p = wait_for_bfd_packet(
            self, pcap_time_min=time.time() - self.vpp_clock_offset)
        # poll bit needs to be set
        self.assertIn("P", p.sprintf("%BFD.flags%"),
                      "Poll bit not set in BFD packet")
        # finish poll sequence with final packet
        final = self.test_session.create_packet()
        final[BFD].flags = "F"
        timeout = self.test_session.detect_mult * \
            max(self.test_session.desired_min_tx,
                self.vpp_session.required_min_rx) / USEC_IN_SEC
        self.test_session.send_packet(final)
        time_mark = time.time()
        e = self.vapi.wait_for_event(2 * timeout, "bfd_udp_session_details")
        verify_event(self, e, expected_state=BFDState.down)
        time_to_event = time.time() - time_mark
        self.assert_in_range(time_to_event, .9 * timeout,
                             1.1 * timeout, "session timeout")

    def test_modify_req_min_rx_halve(self):
        """ modify session - halve required min rx """
        self.vpp_session.modify_parameters(
            required_min_rx=2 * self.vpp_session.required_min_rx)
        bfd_session_up(self)
        p = wait_for_bfd_packet(self)
        self.test_session.update(desired_min_tx=10000,
                                 required_min_rx=10000)
        self.test_session.send_packet()
        p = wait_for_bfd_packet(
            self, pcap_time_min=time.time() - self.vpp_clock_offset)
        # halve required min rx
        old_required_min_rx = self.vpp_session.required_min_rx
        self.vpp_session.modify_parameters(
            required_min_rx=0.5 * self.vpp_session.required_min_rx)
        # now we wait 0.8*3*old-req-min-rx and the session should still be up
        self.sleep(0.8 * self.vpp_session.detect_mult *
                   old_required_min_rx / USEC_IN_SEC)
        self.assert_equal(len(self.vapi.collect_events()), 0,
                          "number of bfd events")
        p = wait_for_bfd_packet(self)
        # poll bit needs to be set
        self.assertIn("P", p.sprintf("%BFD.flags%"),
                      "Poll bit not set in BFD packet")
        # finish poll sequence with final packet
        final = self.test_session.create_packet()
        final[BFD].flags = "F"
        self.test_session.send_packet(final)
        # now the session should time out under new conditions
        before = time.time()
        e = self.vapi.wait_for_event(1, "bfd_udp_session_details")
        after = time.time()
        detection_time = self.vpp_session.detect_mult *\
            self.vpp_session.required_min_rx / USEC_IN_SEC
        self.assert_in_range(after - before,
                             0.9 * detection_time,
                             1.1 * detection_time,
                             "time before bfd session goes down")
        verify_event(self, e, expected_state=BFDState.down)

    def test_modify_des_min_tx(self):
        """ modify desired min tx interval """
        pass

    def test_modify_detect_mult(self):
        """ modify detect multiplier """
        bfd_session_up(self)
        p = wait_for_bfd_packet(self)
        self.vpp_session.modify_parameters(detect_mult=1)
        p = wait_for_bfd_packet(
            self, pcap_time_min=time.time() - self.vpp_clock_offset)
        self.assert_equal(self.vpp_session.detect_mult,
                          p[BFD].detect_mult,
                          "detect mult")
        # poll bit must not be set
        self.assertNotIn("P", p.sprintf("%BFD.flags%"),
                         "Poll bit not set in BFD packet")
        self.vpp_session.modify_parameters(detect_mult=10)
        p = wait_for_bfd_packet(
            self, pcap_time_min=time.time() - self.vpp_clock_offset)
        self.assert_equal(self.vpp_session.detect_mult,
                          p[BFD].detect_mult,
                          "detect mult")
        # poll bit must not be set
        self.assertNotIn("P", p.sprintf("%BFD.flags%"),
                         "Poll bit not set in BFD packet")

    def test_no_periodic_if_remote_demand(self):
        """ no periodic frames outside poll sequence if remote demand set """
        bfd_session_up(self)
        demand = self.test_session.create_packet()
        demand[BFD].flags = "D"
        self.test_session.send_packet(demand)
        transmit_time = 0.9 \
            * max(self.vpp_session.required_min_rx,
                  self.test_session.desired_min_tx) \
            / USEC_IN_SEC
        count = 0
        for dummy in range(self.test_session.detect_mult * 2):
            time.sleep(transmit_time)
            self.test_session.send_packet(demand)
            try:
                p = wait_for_bfd_packet(self, timeout=0)
                self.logger.error(ppp("Received unexpected packet:", p))
                count += 1
            except CaptureTimeoutError:
                pass
        events = self.vapi.collect_events()
        for e in events:
            self.logger.error("Received unexpected event: %s", e)
        self.assert_equal(count, 0, "number of packets received")
        self.assert_equal(len(events), 0, "number of events received")

    def test_echo_looped_back(self):
        """ echo packets looped back """
        # don't need a session in this case..
        self.vpp_session.remove_vpp_config()
        self.pg0.enable_capture()
        echo_packet_count = 10
        # random source port low enough to increment a few times..
        udp_sport_tx = randint(1, 50000)
        udp_sport_rx = udp_sport_tx
        echo_packet = (Ether(src=self.pg0.remote_mac,
                             dst=self.pg0.local_mac) /
                       IP(src=self.pg0.remote_ip4,
                          dst=self.pg0.local_ip4) /
                       UDP(dport=BFD.udp_dport_echo) /
                       Raw("this should be looped back"))
        for dummy in range(echo_packet_count):
            self.sleep(.01, "delay between echo packets")
            echo_packet[UDP].sport = udp_sport_tx
            udp_sport_tx += 1
            self.logger.debug(ppp("Sending packet:", echo_packet))
            self.pg0.add_stream(echo_packet)
            self.pg_start()
        for dummy in range(echo_packet_count):
            p = self.pg0.wait_for_packet(1)
            self.logger.debug(ppp("Got packet:", p))
            ether = p[Ether]
            self.assert_equal(self.pg0.remote_mac,
                              ether.dst, "Destination MAC")
            self.assert_equal(self.pg0.local_mac, ether.src, "Source MAC")
            ip = p[IP]
            self.assert_equal(self.pg0.remote_ip4, ip.dst, "Destination IP")
            self.assert_equal(self.pg0.local_ip4, ip.src, "Destination IP")
            udp = p[UDP]
            self.assert_equal(udp.dport, BFD.udp_dport_echo,
                              "UDP destination port")
            self.assert_equal(udp.sport, udp_sport_rx, "UDP source port")
            udp_sport_rx += 1
            self.assertTrue(p.haslayer(Raw) and p[Raw] == echo_packet[Raw],
                            "Received packet is not the echo packet sent")
        self.assert_equal(udp_sport_tx, udp_sport_rx, "UDP source port (== "
                          "ECHO packet identifier for test purposes)")


class BFD6TestCase(VppTestCase):
    """Bidirectional Forwarding Detection (BFD) (IPv6) """

    pg0 = None
    vpp_clock_offset = None
    vpp_session = None
    test_session = None

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
        self.factory = AuthKeyFactory()
        self.vapi.want_bfd_events()
        self.pg0.enable_capture()
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
        if not self.vpp_dead:
            self.vapi.want_bfd_events(enable_disable=0)
        self.vapi.collect_events()  # clear the event queue
        super(BFD6TestCase, self).tearDown()

    def test_session_up(self):
        """ bring BFD session up """
        bfd_session_up(self)

    def test_hold_up(self):
        """ hold BFD session up """
        bfd_session_up(self)
        for dummy in range(self.test_session.detect_mult * 2):
            wait_for_bfd_packet(self)
            self.test_session.send_packet()
        self.assert_equal(len(self.vapi.collect_events()), 0,
                          "number of bfd events")
        self.assert_equal(self.vpp_session.state, BFDState.up, BFDState)

    def test_echo_looped_back(self):
        """ echo packets looped back """
        # don't need a session in this case..
        self.vpp_session.remove_vpp_config()
        self.pg0.enable_capture()
        echo_packet_count = 10
        # random source port low enough to increment a few times..
        udp_sport_tx = randint(1, 50000)
        udp_sport_rx = udp_sport_tx
        echo_packet = (Ether(src=self.pg0.remote_mac,
                             dst=self.pg0.local_mac) /
                       IPv6(src=self.pg0.remote_ip6,
                            dst=self.pg0.local_ip6) /
                       UDP(dport=BFD.udp_dport_echo) /
                       Raw("this should be looped back"))
        for dummy in range(echo_packet_count):
            self.sleep(.01, "delay between echo packets")
            echo_packet[UDP].sport = udp_sport_tx
            udp_sport_tx += 1
            self.logger.debug(ppp("Sending packet:", echo_packet))
            self.pg0.add_stream(echo_packet)
            self.pg_start()
        for dummy in range(echo_packet_count):
            p = self.pg0.wait_for_packet(1)
            self.logger.debug(ppp("Got packet:", p))
            ether = p[Ether]
            self.assert_equal(self.pg0.remote_mac,
                              ether.dst, "Destination MAC")
            self.assert_equal(self.pg0.local_mac, ether.src, "Source MAC")
            ip = p[IPv6]
            self.assert_equal(self.pg0.remote_ip6, ip.dst, "Destination IP")
            self.assert_equal(self.pg0.local_ip6, ip.src, "Destination IP")
            udp = p[UDP]
            self.assert_equal(udp.dport, BFD.udp_dport_echo,
                              "UDP destination port")
            self.assert_equal(udp.sport, udp_sport_rx, "UDP source port")
            udp_sport_rx += 1
            self.assertTrue(p.haslayer(Raw) and p[Raw] == echo_packet[Raw],
                            "Received packet is not the echo packet sent")
        self.assert_equal(udp_sport_tx, udp_sport_rx, "UDP source port (== "
                          "ECHO packet identifier for test purposes)")


class BFDSHA1TestCase(VppTestCase):
    """Bidirectional Forwarding Detection (BFD) (SHA1 auth) """

    pg0 = None
    vpp_clock_offset = None
    vpp_session = None
    test_session = None

    @classmethod
    def setUpClass(cls):
        super(BFDSHA1TestCase, cls).setUpClass()
        try:
            cls.create_pg_interfaces([0])
            cls.pg0.config_ip4()
            cls.pg0.admin_up()
            cls.pg0.resolve_arp()

        except Exception:
            super(BFDSHA1TestCase, cls).tearDownClass()
            raise

    def setUp(self):
        super(BFDSHA1TestCase, self).setUp()
        self.factory = AuthKeyFactory()
        self.vapi.want_bfd_events()
        self.pg0.enable_capture()

    def tearDown(self):
        if not self.vpp_dead:
            self.vapi.want_bfd_events(enable_disable=0)
        self.vapi.collect_events()  # clear the event queue
        super(BFDSHA1TestCase, self).tearDown()

    def test_session_up(self):
        """ bring BFD session up """
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        self.vpp_session = VppBFDUDPSession(self, self.pg0,
                                            self.pg0.remote_ip4,
                                            sha1_key=key)
        self.vpp_session.add_vpp_config()
        self.vpp_session.admin_up()
        self.test_session = BFDTestSession(
            self, self.pg0, AF_INET, sha1_key=key,
            bfd_key_id=self.vpp_session.bfd_key_id)
        bfd_session_up(self)

    def test_hold_up(self):
        """ hold BFD session up """
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        self.vpp_session = VppBFDUDPSession(self, self.pg0,
                                            self.pg0.remote_ip4,
                                            sha1_key=key)
        self.vpp_session.add_vpp_config()
        self.vpp_session.admin_up()
        self.test_session = BFDTestSession(
            self, self.pg0, AF_INET, sha1_key=key,
            bfd_key_id=self.vpp_session.bfd_key_id)
        bfd_session_up(self)
        for dummy in range(self.test_session.detect_mult * 2):
            wait_for_bfd_packet(self)
            self.test_session.send_packet()
        self.assert_equal(self.vpp_session.state, BFDState.up, BFDState)

    def test_hold_up_meticulous(self):
        """ hold BFD session up - meticulous auth """
        key = self.factory.create_random_key(
            self, BFDAuthType.meticulous_keyed_sha1)
        key.add_vpp_config()
        self.vpp_session = VppBFDUDPSession(self, self.pg0,
                                            self.pg0.remote_ip4, sha1_key=key)
        self.vpp_session.add_vpp_config()
        self.vpp_session.admin_up()
        # specify sequence number so that it wraps
        self.test_session = BFDTestSession(
            self, self.pg0, AF_INET, sha1_key=key,
            bfd_key_id=self.vpp_session.bfd_key_id,
            our_seq_number=0xFFFFFFFF - 4)
        bfd_session_up(self)
        for dummy in range(30):
            wait_for_bfd_packet(self)
            self.test_session.inc_seq_num()
            self.test_session.send_packet()
        self.assert_equal(self.vpp_session.state, BFDState.up, BFDState)

    def test_send_bad_seq_number(self):
        """ session is not kept alive by msgs with bad seq numbers"""
        key = self.factory.create_random_key(
            self, BFDAuthType.meticulous_keyed_sha1)
        key.add_vpp_config()
        self.vpp_session = VppBFDUDPSession(self, self.pg0,
                                            self.pg0.remote_ip4, sha1_key=key)
        self.vpp_session.add_vpp_config()
        self.vpp_session.admin_up()
        self.test_session = BFDTestSession(
            self, self.pg0, AF_INET, sha1_key=key,
            bfd_key_id=self.vpp_session.bfd_key_id)
        bfd_session_up(self)
        detection_time = self.vpp_session.detect_mult *\
            self.vpp_session.required_min_rx / USEC_IN_SEC
        session_timeout = time.time() + detection_time
        while time.time() < session_timeout:
            self.assert_equal(len(self.vapi.collect_events()), 0,
                              "number of bfd events")
            wait_for_bfd_packet(self)
            self.test_session.send_packet()
        wait_for_bfd_packet(self)
        self.test_session.send_packet()
        e = self.vapi.collect_events()
        # session should be down now, because the sequence numbers weren't
        # updated
        self.assert_equal(len(e), 1, "number of bfd events")
        verify_event(self, e[0], expected_state=BFDState.down)

    def execute_rogue_session_scenario(self, vpp_bfd_udp_session,
                                       legitimate_test_session,
                                       rogue_test_session,
                                       rogue_bfd_values=None):
        """ execute a rogue session interaction scenario

        1. create vpp session, add config
        2. bring the legitimate session up
        3. copy the bfd values from legitimate session to rogue session
        4. apply rogue_bfd_values to rogue session
        5. set rogue session state to down
        6. send message to take the session down from the rogue session
        7. assert that the legitimate session is unaffected
        """

        self.vpp_session = vpp_bfd_udp_session
        self.vpp_session.add_vpp_config()
        self.vpp_session.admin_up()
        self.test_session = legitimate_test_session
        # bring vpp session up
        bfd_session_up(self)
        # send packet from rogue session
        rogue_test_session.update(
            my_discriminator=self.test_session.my_discriminator,
            your_discriminator=self.test_session.your_discriminator,
            desired_min_tx=self.test_session.desired_min_tx,
            required_min_rx=self.test_session.required_min_rx,
            detect_mult=self.test_session.detect_mult,
            diag=self.test_session.diag,
            state=self.test_session.state,
            auth_type=self.test_session.auth_type)
        if rogue_bfd_values:
            rogue_test_session.update(**rogue_bfd_values)
        rogue_test_session.update(state=BFDState.down)
        rogue_test_session.send_packet()
        wait_for_bfd_packet(self)
        self.assert_equal(self.vpp_session.state, BFDState.up, BFDState)

    def test_mismatch_auth(self):
        """ session is not brought down by unauthenticated msg """
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        vpp_session = VppBFDUDPSession(
            self, self.pg0, self.pg0.remote_ip4, sha1_key=key)
        legitimate_test_session = BFDTestSession(
            self, self.pg0, AF_INET, sha1_key=key,
            bfd_key_id=vpp_session.bfd_key_id)
        rogue_test_session = BFDTestSession(self, self.pg0, AF_INET)
        self.execute_rogue_session_scenario(vpp_session,
                                            legitimate_test_session,
                                            rogue_test_session)

    def test_mismatch_bfd_key_id(self):
        """ session is not brought down by msg with non-existent key-id """
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        vpp_session = VppBFDUDPSession(
            self, self.pg0, self.pg0.remote_ip4, sha1_key=key)
        # pick a different random bfd key id
        x = randint(0, 255)
        while x == vpp_session.bfd_key_id:
            x = randint(0, 255)
        legitimate_test_session = BFDTestSession(
            self, self.pg0, AF_INET, sha1_key=key,
            bfd_key_id=vpp_session.bfd_key_id)
        rogue_test_session = BFDTestSession(
            self, self.pg0, AF_INET, sha1_key=key, bfd_key_id=x)
        self.execute_rogue_session_scenario(vpp_session,
                                            legitimate_test_session,
                                            rogue_test_session)

    def test_mismatched_auth_type(self):
        """ session is not brought down by msg with wrong auth type """
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        vpp_session = VppBFDUDPSession(
            self, self.pg0, self.pg0.remote_ip4, sha1_key=key)
        legitimate_test_session = BFDTestSession(
            self, self.pg0, AF_INET, sha1_key=key,
            bfd_key_id=vpp_session.bfd_key_id)
        rogue_test_session = BFDTestSession(
            self, self.pg0, AF_INET, sha1_key=key,
            bfd_key_id=vpp_session.bfd_key_id)
        self.execute_rogue_session_scenario(
            vpp_session, legitimate_test_session, rogue_test_session,
            {'auth_type': BFDAuthType.keyed_md5})

    def test_restart(self):
        """ simulate remote peer restart and resynchronization """
        key = self.factory.create_random_key(
            self, BFDAuthType.meticulous_keyed_sha1)
        key.add_vpp_config()
        self.vpp_session = VppBFDUDPSession(self, self.pg0,
                                            self.pg0.remote_ip4, sha1_key=key)
        self.vpp_session.add_vpp_config()
        self.vpp_session.admin_up()
        self.test_session = BFDTestSession(
            self, self.pg0, AF_INET, sha1_key=key,
            bfd_key_id=self.vpp_session.bfd_key_id, our_seq_number=0)
        bfd_session_up(self)
        # don't send any packets for 2*detection_time
        detection_time = self.vpp_session.detect_mult *\
            self.vpp_session.required_min_rx / USEC_IN_SEC
        self.sleep(detection_time, "simulating peer restart")
        events = self.vapi.collect_events()
        self.assert_equal(len(events), 1, "number of bfd events")
        verify_event(self, events[0], expected_state=BFDState.down)
        self.test_session.update(state=BFDState.down)
        # reset sequence number
        self.test_session.our_seq_number = 0
        self.test_session.vpp_seq_number = None
        # now throw away any pending packets
        self.pg0.enable_capture()
        bfd_session_up(self)


class BFDAuthOnOffTestCase(VppTestCase):
    """Bidirectional Forwarding Detection (BFD) (changing auth) """

    pg0 = None
    vpp_session = None
    test_session = None

    @classmethod
    def setUpClass(cls):
        super(BFDAuthOnOffTestCase, cls).setUpClass()
        try:
            cls.create_pg_interfaces([0])
            cls.pg0.config_ip4()
            cls.pg0.admin_up()
            cls.pg0.resolve_arp()

        except Exception:
            super(BFDAuthOnOffTestCase, cls).tearDownClass()
            raise

    def setUp(self):
        super(BFDAuthOnOffTestCase, self).setUp()
        self.factory = AuthKeyFactory()
        self.vapi.want_bfd_events()
        self.pg0.enable_capture()

    def tearDown(self):
        if not self.vpp_dead:
            self.vapi.want_bfd_events(enable_disable=0)
        self.vapi.collect_events()  # clear the event queue
        super(BFDAuthOnOffTestCase, self).tearDown()

    def test_auth_on_immediate(self):
        """ turn auth on without disturbing session state (immediate) """
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        self.vpp_session = VppBFDUDPSession(self, self.pg0,
                                            self.pg0.remote_ip4)
        self.vpp_session.add_vpp_config()
        self.vpp_session.admin_up()
        self.test_session = BFDTestSession(self, self.pg0, AF_INET)
        bfd_session_up(self)
        for dummy in range(self.test_session.detect_mult * 2):
            p = wait_for_bfd_packet(self)
            self.assert_equal(p[BFD].state, BFDState.up, BFDState)
            self.test_session.send_packet()
        self.vpp_session.activate_auth(key)
        self.test_session.bfd_key_id = self.vpp_session.bfd_key_id
        self.test_session.sha1_key = key
        for dummy in range(self.test_session.detect_mult * 2):
            p = wait_for_bfd_packet(self)
            self.assert_equal(p[BFD].state, BFDState.up, BFDState)
            self.test_session.send_packet()
        self.assert_equal(self.vpp_session.state, BFDState.up, BFDState)
        self.assert_equal(len(self.vapi.collect_events()), 0,
                          "number of bfd events")

    def test_auth_off_immediate(self):
        """ turn auth off without disturbing session state (immediate) """
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        self.vpp_session = VppBFDUDPSession(self, self.pg0,
                                            self.pg0.remote_ip4, sha1_key=key)
        self.vpp_session.add_vpp_config()
        self.vpp_session.admin_up()
        self.test_session = BFDTestSession(
            self, self.pg0, AF_INET, sha1_key=key,
            bfd_key_id=self.vpp_session.bfd_key_id)
        bfd_session_up(self)
        # self.vapi.want_bfd_events(enable_disable=0)
        for dummy in range(self.test_session.detect_mult * 2):
            p = wait_for_bfd_packet(self)
            self.assert_equal(p[BFD].state, BFDState.up, BFDState)
            self.test_session.inc_seq_num()
            self.test_session.send_packet()
        self.vpp_session.deactivate_auth()
        self.test_session.bfd_key_id = None
        self.test_session.sha1_key = None
        for dummy in range(self.test_session.detect_mult * 2):
            p = wait_for_bfd_packet(self)
            self.assert_equal(p[BFD].state, BFDState.up, BFDState)
            self.test_session.inc_seq_num()
            self.test_session.send_packet()
        self.assert_equal(self.vpp_session.state, BFDState.up, BFDState)
        self.assert_equal(len(self.vapi.collect_events()), 0,
                          "number of bfd events")

    def test_auth_change_key_immediate(self):
        """ change auth key without disturbing session state (immediate) """
        key1 = self.factory.create_random_key(self)
        key1.add_vpp_config()
        key2 = self.factory.create_random_key(self)
        key2.add_vpp_config()
        self.vpp_session = VppBFDUDPSession(self, self.pg0,
                                            self.pg0.remote_ip4, sha1_key=key1)
        self.vpp_session.add_vpp_config()
        self.vpp_session.admin_up()
        self.test_session = BFDTestSession(
            self, self.pg0, AF_INET, sha1_key=key1,
            bfd_key_id=self.vpp_session.bfd_key_id)
        bfd_session_up(self)
        for dummy in range(self.test_session.detect_mult * 2):
            p = wait_for_bfd_packet(self)
            self.assert_equal(p[BFD].state, BFDState.up, BFDState)
            self.test_session.send_packet()
        self.vpp_session.activate_auth(key2)
        self.test_session.bfd_key_id = self.vpp_session.bfd_key_id
        self.test_session.sha1_key = key2
        for dummy in range(self.test_session.detect_mult * 2):
            p = wait_for_bfd_packet(self)
            self.assert_equal(p[BFD].state, BFDState.up, BFDState)
            self.test_session.send_packet()
        self.assert_equal(self.vpp_session.state, BFDState.up, BFDState)
        self.assert_equal(len(self.vapi.collect_events()), 0,
                          "number of bfd events")

    def test_auth_on_delayed(self):
        """ turn auth on without disturbing session state (delayed) """
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        self.vpp_session = VppBFDUDPSession(self, self.pg0,
                                            self.pg0.remote_ip4)
        self.vpp_session.add_vpp_config()
        self.vpp_session.admin_up()
        self.test_session = BFDTestSession(self, self.pg0, AF_INET)
        bfd_session_up(self)
        for dummy in range(self.test_session.detect_mult * 2):
            wait_for_bfd_packet(self)
            self.test_session.send_packet()
        self.vpp_session.activate_auth(key, delayed=True)
        for dummy in range(self.test_session.detect_mult * 2):
            p = wait_for_bfd_packet(self)
            self.assert_equal(p[BFD].state, BFDState.up, BFDState)
            self.test_session.send_packet()
        self.test_session.bfd_key_id = self.vpp_session.bfd_key_id
        self.test_session.sha1_key = key
        self.test_session.send_packet()
        for dummy in range(self.test_session.detect_mult * 2):
            p = wait_for_bfd_packet(self)
            self.assert_equal(p[BFD].state, BFDState.up, BFDState)
            self.test_session.send_packet()
        self.assert_equal(self.vpp_session.state, BFDState.up, BFDState)
        self.assert_equal(len(self.vapi.collect_events()), 0,
                          "number of bfd events")

    def test_auth_off_delayed(self):
        """ turn auth off without disturbing session state (delayed) """
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        self.vpp_session = VppBFDUDPSession(self, self.pg0,
                                            self.pg0.remote_ip4, sha1_key=key)
        self.vpp_session.add_vpp_config()
        self.vpp_session.admin_up()
        self.test_session = BFDTestSession(
            self, self.pg0, AF_INET, sha1_key=key,
            bfd_key_id=self.vpp_session.bfd_key_id)
        bfd_session_up(self)
        for dummy in range(self.test_session.detect_mult * 2):
            p = wait_for_bfd_packet(self)
            self.assert_equal(p[BFD].state, BFDState.up, BFDState)
            self.test_session.send_packet()
        self.vpp_session.deactivate_auth(delayed=True)
        for dummy in range(self.test_session.detect_mult * 2):
            p = wait_for_bfd_packet(self)
            self.assert_equal(p[BFD].state, BFDState.up, BFDState)
            self.test_session.send_packet()
        self.test_session.bfd_key_id = None
        self.test_session.sha1_key = None
        self.test_session.send_packet()
        for dummy in range(self.test_session.detect_mult * 2):
            p = wait_for_bfd_packet(self)
            self.assert_equal(p[BFD].state, BFDState.up, BFDState)
            self.test_session.send_packet()
        self.assert_equal(self.vpp_session.state, BFDState.up, BFDState)
        self.assert_equal(len(self.vapi.collect_events()), 0,
                          "number of bfd events")

    def test_auth_change_key_delayed(self):
        """ change auth key without disturbing session state (delayed) """
        key1 = self.factory.create_random_key(self)
        key1.add_vpp_config()
        key2 = self.factory.create_random_key(self)
        key2.add_vpp_config()
        self.vpp_session = VppBFDUDPSession(self, self.pg0,
                                            self.pg0.remote_ip4, sha1_key=key1)
        self.vpp_session.add_vpp_config()
        self.vpp_session.admin_up()
        self.test_session = BFDTestSession(
            self, self.pg0, AF_INET, sha1_key=key1,
            bfd_key_id=self.vpp_session.bfd_key_id)
        bfd_session_up(self)
        for dummy in range(self.test_session.detect_mult * 2):
            p = wait_for_bfd_packet(self)
            self.assert_equal(p[BFD].state, BFDState.up, BFDState)
            self.test_session.send_packet()
        self.vpp_session.activate_auth(key2, delayed=True)
        for dummy in range(self.test_session.detect_mult * 2):
            p = wait_for_bfd_packet(self)
            self.assert_equal(p[BFD].state, BFDState.up, BFDState)
            self.test_session.send_packet()
        self.test_session.bfd_key_id = self.vpp_session.bfd_key_id
        self.test_session.sha1_key = key2
        self.test_session.send_packet()
        for dummy in range(self.test_session.detect_mult * 2):
            p = wait_for_bfd_packet(self)
            self.assert_equal(p[BFD].state, BFDState.up, BFDState)
            self.test_session.send_packet()
        self.assert_equal(self.vpp_session.state, BFDState.up, BFDState)
        self.assert_equal(len(self.vapi.collect_events()), 0,
                          "number of bfd events")

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
