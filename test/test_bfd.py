#!/usr/bin/env python

import unittest
import hashlib
import binascii
import time
from random import randint
from bfd import *
from framework import *
from util import ppp

us_in_sec = 1000000


class AuthKeyFactory(object):
    """Factory class for creating auth keys with unique conf key ID"""

    def __init__(self):
        self._conf_key_ids = {}

    def create_random_key(self, test, auth_type=BFDAuthType.keyed_sha1):
        conf_key_id = randint(0, 0xFFFFFFFF)
        while conf_key_id in self._conf_key_ids:
            conf_key_id = randint(0, 0xFFFFFFFF)
        self._conf_key_ids[conf_key_id] = 1
        key = str(bytearray([randint(0, 255) for j in range(randint(1, 20))]))
        return VppBFDAuthKey(test=test, auth_type=auth_type,
                             conf_key_id=conf_key_id, key=key)


class BFDAPITestCase(VppTestCase):
    """Bidirectional Forwarding Detection (BFD) - API"""

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
        self.logger.debug("Session state is %s" % str(session.state))
        session.remove_vpp_config()
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

    def test_add_bfd6(self):
        """ create IPv6 BFD session """
        session = VppBFDUDPSession(
            self, self.pg0, self.pg0.remote_ip6, af=AF_INET6)
        session.add_vpp_config()
        self.logger.debug("Session state is %s" % str(session.state))
        session.remove_vpp_config()
        session.add_vpp_config()
        self.logger.debug("Session state is %s" % str(session.state))
        session.remove_vpp_config()

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
        random.shuffle(indexes)
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
        self.logger.debug("Session state is %s" % str(session.state))
        session.remove_vpp_config()
        session.add_vpp_config()
        self.logger.debug("Session state is %s" % str(session.state))
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

    def test_add_authenticated_with_nonexistent_key(self):
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
                 bfd_key_id=None, our_seq_number=0xFFFFFFFF - 4):
        self.test = test
        self.af = af
        self.sha1_key = sha1_key
        self.bfd_key_id = bfd_key_id
        self.interface = interface
        self.udp_sport = 50000
        self.our_seq_number = our_seq_number
        self.vpp_seq_number = None
        self.bfd_values = {
            'my_discriminator': 0,
            'desired_min_tx_interval': 100000,
            'detect_mult': detect_mult,
            'diag': BFDDiagCode.no_diagnostic,
        }

    def inc_seq_num(self):
        if self.our_seq_number == 0xFFFFFFFF:
            self.our_seq_number = 0
        else:
            self.our_seq_number += 1

    def update(self, **kwargs):
        self.bfd_values.update(kwargs)

    def create_packet(self):
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
        for name, value in self.bfd_values.iteritems():
            self.test.logger.debug("BFD: setting packet.%s=%s", name, value)
            packet[BFD].setfieldval(name, value)
        if self.sha1_key:
            hash_material = str(packet[BFD])[:32] + self.sha1_key.key + \
                "\0" * (20 - len(self.sha1_key.key))
            self.test.logger.debug("BFD: Calculated SHA1 hash: %s" %
                                   hashlib.sha1(hash_material).hexdigest())
            packet[BFD].auth_key_hash = hashlib.sha1(hash_material).digest()
        return packet

    def send_packet(self):
        p = self.create_packet()
        self.test.logger.debug(ppp("Sending packet:", p))
        self.test.pg0.add_stream([p])
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
                               self.bfd_values['my_discriminator'],
                               "BFD - your discriminator")
        if self.sha1_key:
            self.verify_sha1_auth(packet)


class BFDCommonCode:
    """Common code used by both IPv4 and IPv6 Test Cases"""

    def tearDown(self):
        self.vapi.collect_events()  # clear the event queue
        if not self.vpp_dead:
            self.vapi.want_bfd_events(enable_disable=0)

    def bfd_session_up(self):
        """ Bring BFD session up """
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
        self.assert_equal(self.vpp_session.state, BFDState.up, BFDState)

    def bfd_session_down(self):
        """ Bring BFD session down """
        self.assert_equal(self.vpp_session.state, BFDState.up, BFDState)
        self.test_session.update(state=BFDState.down)
        self.test_session.send_packet()
        self.logger.info("BFD: Waiting for event")
        e = self.vapi.wait_for_event(1, "bfd_udp_session_details")
        self.verify_event(e, expected_state=BFDState.down)
        self.logger.info("BFD: Session is Down")
        self.assert_equal(self.vpp_session.state, BFDState.down, BFDState)

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
        self.assert_equal(e.sw_if_index,
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
        self.logger.debug(ppp("BFD: Got packet:", p))
        bfd = p[BFD]
        if bfd is None:
            raise Exception(ppp("Unexpected or invalid BFD packet:", p))
        if bfd.payload:
            raise Exception(ppp("Unexpected payload in BFD packet:", bfd))
        self.verify_ip(p)
        self.verify_udp(p)
        self.test_session.verify_bfd(p)
        return p, after - before


class BFD4TestCase(VppTestCase, BFDCommonCode):
    """Bidirectional Forwarding Detection (BFD)"""

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
        VppTestCase.tearDown(self)

    def test_session_up(self):
        """ bring BFD session up """
        self.bfd_session_up()

    def test_session_down(self):
        """ bring BFD session down """
        self.bfd_session_up()
        self.bfd_session_down()

    def test_hold_up(self):
        """ hold BFD session up """
        self.bfd_session_up()
        for i in range(5):
            self.wait_for_bfd_packet()
            self.test_session.send_packet()
        self.assert_equal(len(self.vapi.collect_events()), 0,
                          "number of bfd events")

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
        self.factory = AuthKeyFactory()
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
        VppTestCase.tearDown(self)

    def test_session_up(self):
        """ bring BFD session up """
        self.bfd_session_up()

    def test_hold_up(self):
        """ hold BFD session up """
        self.bfd_session_up()
        for i in range(5):
            self.wait_for_bfd_packet()
            self.test_session.send_packet()
        self.assert_equal(len(self.vapi.collect_events()), 0,
                          "number of bfd events")
        self.assert_equal(self.vpp_session.state, BFDState.up, BFDState)


class BFDSHA1TestCase(VppTestCase, BFDCommonCode):
    """Bidirectional Forwarding Detection (BFD) (SHA1 auth) """

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

    def tearDown(self):
        BFDCommonCode.tearDown(self)
        VppTestCase.tearDown(self)

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
        self.bfd_session_up()

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
        self.bfd_session_up()
        for i in range(5):
            self.wait_for_bfd_packet()
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
        self.test_session = BFDTestSession(
            self, self.pg0, AF_INET, sha1_key=key,
            bfd_key_id=self.vpp_session.bfd_key_id)
        self.bfd_session_up()
        for i in range(5):
            self.wait_for_bfd_packet()
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
        self.bfd_session_up()
        self.wait_for_bfd_packet()
        self.test_session.send_packet()
        self.assert_equal(len(self.vapi.collect_events()), 0,
                          "number of bfd events")
        self.wait_for_bfd_packet()
        self.test_session.send_packet()
        self.assert_equal(len(self.vapi.collect_events()), 0,
                          "number of bfd events")
        self.wait_for_bfd_packet()
        self.test_session.send_packet()
        self.wait_for_bfd_packet()
        self.test_session.send_packet()
        e = self.vapi.collect_events()
        # session should be down now, because the sequence numbers weren't
        # updated
        self.assert_equal(len(e), 1, "number of bfd events")
        self.verify_event(e[0], expected_state=BFDState.down)

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
        self.bfd_session_up()
        # send packet from rogue session
        rogue_test_session.bfd_values = self.test_session.bfd_values.copy()
        if rogue_bfd_values:
            rogue_test_session.update(**rogue_bfd_values)
        rogue_test_session.update(state=BFDState.down)
        rogue_test_session.send_packet()
        self.wait_for_bfd_packet()
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
        self.bfd_session_up()
        # now we need to not respond for 2*detection_time (4 packets)
        self.wait_for_bfd_packet()
        self.assert_equal(len(self.vapi.collect_events()), 0,
                          "number of bfd events")
        self.wait_for_bfd_packet()
        self.assert_equal(len(self.vapi.collect_events()), 0,
                          "number of bfd events")
        e = self.vapi.wait_for_event(1, "bfd_udp_session_details")
        self.verify_event(e, expected_state=BFDState.down)
        self.test_session.update(state=BFDState.down)
        self.wait_for_bfd_packet()
        self.assert_equal(len(self.vapi.collect_events()), 0,
                          "number of bfd events")
        self.wait_for_bfd_packet()
        self.assert_equal(len(self.vapi.collect_events()), 0,
                          "number of bfd events")
        # reset sequence number
        self.test_session.our_seq_number = 0
        self.bfd_session_up()


class BFDAuthOnOffTestCase(VppTestCase, BFDCommonCode):
    """Bidirectional Forwarding Detection (BFD) (changing auth) """

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

    def tearDown(self):
        BFDCommonCode.tearDown(self)
        VppTestCase.tearDown(self)

    def test_auth_on_immediate(self):
        """ turn auth on without disturbing session state (immediate) """
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        self.vpp_session = VppBFDUDPSession(self, self.pg0,
                                            self.pg0.remote_ip4)
        self.vpp_session.add_vpp_config()
        self.vpp_session.admin_up()
        self.test_session = BFDTestSession(self, self.pg0, AF_INET)
        self.bfd_session_up()
        for i in range(5):
            self.wait_for_bfd_packet()
            self.test_session.send_packet()
        self.vpp_session.activate_auth(key)
        self.test_session.bfd_key_id = self.vpp_session.bfd_key_id
        self.test_session.sha1_key = key
        for i in range(5):
            self.wait_for_bfd_packet()
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
        self.bfd_session_up()
        for i in range(5):
            self.wait_for_bfd_packet()
            self.test_session.send_packet()
        self.vpp_session.deactivate_auth()
        self.test_session.bfd_key_id = None
        self.test_session.sha1_key = None
        for i in range(5):
            self.wait_for_bfd_packet()
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
        self.bfd_session_up()
        for i in range(5):
            self.wait_for_bfd_packet()
            self.test_session.send_packet()
        self.vpp_session.activate_auth(key2)
        self.test_session.bfd_key_id = self.vpp_session.bfd_key_id
        self.test_session.sha1_key = key2
        for i in range(5):
            self.wait_for_bfd_packet()
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
        self.bfd_session_up()
        for i in range(5):
            self.wait_for_bfd_packet()
            self.test_session.send_packet()
        self.vpp_session.activate_auth(key, delayed=True)
        for i in range(5):
            self.wait_for_bfd_packet()
            self.test_session.send_packet()
        self.test_session.bfd_key_id = self.vpp_session.bfd_key_id
        self.test_session.sha1_key = key
        self.test_session.send_packet()
        for i in range(5):
            self.wait_for_bfd_packet()
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
        self.bfd_session_up()
        for i in range(5):
            self.wait_for_bfd_packet()
            self.test_session.send_packet()
        self.vpp_session.deactivate_auth(delayed=True)
        for i in range(5):
            self.wait_for_bfd_packet()
            self.test_session.send_packet()
        self.test_session.bfd_key_id = None
        self.test_session.sha1_key = None
        self.test_session.send_packet()
        for i in range(5):
            self.wait_for_bfd_packet()
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
        self.bfd_session_up()
        for i in range(5):
            self.wait_for_bfd_packet()
            self.test_session.send_packet()
        self.vpp_session.activate_auth(key2, delayed=True)
        for i in range(5):
            self.wait_for_bfd_packet()
            self.test_session.send_packet()
        self.test_session.bfd_key_id = self.vpp_session.bfd_key_id
        self.test_session.sha1_key = key2
        self.test_session.send_packet()
        for i in range(5):
            self.wait_for_bfd_packet()
            self.test_session.send_packet()
        self.assert_equal(self.vpp_session.state, BFDState.up, BFDState)
        self.assert_equal(len(self.vapi.collect_events()), 0,
                          "number of bfd events")

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
