#!/usr/bin/env python3
"""BFD tests"""

from __future__ import division

import binascii
from collections import namedtuple
import hashlib
import ipaddress
import reprlib
import time
import unittest
from random import randint, shuffle, getrandbits
from socket import AF_INET, AF_INET6
from parameterized import parameterized, parameterized_class

import scapy.compat
from scapy.contrib.mpls import MPLS
from scapy.layers.inet import UDP, IP, ICMP, IPOption, TCP, fragment
from scapy.layers.inet6 import IPv6, ICMPv6DestUnreach, ICMPv6EchoRequest
from scapy.layers.l2 import Ether, GRE
from scapy.packet import Raw

from config import config
from bfd import (
    VppBFDAuthKey,
    BFD,
    BFDAuthType,
    VppBFDUDPSession,
    BFDDiagCode,
    BFDState,
    BFD_vpp_echo,
    BFD_UDP_SH_PORT,
    BFD_UDP_MH_PORT,
    BFD_UDP_SBFD_PORT,
    BFD_UDP_DEFAULT_TOS,
    BFD_TEST_DETECT_MULT,
    VppSBFDReflector,
    SBFD_DEFAULT_REQUIRED_MIN_RX,
)
from framework import VppTestCase
from asfframework import (
    tag_fixme_vpp_workers,
    tag_run_solo,
    VppTestRunner,
)
from util import ppp
from vpp_ip import DpoProto
from vpp_ip_route import (
    VppIpRoute,
    VppRoutePath,
    VppIpTable,
    VppMplsTable,
    find_route,
    VppMplsRoute,
    FibPathProto,
)
from vpp_lo_interface import VppLoInterface
from vpp_neighbor import VppNeighbor
from vpp_papi_provider import UnexpectedApiReturnValueError, CliFailedCommandError
from vpp_pg_interface import CaptureTimeoutError, is_ipv6_misc
from vpp_gre_interface import VppGreInterface
from vpp_qos import VppQosRecord, VppQosEgressMap, VppQosMark
from vpp_papi import VppEnum

USEC_IN_SEC = 1000000
BFD_STATS_V4_SH_PATH = "/bfd/udp4/sessions"
BFD_STATS_V6_SH_PATH = "/bfd/udp6/sessions"
BFD_STATS_V4_MH_PATH = "/bfd/udp4/sessions_mh"
BFD_STATS_V6_MH_PATH = "/bfd/udp6/sessions_mh"
BFD_IPV4_REMOTE_ADDR = "2.2.2.2"
BFD_IPV6_REMOTE_ADDR = "2::2"
BFD_IPV4_REMOTE_ADDR2 = "3.3.3.3"
BFD_IPV6_REMOTE_ADDR2 = "3::3"
# S-BFD requests sent over MPLS paths go to these ranges (RFC 7881 section 5.1)
SBFD_MPLS_PATH_DST4 = ("127.0.0.1", "127.255.255.254")
SBFD_MPLS_PATH_DST6 = ("::ffff:127.0.0.1", "::ffff:127.255.255.254")
SBFD_MPLS_PATH_PREFIXES = (("127.0.0.0", 8), ("::ffff:127.0.0.0", 104))


def set_ipv4_pfx_route_info(cls, pg_if, dst_ip, set_src):
    try:
        if cls.multihop:
            paths = []
            # Get list of all the next hops
            for nh_host in pg_if.remote_hosts:
                nh_host_ip = nh_host.ip4
                paths.append(VppRoutePath(nh_host_ip, pg_if.sw_if_index))
            cls.dst_ip_net = dst_ip
            # Create a route pointing to list of next hops
            if paths:
                rip = VppIpRoute(cls, cls.dst_ip_net, 32, paths)
                rip.add_vpp_config()
                cls.logger.info("Route via %s on %s created" % (paths, pg_if.name))
            if set_src:
                cls.src_ip_net = cls.loopback0.local_ip4
        else:
            cls.dst_ip_net = pg_if.remote_ip4
            if set_src:
                cls.src_ip_net = pg_if.local_ip4
    except BaseException:
        cls.vapi.want_bfd_events(enable_disable=0)
        raise


def set_ipv6_pfx_route_info(cls, pg_if, dst_ip, set_src):
    try:
        if cls.multihop:
            paths = []
            # Get list of all the next hops
            for nh_host in pg_if.remote_hosts:
                nh_host_ip = nh_host.ip6
                paths.append(VppRoutePath(nh_host_ip, pg_if.sw_if_index))
            cls.dst_ip6_net = dst_ip
            # Create a route pointing to list of next hops
            if paths:
                rip = VppIpRoute(cls, cls.dst_ip6_net, 128, paths)
                rip.add_vpp_config()
                cls.logger.info("Route via %s on %s created" % (paths, pg_if.name))
            if set_src:
                cls.src_ip6_net = cls.loopback0.local_ip6
        else:
            cls.dst_ip6_net = cls.pg0.remote_ip6
            if set_src:
                cls.src_ip6_net = cls.pg0.local_ip6
    except BaseException:
        cls.vapi.want_bfd_events(enable_disable=0)
        raise


class AuthKeyFactory(object):
    """Factory class for creating auth keys with unique conf key ID"""

    def __init__(self):
        self._conf_key_ids = {}

    def create_random_key(self, test, auth_type=BFDAuthType.keyed_sha1):
        """create a random key with unique conf key id"""
        conf_key_id = randint(0, 0xFFFFFFFF)
        while conf_key_id in self._conf_key_ids:
            conf_key_id = randint(0, 0xFFFFFFFF)
        self._conf_key_ids[conf_key_id] = 1
        key = scapy.compat.raw(
            bytearray([randint(0, 255) for _ in range(randint(1, 20))])
        )
        return VppBFDAuthKey(
            test=test, auth_type=auth_type, conf_key_id=conf_key_id, key=key
        )


@parameterized_class(
    [
        {"multihop": False},
        {"multihop": True},
    ]
)
class BFDAPITestCase(VppTestCase):
    """BFD API test"""

    pg0 = None
    pg1 = None
    interface0 = None
    interface1 = None
    src_ip_net = ""
    dst_ip_net = ""
    src_ip_net2 = ""
    dst_ip_net2 = ""
    src_ip6_net = ""
    dst_ip6_net = ""
    src_ip6_net2 = ""
    dst_ip6_net2 = ""

    @classmethod
    def setUpClass(cls):
        super(BFDAPITestCase, cls).setUpClass()
        hoptype_str = "MultiHop" if cls.multihop else "SingleHop"
        cls.__doc__ = (
            f"""""Bidirectional Forwarding Detection (BFD) - API, {hoptype_str}"""
        )
        cls.vapi.cli("set log class bfd level debug")
        try:
            cls.create_pg_interfaces(range(2))
            cls.create_loopback_interfaces(2)
            cls.loopback0 = cls.lo_interfaces[0]
            cls.loopback0.config_ip4()
            cls.loopback0.admin_up()
            cls.loopback1 = cls.lo_interfaces[1]
            cls.loopback1.config_ip4()
            cls.loopback1.admin_up()
            for i in cls.pg_interfaces:
                i.config_ip4()
                i.config_ip6()
                i.resolve_arp()

        except Exception:
            super(BFDAPITestCase, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(BFDAPITestCase, cls).tearDownClass()

    def setUp(self):
        super(BFDAPITestCase, self).setUp()
        self.factory = AuthKeyFactory()

        if self.multihop:
            self.interface0 = None
            self.interface1 = None
            self.src_ip_net = self.loopback0.local_ip4
            self.src_ip6_net = self.loopback0.local_ip6
            self.dst_ip_net = BFD_IPV4_REMOTE_ADDR
            self.dst_ip6_net = BFD_IPV6_REMOTE_ADDR
            self.src_ip_net2 = self.loopback1.local_ip4
            self.src_ip6_net2 = self.loopback1.local_ip6
            self.dst_ip_net2 = BFD_IPV4_REMOTE_ADDR2
            self.dst_ip6_net2 = BFD_IPV6_REMOTE_ADDR2
        else:
            self.interface0 = self.pg0
            self.interface1 = self.pg1
            self.src_ip_net = self.pg0.local_ip4
            self.src_ip6_net = self.pg0.local_ip6
            self.dst_ip_net = self.pg0.remote_ip4
            self.dst_ip6_net = self.pg0.remote_ip6
            self.src_ip_net2 = self.pg1.local_ip4
            self.src_ip6_net2 = self.pg1.local_ip6
            self.dst_ip_net2 = BFD_IPV4_REMOTE_ADDR2
            self.dst_ip6_net2 = BFD_IPV6_REMOTE_ADDR2

    def test_add_bfd(self):
        """create a BFD session"""
        session = VppBFDUDPSession(
            self,
            self.interface0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
        )
        session.add_vpp_config()
        self.logger.debug("Session state is %s", session.state)
        session.remove_vpp_config()
        session.add_vpp_config()
        self.logger.debug("Session state is %s", session.state)
        session.remove_vpp_config()

    def test_double_add(self):
        """create the same BFD session twice (negative case)"""
        session = VppBFDUDPSession(
            self,
            self.interface0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
        )
        session.add_vpp_config()

        with self.vapi.assert_negative_api_retval():
            session.add_vpp_config()

        session.remove_vpp_config()

    def test_add_bfd6(self):
        """create IPv6 BFD session"""
        session = VppBFDUDPSession(
            self,
            self.interface0,
            self.dst_ip6_net,
            local_addr=self.src_ip6_net,
            af=AF_INET6,
            multihop=self.multihop,
        )
        session.add_vpp_config()
        self.logger.debug("Session state is %s", session.state)
        session.remove_vpp_config()
        session.add_vpp_config()
        self.logger.debug("Session state is %s", session.state)
        session.remove_vpp_config()

    def test_mod_bfd(self):
        """modify BFD session parameters"""
        session = VppBFDUDPSession(
            self,
            self.interface0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
            desired_min_tx=50000,
            required_min_rx=10000,
            detect_mult=1,
        )
        session.add_vpp_config()
        s = session.get_bfd_udp_session_dump_entry()
        self.assert_equal(
            session.desired_min_tx, s.desired_min_tx, "desired min transmit interval"
        )
        self.assert_equal(
            session.required_min_rx, s.required_min_rx, "required min receive interval"
        )
        self.assert_equal(session.detect_mult, s.detect_mult, "detect mult")
        session.modify_parameters(
            desired_min_tx=session.desired_min_tx * 2,
            required_min_rx=session.required_min_rx * 2,
            detect_mult=session.detect_mult * 2,
        )
        s = session.get_bfd_udp_session_dump_entry()
        self.assert_equal(
            session.desired_min_tx, s.desired_min_tx, "desired min transmit interval"
        )
        self.assert_equal(
            session.required_min_rx, s.required_min_rx, "required min receive interval"
        )
        self.assert_equal(session.detect_mult, s.detect_mult, "detect mult")

    def test_upd_bfd(self):
        """Create/Modify w/ Update BFD session parameters"""
        session = VppBFDUDPSession(
            self,
            self.interface0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
            desired_min_tx=50000,
            required_min_rx=10000,
            detect_mult=1,
        )
        session.upd_vpp_config()
        s = session.get_bfd_udp_session_dump_entry()
        self.assert_equal(
            session.desired_min_tx, s.desired_min_tx, "desired min transmit interval"
        )
        self.assert_equal(
            session.required_min_rx, s.required_min_rx, "required min receive interval"
        )

        self.assert_equal(session.detect_mult, s.detect_mult, "detect mult")
        session.upd_vpp_config(
            desired_min_tx=session.desired_min_tx * 2,
            required_min_rx=session.required_min_rx * 2,
            detect_mult=session.detect_mult * 2,
        )
        s = session.get_bfd_udp_session_dump_entry()
        self.assert_equal(
            session.desired_min_tx, s.desired_min_tx, "desired min transmit interval"
        )
        self.assert_equal(
            session.required_min_rx, s.required_min_rx, "required min receive interval"
        )
        self.assert_equal(session.detect_mult, s.detect_mult, "detect mult")

    def test_add_sha1_keys(self):
        """add SHA1 keys"""
        key_count = 10
        keys = [self.factory.create_random_key(self) for i in range(0, key_count)]
        for key in keys:
            self.assertFalse(key.query_vpp_config())
        for key in keys:
            key.add_vpp_config()
        for key in keys:
            self.assertTrue(key.query_vpp_config())
        # remove randomly
        indexes = list(range(key_count))
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
        """create a BFD session (SHA1)"""
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        session = VppBFDUDPSession(
            self,
            self.interface0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
            sha1_key=key,
        )
        session.add_vpp_config()
        self.logger.debug("Session state is %s", session.state)
        session.remove_vpp_config()
        session.add_vpp_config()
        self.logger.debug("Session state is %s", session.state)
        session.remove_vpp_config()

    def test_double_add_sha1(self):
        """create the same BFD session twice (negative case) (SHA1)"""
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        session = VppBFDUDPSession(
            self,
            self.interface0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
            sha1_key=key,
        )
        session.add_vpp_config()
        with self.assertRaises(Exception):
            session.add_vpp_config()

    def test_add_auth_nonexistent_key(self):
        """create BFD session using non-existent SHA1 (negative case)"""
        session = VppBFDUDPSession(
            self,
            self.interface0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
            sha1_key=self.factory.create_random_key(self),
        )
        self.session = VppBFDUDPSession(
            self,
            self.interface0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
        )
        with self.assertRaises(Exception):
            session.add_vpp_config()

    def test_shared_sha1_key(self):
        """single SHA1 key shared by multiple BFD sessions"""
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        sessions = [
            VppBFDUDPSession(
                self,
                self.interface0,
                self.dst_ip_net,
                local_addr=self.src_ip_net,
                multihop=self.multihop,
                sha1_key=key,
            ),
            VppBFDUDPSession(
                self,
                self.interface0,
                self.dst_ip6_net,
                local_addr=self.src_ip6_net,
                af=AF_INET6,
                multihop=self.multihop,
                sha1_key=key,
            ),
            VppBFDUDPSession(
                self,
                self.interface1,
                self.dst_ip_net2,
                local_addr=self.src_ip_net2,
                multihop=self.multihop,
                sha1_key=key,
            ),
            VppBFDUDPSession(
                self,
                self.interface1,
                self.dst_ip6_net2,
                local_addr=self.src_ip6_net2,
                af=AF_INET6,
                multihop=self.multihop,
                sha1_key=key,
            ),
        ]
        for s in sessions:
            s.add_vpp_config()
        removed = 0
        for s in sessions:
            e = key.get_bfd_auth_keys_dump_entry()
            self.assert_equal(
                e.use_count, len(sessions) - removed, "Use count for shared key"
            )
            s.remove_vpp_config()
            removed += 1
        e = key.get_bfd_auth_keys_dump_entry()
        self.assert_equal(
            e.use_count, len(sessions) - removed, "Use count for shared key"
        )

    def test_activate_auth(self):
        """activate SHA1 authentication"""
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        session = VppBFDUDPSession(
            self,
            self.interface0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
        )
        session.add_vpp_config()
        session.activate_auth(key)

    def test_deactivate_auth(self):
        """deactivate SHA1 authentication"""
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        session = VppBFDUDPSession(
            self,
            self.interface0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
        )
        session.add_vpp_config()
        session.activate_auth(key)
        session.deactivate_auth()

    def test_change_key(self):
        """change SHA1 key"""
        key1 = self.factory.create_random_key(self)
        key2 = self.factory.create_random_key(self)
        while key2.conf_key_id == key1.conf_key_id:
            key2 = self.factory.create_random_key(self)
        key1.add_vpp_config()
        key2.add_vpp_config()
        session = VppBFDUDPSession(
            self,
            self.interface0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
            sha1_key=key1,
        )
        session.add_vpp_config()
        session.activate_auth(key2)

    def test_set_del_udp_echo_source(self):
        """set/del udp echo source"""

        if self.multihop:
            self.skipTest(
                f"Skipping because echo functionality is not supported with multihop"
            )

        self.create_loopback_interfaces(1)
        self.loopback0 = self.lo_interfaces[0]
        self.loopback0.admin_up()
        echo_source = self.vapi.bfd_udp_get_echo_source()
        self.assertFalse(echo_source.is_set)
        self.assertFalse(echo_source.have_usable_ip4)
        self.assertFalse(echo_source.have_usable_ip6)

        self.vapi.bfd_udp_set_echo_source(sw_if_index=self.loopback0.sw_if_index)
        echo_source = self.vapi.bfd_udp_get_echo_source()
        self.assertTrue(echo_source.is_set)
        self.assertEqual(echo_source.sw_if_index, self.loopback0.sw_if_index)
        self.assertFalse(echo_source.have_usable_ip4)
        self.assertFalse(echo_source.have_usable_ip6)

        self.loopback0.config_ip4()
        echo_ip4 = ipaddress.IPv4Address(
            int(ipaddress.IPv4Address(self.loopback0.local_ip4)) ^ 1
        ).packed
        echo_source = self.vapi.bfd_udp_get_echo_source()
        self.assertTrue(echo_source.is_set)
        self.assertEqual(echo_source.sw_if_index, self.loopback0.sw_if_index)
        self.assertTrue(echo_source.have_usable_ip4)
        self.assertEqual(echo_source.ip4_addr.packed, echo_ip4)
        self.assertFalse(echo_source.have_usable_ip6)

        self.loopback0.config_ip6()
        echo_ip6 = ipaddress.IPv6Address(
            int(ipaddress.IPv6Address(self.loopback0.local_ip6)) ^ 1
        ).packed

        echo_source = self.vapi.bfd_udp_get_echo_source()
        self.assertTrue(echo_source.is_set)
        self.assertEqual(echo_source.sw_if_index, self.loopback0.sw_if_index)
        self.assertTrue(echo_source.have_usable_ip4)
        self.assertEqual(echo_source.ip4_addr.packed, echo_ip4)
        self.assertTrue(echo_source.have_usable_ip6)
        self.assertEqual(echo_source.ip6_addr.packed, echo_ip6)

        self.vapi.bfd_udp_del_echo_source()
        echo_source = self.vapi.bfd_udp_get_echo_source()
        self.assertFalse(echo_source.is_set)
        self.assertFalse(echo_source.have_usable_ip4)
        self.assertFalse(echo_source.have_usable_ip6)

    def test_set_udp_tos(self):
        """test udp tos configuration"""
        if self.multihop:
            return
        self.vapi.bfd_udp_set_tos(BFD_UDP_DEFAULT_TOS)
        my_tos = self.vapi.bfd_udp_get_tos()
        self.logger.debug("MY_TOS is %s", my_tos)
        self.assertTrue(my_tos.tos == BFD_UDP_DEFAULT_TOS)
        new_tos_value = 112
        self.vapi.bfd_udp_set_tos(new_tos_value)
        my_tos = self.vapi.bfd_udp_get_tos()
        self.assertTrue(my_tos.tos == new_tos_value)
        self.vapi.bfd_udp_set_tos(BFD_UDP_DEFAULT_TOS)

    def test_sbfd_reflector_add_del(self):
        """add/delete S-BFD reflector discriminators"""
        r1 = VppSBFDReflector(self, 0x01020304)
        r2 = VppSBFDReflector(self, 0xFFFFFFFF, admin_up=False, required_min_rx=1000000)
        r1.add_vpp_config()
        r2.add_vpp_config()
        self.assert_equal(
            len(self.vapi.bfd_udp_sbfd_reflector_dump()), 2, "number of reflectors"
        )
        verify_sbfd_reflector_config(self, r1)
        verify_sbfd_reflector_config(self, r2)
        r1.remove_vpp_config()
        self.assertFalse(r1.query_vpp_config())
        verify_sbfd_reflector_config(self, r2)
        r2.remove_vpp_config()
        self.assert_equal(
            len(self.vapi.bfd_udp_sbfd_reflector_dump()), 0, "number of reflectors"
        )

    def test_sbfd_reflector_api_defaults(self):
        """add S-BFD reflector discriminator with API defaults"""
        reflector = VppSBFDReflector(self, 0x01020304)
        self.vapi.bfd_udp_sbfd_reflector_add_del(discriminator=reflector.discriminator)
        self.registry.register(reflector, self.logger)
        dump = reflector.get_bfd_udp_sbfd_reflector_dump_entry()
        self.assertIsNotNone(dump)
        self.assertTrue(dump.admin_up)
        self.assert_equal(
            dump.required_min_rx, SBFD_DEFAULT_REQUIRED_MIN_RX, "required min rx"
        )
        reflector.remove_vpp_config()

    def test_sbfd_reflector_double_add(self):
        """add the same S-BFD discriminator twice (negative case)"""
        reflector = VppSBFDReflector(self, 0x01020304)
        reflector.add_vpp_config()
        duplicate = VppSBFDReflector(
            self, reflector.discriminator, admin_up=False, required_min_rx=1000000
        )
        with self.vapi.assert_negative_api_retval():
            duplicate.add_vpp_config()
        verify_sbfd_reflector_config(self, reflector)
        reflector.remove_vpp_config()

    def test_sbfd_reflector_del_nonexistent(self):
        """delete a non-existent S-BFD discriminator (negative case)"""
        with self.vapi.assert_negative_api_retval():
            self.vapi.bfd_udp_sbfd_reflector_add_del(
                is_add=False, discriminator=0x01020304
            )

    def test_sbfd_reflector_mod(self):
        """modify S-BFD reflector discriminator in place"""
        reflector = VppSBFDReflector(self, 0x01020304)
        reflector.add_vpp_config()
        for change in (
            {"admin_up": False, "required_min_rx": 1000000},
            {"admin_up": True},
            {"required_min_rx": 20000},
        ):
            reflector.modify_parameters(**change)
            verify_sbfd_reflector_config(self, reflector)
            self.assert_equal(
                len(self.vapi.bfd_udp_sbfd_reflector_dump()), 1, "number of reflectors"
            )
        reflector.remove_vpp_config()

    def test_sbfd_reflector_mod_nonexistent(self):
        """modify a non-existent S-BFD discriminator (negative case)"""
        with self.vapi.assert_negative_api_retval():
            self.vapi.bfd_udp_sbfd_reflector_mod(
                discriminator=0x01020304,
                admin_up=True,
                required_min_rx=SBFD_DEFAULT_REQUIRED_MIN_RX,
            )
        self.assert_equal(
            len(self.vapi.bfd_udp_sbfd_reflector_dump()), 0, "number of reflectors"
        )

    def test_sbfd_reflector_mod_zero_required_min_rx(self):
        """modify S-BFD discriminator to required min rx 0 (negative case)"""
        reflector = VppSBFDReflector(self, 0x01020304)
        reflector.add_vpp_config()
        with self.vapi.assert_negative_api_retval():
            self.vapi.bfd_udp_sbfd_reflector_mod(
                discriminator=reflector.discriminator, admin_up=False, required_min_rx=0
            )
        verify_sbfd_reflector_config(self, reflector)
        reflector.remove_vpp_config()

    def test_sbfd_reflector_zero_discriminator(self):
        """add S-BFD discriminator 0 (negative case)"""
        with self.vapi.assert_negative_api_retval():
            self.vapi.bfd_udp_sbfd_reflector_add_del(discriminator=0)
        self.assert_equal(
            len(self.vapi.bfd_udp_sbfd_reflector_dump()), 0, "number of reflectors"
        )

    def test_sbfd_reflector_zero_required_min_rx(self):
        """add S-BFD discriminator with required min rx 0 (negative case)"""
        with self.vapi.assert_negative_api_retval():
            self.vapi.bfd_udp_sbfd_reflector_add_del(
                discriminator=0x01020304, required_min_rx=0
            )
        self.assert_equal(
            len(self.vapi.bfd_udp_sbfd_reflector_dump()), 0, "number of reflectors"
        )

    def test_sbfd_reflector_src_address(self):
        """S-BFD reflector source addresses for replies over MPLS paths"""
        r1 = VppSBFDReflector(self, 0x01020304, src_ip4="192.0.2.20")
        r2 = VppSBFDReflector(
            self, 0xFFFFFFFF, src_ip4="192.0.2.21", src_ip6="2001:db8::21"
        )
        r1.add_vpp_config()
        r2.add_vpp_config()
        verify_sbfd_reflector_config(self, r1)
        verify_sbfd_reflector_config(self, r2)
        # in place: add a source, remove both
        r1.modify_parameters(src_ip6="2001:db8::22")
        verify_sbfd_reflector_config(self, r1)
        r2.modify_parameters(src_ip4="0.0.0.0", src_ip6="::")
        verify_sbfd_reflector_config(self, r2)
        r2.remove_vpp_config()
        for invalid in (
            {"src_ip4": "127.0.0.1"},
            {"src_ip4": "0.1.2.3"},
            {"src_ip4": "224.0.0.1"},
            {"src_ip4": "240.0.0.1"},
            {"src_ip4": "255.255.255.255"},
            {"src_ip6": "::1"},
            {"src_ip6": "::ffff:127.0.0.1"},
            {"src_ip6": "fe80::1"},
            {"src_ip6": "ff02::1"},
        ):
            with self.vapi.assert_negative_api_retval():
                self.vapi.bfd_udp_sbfd_reflector_add_del(
                    discriminator=r2.discriminator, **invalid
                )
            # rejected by mod too, before anything is changed
            with self.vapi.assert_negative_api_retval():
                self.vapi.bfd_udp_sbfd_reflector_mod(
                    discriminator=r1.discriminator,
                    admin_up=not r1.admin_up,
                    required_min_rx=r1.required_min_rx,
                    **invalid,
                )
            verify_sbfd_reflector_config(self, r1)
        # all of ::ffff:0:0/96 is no source (RFC 6890), not only
        # ::ffff:127.0.0.0/104: add and mod fail with
        # VNET_API_ERROR_INVALID_SRC_ADDRESS, as the CLI test checks too
        mapped = {"src_ip6": "::ffff:10.1.2.3"}
        invalid_src_address = -57
        with self.vapi.assert_known_api_retval([invalid_src_address]):
            self.vapi.bfd_udp_sbfd_reflector_add_del(
                discriminator=r2.discriminator, **mapped
            )
        with self.vapi.assert_known_api_retval([invalid_src_address]):
            self.vapi.bfd_udp_sbfd_reflector_mod(
                discriminator=r1.discriminator,
                admin_up=not r1.admin_up,
                required_min_rx=r1.required_min_rx,
                **mapped,
            )
        verify_sbfd_reflector_config(self, r1)
        r1.remove_vpp_config()
        self.assert_equal(
            len(self.vapi.bfd_udp_sbfd_reflector_dump()), 0, "number of reflectors"
        )

    def test_sbfd_reflector_with_classic_session(self):
        """S-BFD reflector and classic BFD session configured together"""
        session = VppBFDUDPSession(
            self,
            self.interface0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
        )
        session.add_vpp_config()
        reflector = VppSBFDReflector(self, 0x01020304)
        reflector.add_vpp_config()
        self.assert_equal(
            len(self.vapi.bfd_udp_session_dump()), 1, "number of BFD sessions"
        )
        self.assert_equal(
            len(self.vapi.bfd_udp_sbfd_reflector_dump()), 1, "number of reflectors"
        )
        reflector.remove_vpp_config()
        verify_bfd_session_config(self, session)
        reflector.add_vpp_config()
        session.remove_vpp_config()
        verify_sbfd_reflector_config(self, reflector)
        reflector.remove_vpp_config()


class BFDTestSession(object):
    """BFD session as seen from test framework side"""

    def __init__(
        self,
        test,
        interface,
        af,
        detect_mult=BFD_TEST_DETECT_MULT,
        sha1_key=None,
        bfd_key_id=None,
        our_seq_number=None,
        tunnel_header=None,
        phy_interface=None,
        multihop=False,
        local_addr=None,
        peer_addr=None,
    ):
        self.test = test
        self.af = af
        self.sha1_key = sha1_key
        self.bfd_key_id = bfd_key_id
        self.interface = interface
        if phy_interface:
            self.phy_interface = phy_interface
        else:
            self.phy_interface = self.interface
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
        self.tunnel_header = tunnel_header
        self.tx_packets = 0
        self.rx_packets = 0
        self.tx_packets_echo = 0
        self.rx_packets_echo = 0

        if multihop:
            self.sw_if_index = 0
            BFD.udp_dport = BFD_UDP_MH_PORT
        else:
            BFD.udp_dport = BFD_UDP_SH_PORT
            self.sw_if_index = self.interface.sw_if_index

        if local_addr:
            self.local_addr = local_addr
        else:
            if self.af == AF_INET:
                self.local_addr = self.interface.local_ip4
            else:
                self.local_addr = self.interface.local_ip6

        if peer_addr:
            self.peer_addr = peer_addr
        else:
            if self.af == AF_INET:
                self.peer_addr = self.interface.remote_ip4
            else:
                self.peer_addr = self.interface.remote_ip6

    def inc_seq_num(self):
        """increment sequence number, wrapping if needed"""
        if self.our_seq_number == 0xFFFFFFFF:
            self.our_seq_number = 0
        else:
            self.our_seq_number += 1

    def update(
        self,
        my_discriminator=None,
        your_discriminator=None,
        desired_min_tx=None,
        required_min_rx=None,
        required_min_echo_rx=None,
        detect_mult=None,
        diag=None,
        state=None,
        auth_type=None,
    ):
        """update BFD parameters associated with session"""
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
        """set packet fields with known values in packet"""
        bfd = packet[BFD]
        if self.my_discriminator:
            self.test.logger.debug(
                "BFD: setting packet.my_discriminator=%s", self.my_discriminator
            )
            bfd.my_discriminator = self.my_discriminator
        if self.your_discriminator:
            self.test.logger.debug(
                "BFD: setting packet.your_discriminator=%s", self.your_discriminator
            )
            bfd.your_discriminator = self.your_discriminator
        if self.required_min_rx:
            self.test.logger.debug(
                "BFD: setting packet.required_min_rx_interval=%s", self.required_min_rx
            )
            bfd.required_min_rx_interval = self.required_min_rx
        if self.required_min_echo_rx:
            self.test.logger.debug(
                "BFD: setting packet.required_min_echo_rx=%s", self.required_min_echo_rx
            )
            bfd.required_min_echo_rx_interval = self.required_min_echo_rx
        if self.desired_min_tx:
            self.test.logger.debug(
                "BFD: setting packet.desired_min_tx_interval=%s", self.desired_min_tx
            )
            bfd.desired_min_tx_interval = self.desired_min_tx
        if self.detect_mult:
            self.test.logger.debug(
                "BFD: setting packet.detect_mult=%s", self.detect_mult
            )
            bfd.detect_mult = self.detect_mult
        if self.diag:
            self.test.logger.debug("BFD: setting packet.diag=%s", self.diag)
            bfd.diag = self.diag
        if self.state:
            self.test.logger.debug("BFD: setting packet.state=%s", self.state)
            bfd.state = self.state
        if self.auth_type:
            # this is used by a negative test-case
            self.test.logger.debug("BFD: setting packet.auth_type=%s", self.auth_type)
            bfd.auth_type = self.auth_type

    def create_packet(self):
        """create a BFD packet, reflecting the current state of session"""
        if self.sha1_key:
            bfd = BFD(flags="A")
            bfd.auth_type = self.sha1_key.auth_type
            bfd.auth_len = BFD.sha1_auth_len
            bfd.auth_key_id = self.bfd_key_id
            bfd.auth_seq_num = self.our_seq_number
            bfd.length = BFD.sha1_auth_len + BFD.bfd_pkt_len
        else:
            bfd = BFD()
        packet = Ether(
            src=self.phy_interface.remote_mac, dst=self.phy_interface.local_mac
        )
        if self.tunnel_header:
            packet = packet / self.tunnel_header
        if self.af == AF_INET6:
            packet = (
                packet
                / IPv6(
                    src=self.peer_addr,
                    dst=self.local_addr,
                    hlim=255,
                )
                / UDP(sport=self.udp_sport, dport=BFD.udp_dport)
                / bfd
            )
        else:
            packet = (
                packet
                / IP(src=self.peer_addr, dst=self.local_addr, ttl=255)
                / UDP(sport=self.udp_sport, dport=BFD.udp_dport)
                / bfd
            )
        self.test.logger.debug("BFD: Creating packet")
        self.fill_packet_fields(packet)
        if self.sha1_key:
            hash_material = (
                scapy.compat.raw(packet[BFD])[:32]
                + self.sha1_key.key
                + b"\0" * (20 - len(self.sha1_key.key))
            )
            self.test.logger.debug(
                "BFD: Calculated SHA1 hash: %s"
                % hashlib.sha1(hash_material).hexdigest()
            )
            packet[BFD].auth_key_hash = hashlib.sha1(hash_material).digest()
        return packet

    def send_packet(self, packet=None, interface=None):
        """send packet on interface, creating the packet if needed"""
        if packet is None:
            packet = self.create_packet()
        if interface is None:
            interface = self.phy_interface
        self.test.logger.debug(ppp("Sending packet:", packet))
        interface.add_stream(packet)
        self.tx_packets += 1
        self.test.pg_start()

    def verify_sha1_auth(self, packet):
        """Verify correctness of authentication in BFD layer."""
        bfd = packet[BFD]
        self.test.assert_equal(bfd.auth_len, 28, "Auth section length")
        self.test.assert_equal(bfd.auth_type, self.sha1_key.auth_type, BFDAuthType)
        self.test.assert_equal(bfd.auth_key_id, self.bfd_key_id, "Key ID")
        self.test.assert_equal(bfd.auth_reserved, 0, "Reserved")
        if self.vpp_seq_number is None:
            self.vpp_seq_number = bfd.auth_seq_num
            self.test.logger.debug(
                "Received initial sequence number: %s" % self.vpp_seq_number
            )
        else:
            recvd_seq_num = bfd.auth_seq_num
            self.test.logger.debug(
                "Received followup sequence number: %s" % recvd_seq_num
            )
            if self.vpp_seq_number < 0xFFFFFFFF:
                if self.sha1_key.auth_type == BFDAuthType.meticulous_keyed_sha1:
                    self.test.assert_equal(
                        recvd_seq_num, self.vpp_seq_number + 1, "BFD sequence number"
                    )
                else:
                    self.test.assert_in_range(
                        recvd_seq_num,
                        self.vpp_seq_number,
                        self.vpp_seq_number + 1,
                        "BFD sequence number",
                    )
            else:
                if self.sha1_key.auth_type == BFDAuthType.meticulous_keyed_sha1:
                    self.test.assert_equal(recvd_seq_num, 0, "BFD sequence number")
                else:
                    self.test.assertIn(
                        recvd_seq_num,
                        (self.vpp_seq_number, 0),
                        "BFD sequence number not one of "
                        "(%s, 0)" % self.vpp_seq_number,
                    )
            self.vpp_seq_number = recvd_seq_num
        # last 20 bytes represent the hash - so replace them with the key,
        # pad the result with zeros and hash the result
        hash_material = (
            bfd.original[:-20]
            + self.sha1_key.key
            + b"\0" * (20 - len(self.sha1_key.key))
        )
        expected_hash = hashlib.sha1(hash_material).hexdigest()
        self.test.assert_equal(
            binascii.hexlify(bfd.auth_key_hash), expected_hash.encode(), "Auth key hash"
        )

    def verify_bfd(self, packet):
        """Verify correctness of BFD layer."""
        bfd = packet[BFD]
        self.test.assert_equal(bfd.version, 1, "BFD version")
        self.test.assert_equal(
            bfd.your_discriminator, self.my_discriminator, "BFD - your discriminator"
        )
        if self.sha1_key:
            self.verify_sha1_auth(packet)


class SBFDTestInitiator(BFDTestSession):
    """S-BFD initiator as seen from test framework side"""

    def __init__(
        self,
        test,
        interface,
        af,
        reflector,
        multihop=False,
        ttl=None,
        reply_src=None,
        **kwargs,
    ):
        super(SBFDTestInitiator, self).__init__(
            test, interface, af, multihop=multihop, **kwargs
        )
        self.reflector = reflector
        self.multihop = multihop
        # TTL or hop limit of the requests, if not the usual 255 or 254
        self.ttl = ttl
        # expected source of the replies, if not the requests' destination
        self.reply_src = reply_src if reply_src else self.local_addr
        self.my_discriminator = randint(1, 0xFFFFFFFF)
        self.your_discriminator = reflector.discriminator
        # values the reflector must not echo back
        self.required_min_rx = 0
        self.required_min_echo_rx = 70000
        self.diag = BFDDiagCode.neighbor_signaled_session_down
        # value the reflector must copy
        self.desired_min_tx = 150000

    def create_packet(self):
        """create an S-BFD request for the reflector discriminator"""
        packet = super(SBFDTestInitiator, self).create_packet()
        packet[UDP].dport = BFD_UDP_SBFD_PORT
        packet[BFD].flags |= "D"
        ttl = self.ttl
        if ttl is None and self.multihop:
            ttl = 254
        if ttl is not None:
            if self.af == AF_INET6:
                packet[IPv6].hlim = ttl
            else:
                packet[IP].ttl = ttl
        return packet

    def verify_bfd(self, packet, poll=False):
        """Verify correctness of BFD layer of an S-BFD reply."""
        super(SBFDTestInitiator, self).verify_bfd(packet)
        bfd = packet[BFD]
        reflector = self.reflector
        self.test.assert_equal(
            bfd.my_discriminator, reflector.discriminator, "BFD - my discriminator"
        )
        if reflector.admin_up:
            self.test.assert_equal(bfd.state, BFDState.up, BFDState)
            self.test.assert_equal(bfd.diag, BFDDiagCode.no_diagnostic, BFDDiagCode)
        else:
            self.test.assert_equal(bfd.state, BFDState.admin_down, BFDState)
            self.test.assert_equal(
                bfd.diag, BFDDiagCode.administratively_down, BFDDiagCode
            )
        self.test.assert_equal(str(bfd.flags), "F" if poll else "", "BFD flags")
        self.test.assert_equal(bfd.detect_mult, self.detect_mult, "detect multiplier")
        self.test.assert_equal(bfd.length, BFD.bfd_pkt_len, "BFD length")
        self.test.assert_equal(
            bfd.desired_min_tx_interval, self.desired_min_tx, "desired min tx"
        )
        self.test.assert_equal(
            bfd.required_min_rx_interval, reflector.required_min_rx, "required min rx"
        )
        self.test.assert_equal(
            bfd.required_min_echo_rx_interval, 0, "required min echo rx"
        )
        self.test.assertFalse(bfd.payload, "unexpected payload after BFD")


def bfd_session_up(test):
    """Bring BFD session up"""
    test.logger.info("BFD: Waiting for slow hello")
    p = wait_for_bfd_packet(test, 2, is_tunnel=test.vpp_session.is_tunnel)
    old_offset = None
    if hasattr(test, "vpp_clock_offset"):
        old_offset = test.vpp_clock_offset
    test.vpp_clock_offset = time.time() - float(p.time)
    test.logger.debug("BFD: Calculated vpp clock offset: %s", test.vpp_clock_offset)
    if old_offset:
        test.assertAlmostEqual(
            old_offset,
            test.vpp_clock_offset,
            delta=0.5,
            msg="vpp clock offset not stable (new: %s, old: %s)"
            % (test.vpp_clock_offset, old_offset),
        )
    test.logger.info("BFD: Sending Init")
    test.test_session.update(
        my_discriminator=randint(0, 40000000),
        your_discriminator=p[BFD].my_discriminator,
        state=BFDState.init,
    )
    if (
        test.test_session.sha1_key
        and test.test_session.sha1_key.auth_type == BFDAuthType.meticulous_keyed_sha1
    ):
        test.test_session.inc_seq_num()
    test.test_session.send_packet()
    test.logger.info("BFD: Waiting for event")
    e = test.vapi.wait_for_event(1, "bfd_udp_session_event")
    verify_event(test, e, expected_state=BFDState.up)
    test.logger.info("BFD: Session is Up")
    test.test_session.update(state=BFDState.up)
    if (
        test.test_session.sha1_key
        and test.test_session.sha1_key.auth_type == BFDAuthType.meticulous_keyed_sha1
    ):
        test.test_session.inc_seq_num()
    test.test_session.send_packet()
    test.assert_equal(test.vpp_session.state, BFDState.up, BFDState)


def bfd_session_down(test):
    """Bring BFD session down"""
    test.assert_equal(test.vpp_session.state, BFDState.up, BFDState)
    test.test_session.update(state=BFDState.down)
    if (
        test.test_session.sha1_key
        and test.test_session.sha1_key.auth_type == BFDAuthType.meticulous_keyed_sha1
    ):
        test.test_session.inc_seq_num()
    test.test_session.send_packet()
    test.logger.info("BFD: Waiting for event")
    e = test.vapi.wait_for_event(1, "bfd_udp_session_event")
    verify_event(test, e, expected_state=BFDState.down)
    test.logger.info("BFD: Session is Down")
    test.assert_equal(test.vpp_session.state, BFDState.down, BFDState)


def verify_bfd_session_config(test, session, state=None):
    dump = session.get_bfd_udp_session_dump_entry()
    test.assertIsNotNone(dump)
    # since dump is not none, we have verified that sw_if_index and addresses
    # are valid (in get_bfd_udp_session_dump_entry)
    if state is not None:
        test.assert_equal(dump.state, state, "session state")
    test.assert_equal(
        dump.required_min_rx, session.required_min_rx, "required min rx interval"
    )
    test.assert_equal(
        dump.desired_min_tx, session.desired_min_tx, "desired min tx interval"
    )
    test.assert_equal(dump.detect_mult, session.detect_mult, "detect multiplier")
    if session.sha1_key is None:
        test.assert_equal(dump.is_authenticated, 0, "is_authenticated flag")
    else:
        test.assert_equal(dump.is_authenticated, 1, "is_authenticated flag")
        test.assert_equal(dump.bfd_key_id, session.bfd_key_id, "bfd key id")
        test.assert_equal(
            dump.conf_key_id, session.sha1_key.conf_key_id, "config key id"
        )


def verify_sbfd_reflector_config(test, reflector):
    dump = reflector.get_bfd_udp_sbfd_reflector_dump_entry()
    test.assertIsNotNone(dump)
    test.assert_equal(dump.admin_up, reflector.admin_up, "admin up flag")
    test.assert_equal(
        dump.required_min_rx, reflector.required_min_rx, "required min rx interval"
    )
    test.assert_equal(
        dump.src_ip4,
        ipaddress.IPv4Address(reflector.src_ip4 or "0.0.0.0"),
        "IPv4 source address",
    )
    test.assert_equal(
        dump.src_ip6,
        ipaddress.IPv6Address(reflector.src_ip6 or "::"),
        "IPv6 source address",
    )


def verify_ip(test, packet, expected_tos=None, session=None, src=None):
    """Verify correctness of IP layer."""
    if session is None:
        session = test.vpp_session
    if session.af == AF_INET6:
        ip = packet[IPv6]
        local_ip = session.local_addr
        remote_ip = session.peer_addr
        test.assert_equal(ip.hlim, 255, "IPv6 hop limit")
        if expected_tos is not None:
            test.assert_equal(ip.tc, expected_tos, "IPv6 TOS")
    else:
        ip = packet[IP]
        local_ip = session.local_addr
        remote_ip = session.peer_addr
        test.assert_equal(ip.ttl, 255, "IPv4 TTL")
        if expected_tos is not None:
            test.assert_equal(ip.tos, expected_tos, "IPv4 TOS")
    if src is not None:
        local_ip = src
    test.assert_equal(ip.src, local_ip, "IP source address")
    test.assert_equal(ip.dst, remote_ip, "IP destination address")


def verify_udp(test, packet, sport=None, dport=None):
    """Verify correctness of UDP layer."""
    udp = packet[UDP]
    if dport is None:
        dport = BFD.udp_dport
    test.assert_equal(udp.dport, dport, "UDP destination port")
    if sport is None:
        test.assert_in_range(
            udp.sport, BFD.udp_sport_min, BFD.udp_sport_max, "UDP source port"
        )
    else:
        test.assert_equal(udp.sport, sport, "UDP source port")


def verify_event(test, event, expected_state):
    """Verify correctness of event values."""
    e = event
    test.logger.debug("BFD: Event: %s" % reprlib.repr(e))
    test.assert_equal(
        e.sw_if_index, test.vpp_session._sw_if_index, "BFD interface index"
    )

    test.assert_equal(
        str(e.local_addr), test.vpp_session.local_addr, "Local IPv6 address"
    )
    test.assert_equal(str(e.peer_addr), test.vpp_session.peer_addr, "Peer IPv6 address")
    test.assert_equal(e.state, expected_state, BFDState)


def wait_for_bfd_packet(
    test, timeout=2, pcap_time_min=None, is_tunnel=False, expected_tos=None
):
    """wait for BFD packet and verify its correctness

    :param timeout: how long to wait
    :param pcap_time_min: ignore packets with pcap timestamp lower than this
    :param expected_tos: expected TOS/TC value for IP verification

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
        test.test_session.rx_packets += 1
        test.logger.debug(ppp("BFD: Got packet:", p))
        if pcap_time_min is not None and p.time < pcap_time_min:
            test.logger.debug(
                ppp(
                    "BFD: ignoring packet (pcap time %s < "
                    "pcap time min %s):" % (p.time, pcap_time_min),
                    p,
                )
            )
        else:
            break
    test.logger.debug(test.vapi.ppcli("show trace"))
    if is_tunnel:
        # strip an IP layer and move to the next
        p = p[IP].payload

    bfd = p[BFD]
    if bfd is None:
        raise Exception(ppp("Unexpected or invalid BFD packet:", p))
    if bfd.payload:
        raise Exception(ppp("Unexpected payload in BFD packet:", bfd))
    verify_ip(test, p, expected_tos)
    verify_udp(test, p)
    test.test_session.verify_bfd(p)
    return p


BFDStats = namedtuple("BFDStats", "rx rx_echo tx tx_echo")


def bfd_grab_stats_snapshot(test, bs_idx=0, thread_index=None):
    s = test.statistics
    ti = thread_index
    if ti is None:
        rx = s["/bfd/rx-session-counters"][:, bs_idx].sum_packets()
        rx_echo = s["/bfd/rx-session-echo-counters"][:, bs_idx].sum_packets()
        tx = s["/bfd/tx-session-counters"][:, bs_idx].sum_packets()
        tx_echo = s["/bfd/tx-session-echo-counters"][:, bs_idx].sum_packets()
    else:
        rx = s["/bfd/rx-session-counters"][ti, bs_idx].sum_packets()
        rx_echo = s["/bfd/rx-session-echo-counters"][ti, bs_idx].sum_packets()
        tx = s["/bfd/tx-session-counters"][ti, bs_idx].sum_packets()
        tx_echo = s["/bfd/tx-session-echo-counters"][ti, bs_idx].sum_packets()
    return BFDStats(rx, rx_echo, tx, tx_echo)


def bfd_stats_diff(stats_before, stats_after):
    rx = stats_after.rx - stats_before.rx
    rx_echo = stats_after.rx_echo - stats_before.rx_echo
    tx = stats_after.tx - stats_before.tx
    tx_echo = stats_after.tx_echo - stats_before.tx_echo
    return BFDStats(rx, rx_echo, tx, tx_echo)


def is_not_sbfd_reply(p):
    """capture filter which keeps only S-BFD replies"""
    return is_ipv6_misc(p) or not (
        p.haslayer(UDP) and p[UDP].sport == BFD_UDP_SBFD_PORT
    )


def wait_for_sbfd_reply(test, initiator, interface, poll=False, timeout=2):
    """wait for S-BFD reply to initiator and verify its correctness"""
    p = interface.wait_for_packet(timeout, filter_out_fn=is_not_sbfd_reply)
    test.logger.debug(ppp("S-BFD: Got reply:", p))
    verify_ip(
        test,
        p,
        expected_tos=test.vapi.bfd_udp_get_tos().tos,
        session=initiator,
        src=initiator.reply_src,
    )
    verify_udp(test, p, sport=BFD_UDP_SBFD_PORT, dport=initiator.udp_sport)
    test.assert_packet_checksums_valid(p)
    initiator.verify_bfd(p, poll)
    return p


def verify_no_sbfd_reply(test, interface, timeout=1):
    """verify that no S-BFD reply is sent out of interface"""
    with test.assertRaises(CaptureTimeoutError):
        interface.wait_for_packet(timeout, filter_out_fn=is_not_sbfd_reply)


def sbfd_err_counter(test, af, name, node="input"):
    """read counter of the S-BFD reflector "input" or "dpo" node"""
    family = 6 if af == AF_INET6 else 4
    return test.statistics.get_err_counter(
        "/err/bfd-sbfd-reflector%d-%s/%s" % (family, node, name)
    )


def sbfd_reflector_coexistence(test):
    """S-BFD reflector answers while classic BFD session stays up"""
    bfd_session_up(test)
    classic_disc = test.test_session.your_discriminator
    discriminator = randint(1, 0xFFFFFFFF)
    while discriminator == classic_disc:
        discriminator = randint(1, 0xFFFFFFFF)
    reflector = VppSBFDReflector(test, discriminator)
    reflector.add_vpp_config()
    initiator = SBFDTestInitiator(
        test,
        test.pg0,
        test.test_session.af,
        reflector,
        multihop=test.multihop,
        local_addr=test.test_session.local_addr,
        peer_addr=test.test_session.peer_addr,
    )
    if test.test_session.af == AF_INET6:
        mpls_path_dst, reply_src = SBFD_MPLS_PATH_DST6[0], test.pg0.local_ip6
    else:
        mpls_path_dst, reply_src = SBFD_MPLS_PATH_DST4[0], test.pg0.local_ip4
    mpls_path = SBFDTestInitiator(
        test,
        test.pg0,
        test.test_session.af,
        reflector,
        multihop=test.multihop,
        local_addr=mpls_path_dst,
        peer_addr=test.test_session.peer_addr,
        ttl=1,
        reply_src=reply_src,
    )
    for dummy in range(test.test_session.detect_mult * 2):
        wait_for_bfd_packet(test)
        test.test_session.send_packet()
        initiator.send_packet()
        wait_for_sbfd_reply(test, initiator, test.pg0)
        mpls_path.send_packet()
        wait_for_sbfd_reply(test, mpls_path, test.pg0)
    # the classic session's discriminator is not an S-BFD discriminator
    no_disc = sbfd_err_counter(test, initiator.af, "no_disc")
    initiator.update(your_discriminator=classic_disc)
    initiator.send_packet()
    verify_no_sbfd_reply(test, test.pg0)
    test.assert_equal(
        sbfd_err_counter(test, initiator.af, "no_disc"), no_disc + 1, "no_disc"
    )
    test.assert_equal(len(test.vapi.collect_events()), 0, "number of bfd events")
    test.assert_equal(test.vpp_session.state, BFDState.up, BFDState)


@parameterized_class(
    [
        {"multihop": False},
        {"multihop": True},
    ]
)
@tag_run_solo
class BFD4TestCase(VppTestCase):
    """BFD v4 test"""

    pg0 = None
    interface0 = None
    vpp_clock_offset = None
    vpp_session = None
    test_session = None
    src_ip_net = ""
    dst_ip_net = ""

    @classmethod
    def setUpClass(cls):
        super(BFD4TestCase, cls).setUpClass()
        hoptype_str = "MultiHop" if cls.multihop else "SingleHop"
        cls.__doc__ = (
            f"""""Bidirectional Forwarding Detection (BFD) - IPv4, {hoptype_str}"""
        )
        cls.vapi.cli("set log class bfd level debug")
        try:
            cls.create_pg_interfaces([0])
            cls.create_loopback_interfaces(1)
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

    @classmethod
    def tearDownClass(cls):
        super(BFD4TestCase, cls).tearDownClass()

    def setUp(self):
        super(BFD4TestCase, self).setUp()
        self.factory = AuthKeyFactory()
        self.vapi.want_bfd_events()
        self.pg0.enable_capture()
        set_ipv4_pfx_route_info(self, self.pg0, BFD_IPV4_REMOTE_ADDR, True)

        try:
            if self.multihop:
                self.interface0 = None
                self.bfd_udp4_sessions = self.statistics[BFD_STATS_V4_MH_PATH]
                self.bfd_udp6_sessions = self.statistics[BFD_STATS_V6_MH_PATH]
            else:
                self.interface0 = self.pg0
                self.bfd_udp4_sessions = self.statistics[BFD_STATS_V4_SH_PATH]
                self.bfd_udp6_sessions = self.statistics[BFD_STATS_V6_SH_PATH]

            self.vapi.cli("trace add bfd-process 500")
            self.vpp_session = VppBFDUDPSession(
                self,
                self.interface0,
                self.dst_ip_net,
                local_addr=self.src_ip_net,
                multihop=self.multihop,
            )
            self.vpp_session.add_vpp_config()
            self.vpp_session.admin_up()
            self.test_session = BFDTestSession(
                self,
                self.pg0,
                AF_INET,
                local_addr=self.src_ip_net,
                peer_addr=self.dst_ip_net,
                multihop=self.multihop,
            )
        except BaseException:
            self.vapi.want_bfd_events(enable_disable=0)
            raise

    def tearDown(self):
        if not self.vpp_dead:
            self.vapi.want_bfd_events(enable_disable=0)
        self.vapi.collect_events()  # clear the event queue
        super(BFD4TestCase, self).tearDown()

    def test_session_up(self):
        """bring BFD session up"""
        bfd_session_up(self)
        if self.multihop:
            bfd_udp4_sessions = self.statistics[BFD_STATS_V4_MH_PATH]
            bfd_udp6_sessions = self.statistics[BFD_STATS_V6_MH_PATH]
        else:
            bfd_udp4_sessions = self.statistics[BFD_STATS_V4_SH_PATH]
            bfd_udp6_sessions = self.statistics[BFD_STATS_V6_SH_PATH]

        self.assert_equal(bfd_udp4_sessions - self.bfd_udp4_sessions, 1)
        self.assert_equal(bfd_udp6_sessions, self.bfd_udp6_sessions)

    def test_session_up_by_ip(self):
        """bring BFD session up - first frame looked up by address pair"""
        self.logger.info("BFD: Sending Slow control frame")
        self.test_session.update(my_discriminator=randint(0, 40000000))
        self.test_session.send_packet()
        self.pg0.enable_capture()
        p = self.pg0.wait_for_packet(1)
        self.assert_equal(
            p[BFD].your_discriminator,
            self.test_session.my_discriminator,
            "BFD - your discriminator",
        )
        self.assert_equal(p[BFD].state, BFDState.init, BFDState)
        self.test_session.update(
            your_discriminator=p[BFD].my_discriminator, state=BFDState.up
        )
        self.logger.info("BFD: Waiting for event")
        e = self.vapi.wait_for_event(1, "bfd_udp_session_event")
        verify_event(self, e, expected_state=BFDState.init)
        self.logger.info("BFD: Sending Up")
        self.test_session.send_packet()
        self.logger.info("BFD: Waiting for event")
        e = self.vapi.wait_for_event(1, "bfd_udp_session_event")
        verify_event(self, e, expected_state=BFDState.up)
        self.logger.info("BFD: Session is Up")
        self.test_session.update(state=BFDState.up)
        self.test_session.send_packet()
        self.assert_equal(self.vpp_session.state, BFDState.up, BFDState)

    def test_session_down(self):
        """bring BFD session down"""
        bfd_session_up(self)
        bfd_session_down(self)

    def test_hold_up(self):
        """hold BFD session up"""
        bfd_session_up(self)
        for dummy in range(self.test_session.detect_mult * 2):
            wait_for_bfd_packet(self)
            self.test_session.send_packet()
        self.assert_equal(len(self.vapi.collect_events()), 0, "number of bfd events")

    def test_sbfd_reflector_coexistence(self):
        """S-BFD reflector next to an Up BFD session"""
        sbfd_reflector_coexistence(self)

    def test_slow_timer(self):
        """verify slow periodic control frames while session down"""
        packet_count = 3
        self.logger.info("BFD: Waiting for %d BFD packets", packet_count)
        prev_packet = wait_for_bfd_packet(self, 2)
        for dummy in range(packet_count):
            next_packet = wait_for_bfd_packet(self, 2)
            time_diff = next_packet.time - prev_packet.time
            # spec says the range should be <0.75, 1>, allow extra 0.05 margin
            # to work around timing issues
            self.assert_in_range(time_diff, 0.70, 1.05, "time between slow packets")
            prev_packet = next_packet

    def test_zero_remote_min_rx(self):
        """no packets when zero remote required min rx interval"""
        bfd_session_up(self)
        self.test_session.update(required_min_rx=0)
        self.test_session.send_packet()
        for dummy in range(self.test_session.detect_mult):
            self.sleep(
                self.vpp_session.required_min_rx / USEC_IN_SEC,
                "sleep before transmitting bfd packet",
            )
            self.test_session.send_packet()
            try:
                p = wait_for_bfd_packet(self, timeout=0)
                self.logger.error(ppp("Received unexpected packet:", p))
            except CaptureTimeoutError:
                pass
        self.assert_equal(len(self.vapi.collect_events()), 0, "number of bfd events")
        self.test_session.update(required_min_rx=300000)
        for dummy in range(3):
            self.test_session.send_packet()
            wait_for_bfd_packet(
                self, timeout=self.test_session.required_min_rx / USEC_IN_SEC
            )
        self.assert_equal(len(self.vapi.collect_events()), 0, "number of bfd events")

    def test_conn_down(self):
        """verify session goes down after inactivity"""
        bfd_session_up(self)
        detection_time = (
            self.test_session.detect_mult
            * self.vpp_session.required_min_rx
            / USEC_IN_SEC
        )
        self.sleep(detection_time, "waiting for BFD session time-out")
        e = self.vapi.wait_for_event(1, "bfd_udp_session_event")
        verify_event(self, e, expected_state=BFDState.down)

    def test_peer_discr_reset_sess_down(self):
        """peer discriminator reset after session goes down"""
        bfd_session_up(self)
        detection_time = (
            self.test_session.detect_mult
            * self.vpp_session.required_min_rx
            / USEC_IN_SEC
        )
        self.sleep(detection_time, "waiting for BFD session time-out")
        self.test_session.my_discriminator = 0
        wait_for_bfd_packet(self, pcap_time_min=time.time() - self.vpp_clock_offset)

    def test_large_required_min_rx(self):
        """large remote required min rx interval"""
        bfd_session_up(self)
        p = wait_for_bfd_packet(self)
        interval = 3000000
        # Keep the detection timeout below the requested transmit interval.
        self.test_session.update(required_min_rx=interval, detect_mult=3)
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
        """immediately honor remote required min rx reduction"""
        self.vpp_session.remove_vpp_config()
        self.vpp_session = VppBFDUDPSession(
            self,
            self.interface0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
            desired_min_tx=10000,
        )
        self.pg0.enable_capture()
        self.vpp_session.add_vpp_config()
        self.test_session.update(desired_min_tx=1000000, required_min_rx=1000000)
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
        self.assert_in_range(
            p.time - reference_packet.time,
            0.95 * 0.75 * interval / USEC_IN_SEC,
            1.05 * interval / USEC_IN_SEC + extra_time,
            "time between BFD packets",
        )
        reference_packet = p
        for dummy in range(3):
            p = wait_for_bfd_packet(self)
            diff = p.time - reference_packet.time
            self.assert_in_range(
                diff,
                0.95 * 0.75 * interval / USEC_IN_SEC,
                1.05 * interval / USEC_IN_SEC,
                "time between BFD packets",
            )
            reference_packet = p

    def test_modify_req_min_rx_double(self):
        """modify session - double required min rx"""
        bfd_session_up(self)
        p = wait_for_bfd_packet(self)
        self.test_session.update(desired_min_tx=10000, required_min_rx=10000)
        self.test_session.send_packet()
        # double required min rx
        self.vpp_session.modify_parameters(
            required_min_rx=2 * self.vpp_session.required_min_rx
        )
        p = wait_for_bfd_packet(self, pcap_time_min=time.time() - self.vpp_clock_offset)
        # poll bit needs to be set
        self.assertIn("P", p.sprintf("%BFD.flags%"), "Poll bit not set in BFD packet")
        # finish poll sequence with final packet
        final = self.test_session.create_packet()
        final[BFD].flags = "F"
        timeout = (
            self.test_session.detect_mult
            * max(self.test_session.desired_min_tx, self.vpp_session.required_min_rx)
            / USEC_IN_SEC
        )
        self.test_session.send_packet(final)
        time_mark = time.time()
        e = self.vapi.wait_for_event(2 * timeout, "bfd_udp_session_event")
        verify_event(self, e, expected_state=BFDState.down)
        time_to_event = time.time() - time_mark
        self.assert_in_range(
            time_to_event, 0.9 * timeout, 1.25 * timeout, "session timeout"
        )

    def test_modify_req_min_rx_halve(self):
        """modify session - halve required min rx"""
        self.vpp_session.modify_parameters(
            required_min_rx=2 * self.vpp_session.required_min_rx
        )
        bfd_session_up(self)
        p = wait_for_bfd_packet(self)
        self.test_session.update(desired_min_tx=10000, required_min_rx=10000)
        self.test_session.send_packet()
        p = wait_for_bfd_packet(self, pcap_time_min=time.time() - self.vpp_clock_offset)
        # halve required min rx
        old_required_min_rx = self.vpp_session.required_min_rx
        self.vpp_session.modify_parameters(
            required_min_rx=self.vpp_session.required_min_rx // 2
        )
        # now we wait 0.8*3*old-req-min-rx and the session should still be up
        self.sleep(
            0.8 * self.vpp_session.detect_mult * old_required_min_rx / USEC_IN_SEC,
            "wait before finishing poll sequence",
        )
        self.assert_equal(len(self.vapi.collect_events()), 0, "number of bfd events")
        p = wait_for_bfd_packet(self)
        # poll bit needs to be set
        self.assertIn("P", p.sprintf("%BFD.flags%"), "Poll bit not set in BFD packet")
        # finish poll sequence with final packet
        final = self.test_session.create_packet()
        final[BFD].flags = "F"
        self.test_session.send_packet(final)
        # now the session should time out under new conditions
        detection_time = (
            self.test_session.detect_mult
            * self.vpp_session.required_min_rx
            / USEC_IN_SEC
        )
        before = time.time()
        e = self.vapi.wait_for_event(2 * detection_time, "bfd_udp_session_event")
        after = time.time()
        self.assert_in_range(
            after - before,
            0.9 * detection_time,
            1.1 * detection_time,
            "time before bfd session goes down",
        )
        verify_event(self, e, expected_state=BFDState.down)

    def test_modify_detect_mult(self):
        """modify detect multiplier"""
        bfd_session_up(self)
        p = wait_for_bfd_packet(self)
        self.vpp_session.modify_parameters(detect_mult=1)
        p = wait_for_bfd_packet(self, pcap_time_min=time.time() - self.vpp_clock_offset)
        self.assert_equal(
            self.vpp_session.detect_mult, p[BFD].detect_mult, "detect mult"
        )
        # poll bit must not be set
        self.assertNotIn(
            "P", p.sprintf("%BFD.flags%"), "Poll bit not set in BFD packet"
        )
        self.vpp_session.modify_parameters(detect_mult=10)
        p = wait_for_bfd_packet(self, pcap_time_min=time.time() - self.vpp_clock_offset)
        self.assert_equal(
            self.vpp_session.detect_mult, p[BFD].detect_mult, "detect mult"
        )
        # poll bit must not be set
        self.assertNotIn(
            "P", p.sprintf("%BFD.flags%"), "Poll bit not set in BFD packet"
        )

    def test_queued_poll(self):
        """test poll sequence queueing"""
        bfd_session_up(self)
        p = wait_for_bfd_packet(self)
        self.vpp_session.modify_parameters(
            required_min_rx=2 * self.vpp_session.required_min_rx
        )
        p = wait_for_bfd_packet(self)
        poll_sequence_start = time.time()
        poll_sequence_length_min = 0.5
        send_final_after = time.time() + poll_sequence_length_min
        # poll bit needs to be set
        self.assertIn("P", p.sprintf("%BFD.flags%"), "Poll bit not set in BFD packet")
        self.assert_equal(
            p[BFD].required_min_rx_interval,
            self.vpp_session.required_min_rx,
            "BFD required min rx interval",
        )
        self.vpp_session.modify_parameters(
            required_min_rx=2 * self.vpp_session.required_min_rx
        )
        # 2nd poll sequence should be queued now
        # don't send the reply back yet, wait for some time to emulate
        # longer round-trip time
        packet_count = 0
        while time.time() < send_final_after:
            self.test_session.send_packet()
            p = wait_for_bfd_packet(self)
            self.assert_equal(
                len(self.vapi.collect_events()), 0, "number of bfd events"
            )
            self.assert_equal(
                p[BFD].required_min_rx_interval,
                self.vpp_session.required_min_rx,
                "BFD required min rx interval",
            )
            packet_count += 1
            # poll bit must be set
            self.assertIn(
                "P", p.sprintf("%BFD.flags%"), "Poll bit not set in BFD packet"
            )
        final = self.test_session.create_packet()
        final[BFD].flags = "F"
        self.test_session.send_packet(final)
        # finish 1st with final
        poll_sequence_length = time.time() - poll_sequence_start
        # vpp must wait for some time before starting new poll sequence
        poll_no_2_started = False
        for dummy in range(2 * packet_count):
            p = wait_for_bfd_packet(self)
            self.assert_equal(
                len(self.vapi.collect_events()), 0, "number of bfd events"
            )
            if "P" in p.sprintf("%BFD.flags%"):
                poll_no_2_started = True
                if time.time() < poll_sequence_start + poll_sequence_length:
                    raise Exception("VPP started 2nd poll sequence too soon")
                final = self.test_session.create_packet()
                final[BFD].flags = "F"
                self.test_session.send_packet(final)
                break
            else:
                self.test_session.send_packet()
        self.assertTrue(poll_no_2_started, "2nd poll sequence not performed")
        # finish 2nd with final
        final = self.test_session.create_packet()
        final[BFD].flags = "F"
        self.test_session.send_packet(final)
        p = wait_for_bfd_packet(self)
        # poll bit must not be set
        self.assertNotIn("P", p.sprintf("%BFD.flags%"), "Poll bit set in BFD packet")

    # returning inconsistent results requiring retries in per-patch tests
    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_poll_response(self):
        """test correct response to control frame with poll bit set"""
        bfd_session_up(self)
        poll = self.test_session.create_packet()
        poll[BFD].flags = "P"
        # Record the cutoff before sending the poll.  VPP can produce the
        # final response before send_packet() returns; computing it afterwards
        # can therefore discard the response we are trying to validate.
        pcap_time_min = time.time() - self.vpp_clock_offset
        self.test_session.send_packet(poll)
        final = wait_for_bfd_packet(self, pcap_time_min=pcap_time_min)
        self.assertIn("F", final.sprintf("%BFD.flags%"))

    def test_no_periodic_if_remote_demand(self):
        """no periodic frames outside poll sequence if remote demand set"""
        bfd_session_up(self)
        demand = self.test_session.create_packet()
        demand[BFD].flags = "D"
        self.test_session.send_packet(demand)
        transmit_time = (
            0.9
            * max(self.vpp_session.required_min_rx, self.test_session.desired_min_tx)
            / USEC_IN_SEC
        )
        count = 0
        for dummy in range(self.test_session.detect_mult * 2):
            self.sleep(transmit_time)
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
        """echo packets looped back"""

        if self.multihop:
            self.skipTest(
                f"Skipping because echo functionality is not supported with multihop"
            )

        bfd_session_up(self)
        stats_before = bfd_grab_stats_snapshot(self)
        self.pg0.enable_capture()
        echo_packet_count = 10
        # random source port low enough to increment a few times..
        udp_sport_tx = randint(1, 50000)
        udp_sport_rx = udp_sport_tx
        echo_packet = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg0.remote_ip4)
            / UDP(dport=BFD.udp_dport_echo)
            / Raw("this should be looped back")
        )
        for dummy in range(echo_packet_count):
            self.sleep(0.01, "delay between echo packets")
            echo_packet[UDP].sport = udp_sport_tx
            udp_sport_tx += 1
            self.logger.debug(ppp("Sending packet:", echo_packet))
            self.pg0.add_stream(echo_packet)
            self.pg_start()
            self.logger.debug(self.vapi.ppcli("show trace"))
        counter = 0
        bfd_control_packets_rx = 0
        while counter < echo_packet_count:
            p = self.pg0.wait_for_packet(2)
            self.logger.debug(ppp("Got packet:", p))
            ether = p[Ether]
            self.assert_equal(self.pg0.remote_mac, ether.dst, "Destination MAC")
            self.assert_equal(self.pg0.local_mac, ether.src, "Source MAC")
            ip = p[IP]
            self.assert_equal(self.pg0.remote_ip4, ip.dst, "Destination IP")
            udp = p[UDP]
            if udp.dport == BFD.udp_dport:
                bfd_control_packets_rx += 1
                continue
            self.assert_equal(self.pg0.remote_ip4, ip.src, "Source IP")
            self.assert_equal(udp.dport, BFD.udp_dport_echo, "UDP destination port")
            self.assert_equal(udp.sport, udp_sport_rx, "UDP source port")
            udp_sport_rx += 1
            # need to compare the hex payload here, otherwise BFD_vpp_echo
            # gets in way
            self.assertEqual(
                scapy.compat.raw(p[UDP].payload),
                scapy.compat.raw(echo_packet[UDP].payload),
                "Received packet is not the echo packet sent",
            )
            counter += 1
        self.assert_equal(
            udp_sport_tx,
            udp_sport_rx,
            "UDP source port (== ECHO packet identifier for test purposes)",
        )
        stats_after = bfd_grab_stats_snapshot(self)
        diff = bfd_stats_diff(stats_before, stats_after)
        self.assertEqual(0, diff.rx, "RX counter bumped but no BFD packets sent")
        self.assertEqual(
            0, diff.rx_echo, "RX echo counter bumped but no BFD session exists"
        )
        self.assertEqual(
            0, diff.tx_echo, "TX echo counter bumped but no BFD session exists"
        )

    def test_echo(self):
        """echo function"""

        if self.multihop:
            self.skipTest(
                f"Skipping because echo functionality is not supported with multihop"
            )

        stats_before = bfd_grab_stats_snapshot(self)
        bfd_session_up(self)
        self.test_session.update(required_min_echo_rx=150000)
        self.test_session.send_packet()
        detection_time = (
            self.test_session.detect_mult
            * self.vpp_session.required_min_rx
            / USEC_IN_SEC
        )
        # echo shouldn't work without echo source set
        for dummy in range(10):
            sleep = self.vpp_session.required_min_rx / USEC_IN_SEC
            self.sleep(sleep, "delay before sending bfd packet")
            self.test_session.send_packet()
        p = wait_for_bfd_packet(self, pcap_time_min=time.time() - self.vpp_clock_offset)
        self.assert_equal(
            p[BFD].required_min_rx_interval,
            self.vpp_session.required_min_rx,
            "BFD required min rx interval",
        )
        self.test_session.send_packet()
        self.vapi.bfd_udp_set_echo_source(sw_if_index=self.loopback0.sw_if_index)
        echo_seen = False
        # should be turned on - loopback echo packets
        for dummy in range(3):
            loop_until = time.time() + 0.75 * detection_time
            while time.time() < loop_until:
                p = self.pg0.wait_for_packet(1)
                self.logger.debug(ppp("Got packet:", p))
                if p[UDP].dport == BFD.udp_dport_echo:
                    self.assert_equal(p[IP].dst, self.pg0.local_ip4, "BFD ECHO dst IP")
                    self.assertNotEqual(
                        p[IP].src,
                        self.loopback0.local_ip4,
                        "BFD ECHO src IP equal to loopback IP",
                    )
                    self.logger.debug(ppp("Looping back packet:", p))
                    self.assert_equal(
                        p[Ether].dst,
                        self.pg0.remote_mac,
                        "ECHO packet destination MAC address",
                    )
                    p[Ether].dst = self.pg0.local_mac
                    self.pg0.add_stream(p)
                    self.test_session.rx_packets_echo += 1
                    self.test_session.tx_packets_echo += 1
                    self.pg_start()
                    echo_seen = True
                elif p.haslayer(BFD):
                    self.test_session.rx_packets += 1
                    if echo_seen:
                        self.assertGreaterEqual(
                            p[BFD].required_min_rx_interval, 1000000
                        )
                    if "P" in p.sprintf("%BFD.flags%"):
                        final = self.test_session.create_packet()
                        final[BFD].flags = "F"
                        self.test_session.send_packet(final)
                else:
                    raise Exception(ppp("Received unknown packet:", p))

                self.assert_equal(
                    len(self.vapi.collect_events()), 0, "number of bfd events"
                )
            self.test_session.send_packet()
        self.assertTrue(echo_seen, "No echo packets received")

        stats_after = bfd_grab_stats_snapshot(self)
        diff = bfd_stats_diff(stats_before, stats_after)
        # our rx is vpp tx and vice versa, also tolerate one packet off
        self.assert_in_range(
            self.test_session.tx_packets, diff.rx - 1, diff.rx + 1, "RX counter"
        )
        self.assert_in_range(
            self.test_session.rx_packets, diff.tx - 1, diff.tx + 1, "TX counter"
        )
        self.assert_in_range(
            self.test_session.tx_packets_echo,
            diff.rx_echo - 1,
            diff.rx_echo + 1,
            "RX echo counter",
        )
        self.assert_in_range(
            self.test_session.rx_packets_echo,
            diff.tx_echo - 1,
            diff.tx_echo + 1,
            "TX echo counter",
        )

    def test_echo_fail(self):
        """session goes down if echo function fails"""

        if self.multihop:
            self.skipTest(
                f"Skipping because echo functionality is not supported with multihop"
            )

        bfd_session_up(self)
        self.test_session.update(required_min_echo_rx=150000)
        self.test_session.send_packet()
        detection_time = (
            self.test_session.detect_mult
            * self.vpp_session.required_min_rx
            / USEC_IN_SEC
        )
        self.vapi.bfd_udp_set_echo_source(sw_if_index=self.loopback0.sw_if_index)
        # echo function should be used now, but we will drop the echo packets
        verified_diag = False
        for dummy in range(3):
            loop_until = time.time() + 0.75 * detection_time
            while time.time() < loop_until:
                p = self.pg0.wait_for_packet(1)
                self.logger.debug(ppp("Got packet:", p))
                if p[UDP].dport == BFD.udp_dport_echo:
                    # dropped
                    pass
                elif p.haslayer(BFD):
                    if "P" in p.sprintf("%BFD.flags%"):
                        self.assertGreaterEqual(
                            p[BFD].required_min_rx_interval, 1000000
                        )
                        final = self.test_session.create_packet()
                        final[BFD].flags = "F"
                        self.test_session.send_packet(final)
                    if p[BFD].state == BFDState.down:
                        self.assert_equal(
                            p[BFD].diag, BFDDiagCode.echo_function_failed, BFDDiagCode
                        )
                        verified_diag = True
                else:
                    raise Exception(ppp("Received unknown packet:", p))
            self.test_session.send_packet()
        events = self.vapi.collect_events()
        self.assert_equal(len(events), 1, "number of bfd events")
        self.assert_equal(events[0].state, BFDState.down, BFDState)
        self.assertTrue(verified_diag, "Incorrect diagnostics code received")

    def test_echo_stop(self):
        """echo function stops if peer sets required min echo rx zero"""

        if self.multihop:
            self.skipTest(
                f"Skipping because echo functionality is not supported with multihop"
            )

        bfd_session_up(self)
        self.test_session.update(required_min_echo_rx=150000)
        self.test_session.send_packet()
        self.vapi.bfd_udp_set_echo_source(sw_if_index=self.loopback0.sw_if_index)
        # wait for first echo packet
        while True:
            p = self.pg0.wait_for_packet(1)
            self.logger.debug(ppp("Got packet:", p))
            if p[UDP].dport == BFD.udp_dport_echo:
                self.logger.debug(ppp("Looping back packet:", p))
                p[Ether].dst = self.pg0.local_mac
                self.pg0.add_stream(p)
                self.pg_start()
                break
            elif p.haslayer(BFD):
                # ignore BFD
                pass
            else:
                raise Exception(ppp("Received unknown packet:", p))
        self.test_session.update(required_min_echo_rx=0)
        self.test_session.send_packet()
        # echo packets shouldn't arrive anymore
        for dummy in range(5):
            wait_for_bfd_packet(self, pcap_time_min=time.time() - self.vpp_clock_offset)
            self.test_session.send_packet()
            events = self.vapi.collect_events()
            self.assert_equal(len(events), 0, "number of bfd events")

    def test_echo_source_removed(self):
        """echo function stops if echo source is removed"""

        if self.multihop:
            self.skipTest(
                f"Skipping because echo functionality is not supported with multihop"
            )

        bfd_session_up(self)
        self.test_session.update(required_min_echo_rx=150000)
        self.test_session.send_packet()
        self.vapi.bfd_udp_set_echo_source(sw_if_index=self.loopback0.sw_if_index)
        # wait for first echo packet
        while True:
            p = self.pg0.wait_for_packet(1)
            self.logger.debug(ppp("Got packet:", p))
            if p[UDP].dport == BFD.udp_dport_echo:
                self.logger.debug(ppp("Looping back packet:", p))
                p[Ether].dst = self.pg0.local_mac
                self.pg0.add_stream(p)
                self.pg_start()
                break
            elif p.haslayer(BFD):
                # ignore BFD
                pass
            else:
                raise Exception(ppp("Received unknown packet:", p))
        self.vapi.bfd_udp_del_echo_source()
        self.test_session.send_packet()
        # echo packets shouldn't arrive anymore
        for dummy in range(5):
            wait_for_bfd_packet(self, pcap_time_min=time.time() - self.vpp_clock_offset)
            self.test_session.send_packet()
            events = self.vapi.collect_events()
            self.assert_equal(len(events), 0, "number of bfd events")

    def test_stale_echo(self):
        """stale echo packets don't keep a session up"""

        if self.multihop:
            self.skipTest(
                f"Skipping because echo functionality is not supported with multihop"
            )

        bfd_session_up(self)
        self.test_session.update(required_min_echo_rx=150000)
        self.vapi.bfd_udp_set_echo_source(sw_if_index=self.loopback0.sw_if_index)
        self.test_session.send_packet()
        # should be turned on - loopback echo packets
        echo_packet = None
        timeout_at = None
        timeout_ok = False
        for dummy in range(10 * self.vpp_session.detect_mult):
            p = self.pg0.wait_for_packet(1)
            if p[UDP].dport == BFD.udp_dport_echo:
                if echo_packet is None:
                    self.logger.debug(ppp("Got first echo packet:", p))
                    echo_packet = p
                    timeout_at = (
                        time.time()
                        + self.vpp_session.detect_mult
                        * self.test_session.required_min_echo_rx
                        / USEC_IN_SEC
                    )
                else:
                    self.logger.debug(ppp("Got followup echo packet:", p))
                self.logger.debug(ppp("Looping back first echo packet:", p))
                echo_packet[Ether].dst = self.pg0.local_mac
                self.pg0.add_stream(echo_packet)
                self.pg_start()
            elif p.haslayer(BFD):
                self.logger.debug(ppp("Got packet:", p))
                if "P" in p.sprintf("%BFD.flags%"):
                    final = self.test_session.create_packet()
                    final[BFD].flags = "F"
                    self.test_session.send_packet(final)
                if p[BFD].state == BFDState.down:
                    self.assertIsNotNone(
                        timeout_at,
                        "Session went down before first echo packet received",
                    )
                    now = time.time()
                    self.assertGreaterEqual(
                        now,
                        timeout_at,
                        "Session timeout at %s, but is expected at %s"
                        % (now, timeout_at),
                    )
                    self.assert_equal(
                        p[BFD].diag, BFDDiagCode.echo_function_failed, BFDDiagCode
                    )
                    events = self.vapi.collect_events()
                    self.assert_equal(len(events), 1, "number of bfd events")
                    self.assert_equal(events[0].state, BFDState.down, BFDState)
                    timeout_ok = True
                    break
            else:
                raise Exception(ppp("Received unknown packet:", p))
            self.test_session.send_packet()
        self.assertTrue(timeout_ok, "Expected timeout event didn't occur")

    def test_invalid_echo_checksum(self):
        """echo packets with invalid checksum don't keep a session up"""

        if self.multihop:
            self.skipTest(
                f"Skipping because echo functionality is not supported with multihop"
            )

        bfd_session_up(self)
        self.test_session.update(required_min_echo_rx=150000)
        self.vapi.bfd_udp_set_echo_source(sw_if_index=self.loopback0.sw_if_index)
        self.test_session.send_packet()
        # should be turned on - loopback echo packets
        timeout_at = None
        timeout_ok = False
        for dummy in range(10 * self.vpp_session.detect_mult):
            p = self.pg0.wait_for_packet(1)
            if p[UDP].dport == BFD.udp_dport_echo:
                self.logger.debug(ppp("Got echo packet:", p))
                if timeout_at is None:
                    timeout_at = (
                        time.time()
                        + self.vpp_session.detect_mult
                        * self.test_session.required_min_echo_rx
                        / USEC_IN_SEC
                    )
                p[BFD_vpp_echo].checksum = getrandbits(64)
                p[Ether].dst = self.pg0.local_mac
                self.logger.debug(ppp("Looping back modified echo packet:", p))
                self.pg0.add_stream(p)
                self.pg_start()
            elif p.haslayer(BFD):
                self.logger.debug(ppp("Got packet:", p))
                if "P" in p.sprintf("%BFD.flags%"):
                    final = self.test_session.create_packet()
                    final[BFD].flags = "F"
                    self.test_session.send_packet(final)
                if p[BFD].state == BFDState.down:
                    self.assertIsNotNone(
                        timeout_at,
                        "Session went down before first echo packet received",
                    )
                    now = time.time()
                    self.assertGreaterEqual(
                        now,
                        timeout_at,
                        "Session timeout at %s, but is expected at %s"
                        % (now, timeout_at),
                    )
                    self.assert_equal(
                        p[BFD].diag, BFDDiagCode.echo_function_failed, BFDDiagCode
                    )
                    events = self.vapi.collect_events()
                    self.assert_equal(len(events), 1, "number of bfd events")
                    self.assert_equal(events[0].state, BFDState.down, BFDState)
                    timeout_ok = True
                    break
            else:
                raise Exception(ppp("Received unknown packet:", p))
            self.test_session.send_packet()
        self.assertTrue(timeout_ok, "Expected timeout event didn't occur")

    def test_admin_up_down(self):
        """put session admin-up and admin-down"""
        bfd_session_up(self)
        self.vpp_session.admin_down()
        self.pg0.enable_capture()
        e = self.vapi.wait_for_event(1, "bfd_udp_session_event")
        verify_event(self, e, expected_state=BFDState.admin_down)
        p = wait_for_bfd_packet(self, timeout=2)
        self.assert_equal(p[BFD].state, BFDState.admin_down, BFDState)
        # try to bring session up - shouldn't be possible
        self.test_session.update(state=BFDState.init)
        self.test_session.send_packet()
        # Only accept a packet captured after the peer's Init. PCAP timestamps
        # use VPP's clock, so translate the current wall-clock time.
        p = wait_for_bfd_packet(
            self,
            timeout=2,
            pcap_time_min=time.time() - self.vpp_clock_offset,
        )
        self.assert_equal(p[BFD].state, BFDState.admin_down, BFDState)
        verify_bfd_session_config(self, self.vpp_session, state=BFDState.admin_down)
        self.vpp_session.admin_up()
        self.test_session.update(state=BFDState.down)
        e = self.vapi.wait_for_event(1, "bfd_udp_session_event")
        verify_event(self, e, expected_state=BFDState.down)
        p = wait_for_bfd_packet(self, pcap_time_min=time.time() - self.vpp_clock_offset)
        self.assert_equal(p[BFD].state, BFDState.down, BFDState)
        self.test_session.send_packet()
        p = wait_for_bfd_packet(self, pcap_time_min=time.time() - self.vpp_clock_offset)
        self.assert_equal(p[BFD].state, BFDState.init, BFDState)
        e = self.vapi.wait_for_event(1, "bfd_udp_session_event")
        verify_event(self, e, expected_state=BFDState.init)
        self.test_session.update(state=BFDState.up)
        self.test_session.send_packet()
        p = wait_for_bfd_packet(self, pcap_time_min=time.time() - self.vpp_clock_offset)
        self.assert_equal(p[BFD].state, BFDState.up, BFDState)
        e = self.vapi.wait_for_event(1, "bfd_udp_session_event")
        verify_event(self, e, expected_state=BFDState.up)

    def test_config_change_remote_demand(self):
        """configuration change while peer in demand mode"""
        bfd_session_up(self)
        demand = self.test_session.create_packet()
        demand[BFD].flags = "D"
        self.test_session.send_packet(demand)
        self.vpp_session.modify_parameters(
            required_min_rx=2 * self.vpp_session.required_min_rx
        )
        p = wait_for_bfd_packet(self, pcap_time_min=time.time() - self.vpp_clock_offset)
        # poll bit must be set
        self.assertIn("P", p.sprintf("%BFD.flags%"), "Poll bit not set")
        # terminate poll sequence
        final = self.test_session.create_packet()
        final[BFD].flags = "D+F"
        self.test_session.send_packet(final)
        # vpp should be quiet now again
        transmit_time = (
            0.9
            * max(self.vpp_session.required_min_rx, self.test_session.desired_min_tx)
            / USEC_IN_SEC
        )
        count = 0
        for dummy in range(self.test_session.detect_mult * 2):
            self.sleep(transmit_time)
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

    def test_intf_deleted(self):
        """interface with bfd session deleted"""
        intf = VppLoInterface(self)
        intf.config_ip4()
        intf.admin_up()
        sw_if_index = intf.sw_if_index

        # Setup routing info for multihop
        set_ipv4_pfx_route_info(self, intf, BFD_IPV4_REMOTE_ADDR2, False)

        vpp_session = VppBFDUDPSession(
            self,
            intf,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
        )

        vpp_session.add_vpp_config()
        vpp_session.admin_up()
        intf.remove_vpp_config()

        # BFD session is removed only for single-hop session
        if self.multihop:
            self.assertTrue(vpp_session.query_vpp_config())
        else:
            e = self.vapi.wait_for_event(1, "bfd_udp_session_event")
            self.assert_equal(e.sw_if_index, sw_if_index, "sw_if_index")
            self.assertFalse(vpp_session.query_vpp_config())

    def test_bfd_traffic_with_tos_configured(self):
        """test BFD traffic with TOS values configured"""
        # Test different TOS values
        test_tos_values = [0, 112, 192, 255]

        for tos_value in test_tos_values:
            with self.subTest(tos=tos_value):
                self.logger.info(f"Testing BFD traffic with TOS value: {tos_value}")
                # Set the TOS value
                self.vapi.bfd_udp_set_tos(tos_value)
                # Verify the TOS value was set
                current_tos = self.vapi.bfd_udp_get_tos()
                self.assertEqual(
                    current_tos.tos, tos_value, f"TOS should be set to {tos_value}"
                )
                # Start the BFD session and wait for the first packet
                self.logger.info("BFD: Waiting for packet with custom TOS")
                p = wait_for_bfd_packet(
                    self,
                    timeout=2,
                    is_tunnel=self.vpp_session.is_tunnel,
                    expected_tos=tos_value,
                )
                # Verify the packet has the expected TOS value
                if self.vpp_session.af == AF_INET6:
                    actual_tos = p[IPv6].tc
                    field_name = "IPv6 TC"
                else:
                    actual_tos = p[IP].tos
                    field_name = "IPv4 TOS"
                self.assertEqual(
                    actual_tos,
                    tos_value,
                    f"{field_name} should be {tos_value}, got {actual_tos}",
                )
                self.logger.info(
                    f"Successfully verified BFD packet with TOS {tos_value}"
                )
                # Send a response packet to keep the session alive
                self.test_session.send_packet()
                # Brief pause between tests
                self.sleep(0.2, "brief pause between TOS tests")


@tag_run_solo
class BFDPollFinalVrfTestCase(VppTestCase):
    """BFD single-hop Poll/Final with default and non-default FIB tables"""

    VRF_ID = 10

    @classmethod
    def setUpClass(cls):
        super(BFDPollFinalVrfTestCase, cls).setUpClass()
        cls.vapi.cli("set log class bfd level debug")
        try:
            cls.create_pg_interfaces([0])
        except Exception:
            super(BFDPollFinalVrfTestCase, cls).tearDownClass()
            raise

    def setUp(self):
        super(BFDPollFinalVrfTestCase, self).setUp()
        self.vpp_session = None
        self.configured_af = None
        self.vapi.want_bfd_events()

    def tearDown(self):
        if not self.vpp_dead:
            self.vapi.want_bfd_events(enable_disable=0)
            self.vapi.collect_events()
            # take pg0 out of the VRF so the registry can free the table
            if self.configured_af == AF_INET6:
                self.pg0.unconfig_ip6()
                self.pg0.set_table_ip6(0)
            elif self.configured_af == AF_INET:
                self.pg0.unconfig_ip4()
                self.pg0.set_table_ip4(0)
            self.pg0.admin_down()
        super(BFDPollFinalVrfTestCase, self).tearDown()

    def _wait_for_final(self, timeout=2):
        # raw capture on pg0 (deliberately NOT wait_for_bfd_packet, whose
        # verify_bfd would trip on unrelated frames): return the first BFD
        # frame carrying the Final(F) bit, or None if none arrives in time
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                p = self.pg0.wait_for_packet(max(0.0001, deadline - time.time()))
            except CaptureTimeoutError:
                return None
            if p.haslayer(BFD) and "F" in p[BFD].sprintf("%BFD.flags%"):
                return p
        return None

    def _poll_final(self, af, table_id):
        is_ip6 = af == AF_INET6
        lookup_node = "ip6-lookup" if is_ip6 else "ip4-lookup"
        rewrite_node = "ip6-rewrite" if is_ip6 else "ip4-rewrite"

        # put pg0 in the requested table and bring the single-hop session up
        if table_id != 0:
            VppIpTable(self, table_id, is_ip6=is_ip6).add_vpp_config()
            if is_ip6:
                self.pg0.set_table_ip6(table_id)
            else:
                self.pg0.set_table_ip4(table_id)
        self.configured_af = af
        if is_ip6:
            self.pg0.config_ip6()
            self.pg0.configure_ipv6_neighbors()
            self.pg0.admin_up()
            self.pg0.resolve_ndp()
            local_addr = self.pg0.local_ip6
            peer_addr = self.pg0.remote_ip6
        else:
            self.pg0.config_ip4()
            self.pg0.configure_ipv4_neighbors()
            self.pg0.admin_up()
            self.pg0.resolve_arp()
            local_addr = self.pg0.local_ip4
            peer_addr = self.pg0.remote_ip4
        self.pg0.enable_capture()

        self.vpp_session = VppBFDUDPSession(
            self, self.pg0, peer_addr, local_addr=local_addr, af=af
        )
        self.vpp_session.add_vpp_config()
        self.vpp_session.admin_up()
        self.test_session = BFDTestSession(
            self,
            self.pg0,
            af,
            local_addr=local_addr,
            peer_addr=peer_addr,
        )
        bfd_session_up(self)
        wait_for_bfd_packet(self)  # drain the queued periodic frame

        # trace the Final reply through the graph so its fate is visible: the
        # reply reuses the incoming Poll buffer and is sent to ipX-lookup, which
        # picks the FIB table from fib_index_by_sw_if_index[rx sw_if_index]
        self.vapi.cli("clear trace")
        self.vapi.cli("trace add pg-input 50")
        poll = self.test_session.create_packet()
        poll[BFD].flags = "P"
        self.test_session.send_packet(poll)

        final = self._wait_for_final()
        trace = self.vapi.cli("show trace")
        self.logger.info("Final reply path (fib table %d):\n%s" % (table_id, trace))
        # with the fix the trace ends in <rewrite_node> -> pg0 output; without
        # it the lookup happens in table 0, finds no route and drops the reply
        self.assertIsNotNone(
            final,
            "VPP did not forward a Final(F) after the Poll: the reply was "
            "dropped in %s (wrong FIB table). Expected the trace to end in "
            "%s. Trace:\n%s" % (lookup_node, rewrite_node, trace),
        )

    def test_poll_final_default_table4(self):
        """IPv4 single-hop in the default table: Final is forwarded out pg0"""
        self._poll_final(AF_INET, 0)

    def test_poll_final_non_default_vrf4(self):
        """IPv4 single-hop in a non-default VRF: Final forwarded with the fix"""
        self._poll_final(AF_INET, self.VRF_ID)

    def test_poll_final_default_table6(self):
        """IPv6 single-hop in the default table: Final is forwarded out pg0"""
        self._poll_final(AF_INET6, 0)

    def test_poll_final_non_default_vrf6(self):
        """IPv6 single-hop in a non-default VRF: Final forwarded with the fix"""
        self._poll_final(AF_INET6, self.VRF_ID)


@parameterized_class(
    [
        {"af": AF_INET, "multihop": False},
        {"af": AF_INET, "multihop": True},
        {"af": AF_INET6, "multihop": False},
        {"af": AF_INET6, "multihop": True},
    ]
)
class SBFDReflectorTestCase(VppTestCase):
    """S-BFD reflector"""

    VRF_ID = 10
    dst_ip_net = ""
    dst_ip6_net = ""

    @classmethod
    def setUpClass(cls):
        super(SBFDReflectorTestCase, cls).setUpClass()
        af_str = "IPv6" if cls.af == AF_INET6 else "IPv4"
        hoptype_str = "MultiHop" if cls.multihop else "SingleHop"
        cls.__doc__ = f"""Seamless BFD (S-BFD) reflector - {af_str}, {hoptype_str}"""
        cls.vapi.cli("set log class bfd level debug")
        try:
            pg_interfaces = cls.create_pg_interfaces([0, 1])
            # pg2 marks the UDP packets it receives for checksum offload,
            # as virtio and af_packet interfaces do
            pg_interfaces += cls.create_pg_interfaces([2], csum_offload=1)
            cls.pg_interfaces = pg_interfaces
            cls.pg0.config_ip4()
            cls.pg0.config_ip6()
            cls.pg0.configure_ipv4_neighbors()
            cls.pg0.configure_ipv6_neighbors()
            cls.pg0.admin_up()
            cls.pg0.resolve_arp()
            cls.pg0.resolve_ndp()
            cls.pg1.admin_up()
            cls.pg2.config_ip4()
            cls.pg2.config_ip6()
            cls.pg2.admin_up()
        except Exception:
            super(SBFDReflectorTestCase, cls).tearDownClass()
            raise

    def setUp(self):
        super(SBFDReflectorTestCase, self).setUp()
        self.vrf_configured = False
        self.mpls_enabled = False
        # the default TOS is 0, so replies would not show that it is applied
        self.saved_tos = self.vapi.bfd_udp_get_tos().tos
        self.vapi.bfd_udp_set_tos(BFD_UDP_DEFAULT_TOS)
        self.pg0.enable_capture()
        self.pg1.enable_capture()
        if self.af == AF_INET6:
            set_ipv6_pfx_route_info(self, self.pg0, BFD_IPV6_REMOTE_ADDR, False)
            self.local_addr = self.pg0.local_ip6
            self.peer_addr = self.dst_ip6_net
            self.mpls_path_dsts = SBFD_MPLS_PATH_DST6
            self.mpls_path_prefix = ("::ffff:127.0.0.0", 104)
        else:
            set_ipv4_pfx_route_info(self, self.pg0, BFD_IPV4_REMOTE_ADDR, False)
            self.local_addr = self.pg0.local_ip4
            self.peer_addr = self.dst_ip_net
            self.mpls_path_dsts = SBFD_MPLS_PATH_DST4
            self.mpls_path_prefix = ("127.0.0.0", 8)

    def tearDown(self):
        if not self.vpp_dead:
            self.vapi.bfd_udp_set_tos(self.saved_tos)
        if not self.vpp_dead and self.mpls_enabled:
            # disable MPLS so the registry can free the MPLS table
            self.pg0.disable_mpls()
            self.pg1.disable_mpls()
        if not self.vpp_dead and self.vrf_configured:
            # take pg1 out of the VRF so the registry can free the table
            if self.af == AF_INET6:
                self.pg1.unconfig_ip6()
                self.pg1.set_table_ip6(0)
            else:
                self.pg1.unconfig_ip4()
                self.pg1.set_table_ip4(0)
        super(SBFDReflectorTestCase, self).tearDown()

    def reflector(self, discriminator=0x01020304, **kwargs):
        """add S-BFD reflector discriminator to VPP"""
        reflector = VppSBFDReflector(self, discriminator, **kwargs)
        reflector.add_vpp_config()
        return reflector

    def initiator(self, reflector, interface=None, **kwargs):
        """create S-BFD initiator for reflector discriminator"""
        kwargs.setdefault("local_addr", self.local_addr)
        kwargs.setdefault("peer_addr", self.peer_addr)
        return SBFDTestInitiator(
            self,
            interface or self.pg0,
            self.af,
            reflector,
            multihop=self.multihop,
            **kwargs,
        )

    def mpls_path_initiator(self, reflector, dst=None, **kwargs):
        """create S-BFD initiator which sends as over an MPLS path: to 127/8
        or ::ffff:127.0.0.0/104 with TTL 1; pg0's address answers"""
        kwargs.setdefault("ttl", 1)
        kwargs.setdefault("reply_src", self.local_addr)
        return self.initiator(
            reflector, local_addr=dst or self.mpls_path_dsts[0], **kwargs
        )

    def labelled(self, request, interface, label, length=None):
        """put the IP packet of an S-BFD request, or its first length bytes,
        behind an MPLS label"""
        ip = request[IPv6] if self.af == AF_INET6 else request[IP]
        if length is not None:
            ip = Raw(scapy.compat.raw(ip)[:length])
        return (
            Ether(src=interface.remote_mac, dst=interface.local_mac)
            / MPLS(label=label, ttl=255)
            / ip
        )

    def counter(self, name, node="input"):
        return sbfd_err_counter(self, self.af, name, node)

    def verify_dropped(self, packets, counter, count=1, node="input", interface=None):
        """send packets on interface, pg0 by default, verify no reply and the
        drop counter"""
        interface = interface or self.pg0
        before = self.counter(counter, node)
        interface.add_stream(packets)
        self.pg_start()
        verify_no_sbfd_reply(self, interface)
        self.assert_equal(self.counter(counter, node), before + count, counter)

    def test_reflect(self):
        """S-BFD request is reflected"""
        initiator = self.initiator(self.reflector(required_min_rx=100000))
        # a reflector sends nothing unless asked
        verify_no_sbfd_reply(self, self.pg0)
        reflected = self.counter("reflected")
        initiator.send_packet()
        wait_for_sbfd_reply(self, initiator, self.pg0)
        self.assert_equal(self.counter("reflected"), reflected + 1, "reflected")

    def test_poll_final(self):
        """S-BFD request with Poll is answered with Final"""
        initiator = self.initiator(self.reflector())
        request = initiator.create_packet()
        request[BFD].flags |= "P"
        initiator.send_packet(request)
        wait_for_sbfd_reply(self, initiator, self.pg0, poll=True)

    def test_admin_down(self):
        """admin-down S-BFD discriminator answers with AdminDown"""
        initiator = self.initiator(self.reflector(admin_up=False))
        initiator.send_packet()
        wait_for_sbfd_reply(self, initiator, self.pg0)

    def sbfd_port_registered(self):
        """True if UDP port 7784 leads to the reflector node of this family"""
        family = 6 if self.af == AF_INET6 else 4
        ports = self.vapi.cli("show udp ports ip%d %d" % (family, BFD_UDP_SBFD_PORT))
        return "bfd-sbfd-reflector%d-input" % family in ports

    def test_modify(self):
        """S-BFD discriminator modified in place answers every request"""
        reflector = self.reflector()
        initiator = self.initiator(reflector)
        no_disc = self.counter("no_disc")
        reflected = self.counter("reflected")
        changes = (
            {},
            {"admin_up": False},
            {"required_min_rx": 1000000},
            {"admin_up": True},
        )
        for change in changes:
            if change:
                reflector.modify_parameters(**change)
            # a modification leaves the registration alone
            self.assertTrue(self.sbfd_port_registered(), "UDP port 7784 registered")
            for prefix in SBFD_MPLS_PATH_PREFIXES:
                self.assertTrue(find_route(self, *prefix), "%s/%d entry" % prefix)
            # each request is answered with the values now configured
            for dummy in range(3):
                initiator.send_packet()
                wait_for_sbfd_reply(self, initiator, self.pg0)
        self.assert_equal(self.counter("no_disc"), no_disc, "no_disc")
        self.assert_equal(
            self.counter("reflected"), reflected + 3 * len(changes), "reflected"
        )

    def test_request_padding(self):
        """padding after S-BFD request is not reflected"""
        initiator = self.initiator(self.reflector())
        initiator.send_packet(initiator.create_packet() / Raw(b"\xa5" * 16))
        wait_for_sbfd_reply(self, initiator, self.pg0)

    def test_rx_checksum_offload(self):
        """S-BFD reply checksums are kept with RX checksum offload"""
        # the request comes in on pg2, which marks it for checksum offload;
        # the reply leaves pg0, which has no TX checksum offload
        initiator = self.initiator(self.reflector(), interface=self.pg2)
        initiator.send_packet()
        p = wait_for_sbfd_reply(self, initiator, self.pg0)
        if self.af == AF_INET:
            self.assert_equal(p[UDP].chksum, 0, "UDP checksum")
            return
        # Make the next reply's checksum compute to 0. The checksum is ~S,
        # S being the ones' complement sum of the 16-bit words of the
        # pseudo-header and the datagram. My Discriminator comes back as
        # Your Discriminator at an even offset, so adding ~S to its low 16
        # bits (with end-around carry) turns S into S + ~S = 0xffff. That
        # computes to checksum 0, which UDP must send as 0xffff.
        disc = initiator.my_discriminator
        low = (disc & 0xFFFF) + p[UDP].chksum
        low = (low & 0xFFFF) + (low >> 16)
        initiator.update(my_discriminator=(disc & 0xFFFF0000) | low)
        initiator.send_packet()
        p = wait_for_sbfd_reply(self, initiator, self.pg0)
        self.assert_equal(p[UDP].chksum, 0xFFFF, "UDP checksum")

    def test_qos_mark(self):
        """S-BFD reply TOS is not remarked from the request's QoS"""
        # egress marking would turn the request's recorded TOS into 1
        src = VppEnum.vl_api_qos_source_t.QOS_API_SOURCE_IP
        qem = VppQosEgressMap(self, 1, [{"outputs": b"\x01" * 256}] * 4)
        VppQosMark(self, self.pg0, qem.add_vpp_config(), src).add_vpp_config()
        VppQosRecord(self, self.pg0, src).add_vpp_config()
        initiator = self.initiator(self.reflector())
        initiator.send_packet()
        wait_for_sbfd_reply(self, initiator, self.pg0)

    def test_mixed_stream(self):
        """valid and invalid S-BFD requests in one frame"""
        i1 = self.initiator(self.reflector(0x01020304))
        i2 = self.initiator(self.reflector(0xFFFFFFFF))
        # values unlike i1's, which i2's reply must copy
        i2.update(detect_mult=3, desired_min_tx=450000)
        unknown = self.initiator(VppSBFDReflector(self, 0x0A0B0C0D))
        demand_clear = i1.create_packet()
        demand_clear[BFD].flags = 0
        names = ("reflected", "demand_clear", "no_disc")
        before = {name: self.counter(name) for name in names}
        self.pg0.add_stream(
            [
                i1.create_packet(),
                demand_clear,
                i2.create_packet(),
                unknown.create_packet(),
            ]
        )
        self.pg_start()
        wait_for_sbfd_reply(self, i1, self.pg0)
        wait_for_sbfd_reply(self, i2, self.pg0)
        verify_no_sbfd_reply(self, self.pg0)
        for name, delta in zip(names, (2, 1, 1)):
            self.assert_equal(self.counter(name), before[name] + delta, name)

    def test_unknown_discriminator(self):
        """S-BFD request for unknown discriminator is dropped"""
        self.reflector(0x01020304)
        initiator = self.initiator(VppSBFDReflector(self, 0x0A0B0C0D))
        # Your Discriminator 0 passes the RFC 5880 checks with state Down, and
        # is never configured
        zero = initiator.create_packet()
        zero[BFD].your_discriminator = 0
        zero[BFD].state = BFDState.down
        self.verify_dropped([initiator.create_packet(), zero], "no_disc", 2)

    def test_demand_clear(self):
        """S-BFD request with Demand bit clear is dropped"""
        request = self.initiator(self.reflector()).create_packet()
        request[BFD].flags = 0
        self.verify_dropped(request, "demand_clear")

    def test_source_port_7784(self):
        """S-BFD request from UDP source port 7784 is dropped"""
        initiator = self.initiator(self.reflector())
        initiator.udp_sport = BFD_UDP_SBFD_PORT
        # the source port is checked before the Demand bit
        demand_clear = initiator.create_packet()
        demand_clear[BFD].flags = 0
        self.verify_dropped([initiator.create_packet(), demand_clear], "bad_sport", 2)

    def test_echo_port(self):
        """S-BFD request to the BFD echo port is not answered"""
        # RFC 7880 section 10: S-BFD Echo packets, to UDP port 3785 (RFC 7881
        # section 3), are not processed by the reflector
        request = self.initiator(self.reflector()).create_packet()
        request[UDP].dport = BFD.udp_dport_echo
        self.verify_dropped(request, "reflected", 0)

    def test_malformed(self):
        """malformed S-BFD requests are dropped"""
        initiator = self.initiator(self.reflector())
        packets = []
        for field, value in (
            ("version", 2),
            ("length", BFD.bfd_pkt_len - 1),
            ("length", BFD.bfd_pkt_len * 2),
            ("detect_mult", 0),
            ("my_discriminator", 0),
        ):
            request = initiator.create_packet()
            setattr(request[BFD], field, value)
            packets.append(request)
        multipoint = initiator.create_packet()
        multipoint[BFD].flags |= "M"
        packets.append(multipoint)
        # Your Discriminator 0 is allowed only with state Down or AdminDown
        your_disc_zero = initiator.create_packet()
        your_disc_zero[BFD].your_discriminator = 0
        your_disc_zero[BFD].state = BFDState.up
        packets.append(your_disc_zero)
        # Length beyond the UDP payload by less than the UDP header. The IP
        # length covers all the bytes, and so does the UDP checksum, as
        # ip4-local and ip6-local compute it over the IP payload.
        for short in (1, 4, 7):
            request = initiator.create_packet()
            request[UDP].len = 8 + BFD.bfd_pkt_len - short
            packets.append(request)
        truncated = initiator.create_packet()
        payload = scapy.compat.raw(truncated[BFD])[: BFD.bfd_pkt_len - 4]
        truncated[UDP].remove_payload()
        packets.append(truncated / Raw(payload))
        # larger than one buffer, so it arrives as a buffer chain
        packets.append(initiator.create_packet() / Raw(b"\xa5" * 3000))
        self.verify_dropped(packets, "bad", len(packets))

    def test_udp_beyond_ip_length(self):
        """S-BFD request running past the IP packet is dropped"""
        request = self.initiator(self.reflector()).create_packet()
        # the IP length covers only 4 of the 24 BFD bytes; UDP checksum 0 is
        # accepted without reading the payload
        request[UDP].len = 8 + BFD.bfd_pkt_len
        request[UDP].chksum = 0
        if self.af == AF_INET6:
            # dropped before the reflector: payload length < UDP length
            request[IPv6].plen = 8 + 4
            self.verify_dropped(request, "bad", 0)
        else:
            request[IP].len = 20 + 8 + 4
            self.verify_dropped(request, "bad")

    def test_authenticated_request(self):
        """S-BFD request with authentication is dropped"""
        initiator = self.initiator(
            self.reflector(),
            sha1_key=AuthKeyFactory().create_random_key(self),
            bfd_key_id=randint(0, 255),
        )
        self.verify_dropped(initiator.create_packet(), "auth")

    def test_non_unicast(self):
        """S-BFD requests from or to non-unicast addresses are dropped"""
        initiator = self.initiator(self.reflector())
        packets = []
        if self.af == AF_INET6:
            # a route to the martian source gets it past ip6-local's uRPF
            default = VppRoutePath(self.pg0.remote_ip6, self.pg0.sw_if_index)
            VppIpRoute(self, "::", 0, [default]).add_vpp_config()
            loopback_src = initiator.create_packet()
            loopback_src[IPv6].src = "::1"
            multicast_dst = initiator.create_packet()
            multicast_dst[Ether].dst = "33:33:00:00:00:01"
            multicast_dst[IPv6].dst = "ff02::1"
            unspecified_src = initiator.create_packet()
            unspecified_src[IPv6].src = "::"
            # all of ::ffff:0:0/96 is no source (RFC 6890), not only
            # ::ffff:127.0.0.0/104
            mapped_src = initiator.create_packet()
            mapped_src[IPv6].src = "::ffff:10.1.2.3"
            packets = [unspecified_src, loopback_src, mapped_src, multicast_dst]
            from_127 = initiator.create_packet()
            from_127[IPv6].src = SBFD_MPLS_PATH_DST6[0]
            # ip6-local counts its errors as ip6-input
            src_lookup_miss = "/err/ip6-input/src_lookup_miss"
        else:
            # a route to the martian source gets it past ip4-local's uRPF
            default = VppRoutePath(self.pg0.remote_ip4, self.pg0.sw_if_index)
            VppIpRoute(self, "0.0.0.0", 0, [default]).add_vpp_config()
            zero_net_src = initiator.create_packet()
            zero_net_src[IP].src = "0.1.2.3"
            # the all-hosts group is delivered locally, as ff02::1 is
            multicast_dst = initiator.create_packet()
            multicast_dst[Ether].dst = "01:00:5e:00:00:01"
            multicast_dst[IP].dst = "224.0.0.1"
            packets = [zero_net_src, multicast_dst]
            from_127 = initiator.create_packet()
            from_127[IP].src = "127.0.0.1"
            src_lookup_miss = "/err/ip4-local/src_lookup_miss"
        self.verify_dropped(packets, "non_unicast", len(packets))
        # here the source lookup resolves through the sbfd entry, which gives
        # no route back to 127/8 or ::ffff:127.0.0.0/104, so ip4-local or
        # ip6-local drops requests from there first; the reflector's own
        # check of these sources applies when other routes let them through
        before = self.statistics.get_err_counter(src_lookup_miss)
        self.verify_dropped(from_127, "non_unicast", 0)
        self.assert_equal(
            self.statistics.get_err_counter(src_lookup_miss),
            before + 1,
            src_lookup_miss,
        )

    def pg1_in_vrf(self):
        """move pg1 to table VRF_ID, with an address and a resolved
        neighbour; return pg1's local and remote addresses"""
        VppIpTable(self, self.VRF_ID, is_ip6=self.af == AF_INET6).add_vpp_config()
        self.vrf_configured = True
        if self.af == AF_INET6:
            self.pg1.set_table_ip6(self.VRF_ID)
            self.pg1.config_ip6()
            self.pg1.configure_ipv6_neighbors()
            self.pg1.resolve_ndp()
            return self.pg1.local_ip6, self.pg1.remote_ip6
        self.pg1.set_table_ip4(self.VRF_ID)
        self.pg1.config_ip4()
        self.pg1.configure_ipv4_neighbors()
        self.pg1.resolve_arp()
        return self.pg1.local_ip4, self.pg1.remote_ip4

    def test_vrf(self):
        """S-BFD reply leaves in the table of the request"""
        local_addr, next_hop = self.pg1_in_vrf()
        if self.af == AF_INET6:
            remote_addr, prefix_len = BFD_IPV6_REMOTE_ADDR, 128
        else:
            remote_addr, prefix_len = BFD_IPV4_REMOTE_ADDR, 32
        peer_addr = next_hop
        if self.multihop:
            # the default table routes the same prefix out of pg0
            path = VppRoutePath(next_hop, self.pg1.sw_if_index)
            VppIpRoute(
                self, remote_addr, prefix_len, [path], table_id=self.VRF_ID
            ).add_vpp_config()
            peer_addr = remote_addr
        initiator = self.initiator(
            self.reflector(),
            interface=self.pg1,
            local_addr=local_addr,
            peer_addr=peer_addr,
        )
        initiator.send_packet()
        wait_for_sbfd_reply(self, initiator, self.pg1)

    def test_last_discriminator_deleted(self):
        """UDP port 7784 is released with the last S-BFD discriminator"""
        r1 = self.reflector(0x01020304)
        r2 = self.reflector(0xFFFFFFFF)
        r1.remove_vpp_config()
        initiator = self.initiator(r2)
        initiator.send_packet()
        wait_for_sbfd_reply(self, initiator, self.pg0)
        r2.remove_vpp_config()
        initiator.send_packet()
        if self.af == AF_INET6:
            p = self.pg0.wait_for_packet(
                2, filter_out_fn=lambda p: not p.haslayer(ICMPv6DestUnreach)
            )
            self.assert_equal(p[ICMPv6DestUnreach].code, 4, "ICMPv6 code")
        else:
            p = self.pg0.wait_for_packet(
                2, filter_out_fn=lambda p: not p.haslayer(ICMP)
            )
            self.assert_equal(p[ICMP].type, 3, "ICMP type")
            self.assert_equal(p[ICMP].code, 3, "ICMP code")
        verify_no_sbfd_reply(self, self.pg0)
        r2.add_vpp_config()
        initiator.send_packet()
        wait_for_sbfd_reply(self, initiator, self.pg0)

    def test_link_local(self):
        """S-BFD request from IPv6 link-local address is reflected"""
        if self.af != AF_INET6 or self.multihop:
            self.skipTest("link-local addresses apply to single-hop IPv6 only")
        # compressed form, as scapy prints it
        remote_ip6_ll = str(ipaddress.IPv6Address(self.pg0.remote_ip6_ll))
        VppNeighbor(
            self,
            self.pg0.sw_if_index,
            self.pg0.remote_mac,
            remote_ip6_ll,
            is_static=True,
        ).add_vpp_config()
        reflector = self.reflector()
        initiator = self.initiator(
            reflector,
            local_addr=self.pg0.local_ip6_ll,
            peer_addr=remote_ip6_ll,
        )
        initiator.send_packet()
        wait_for_sbfd_reply(self, initiator, self.pg0)
        # over an MPLS path, pg0's link-local address answers: the initiator
        # is on the same link, where RFC 7881 section 6.1 allows it
        initiator = self.mpls_path_initiator(
            reflector, peer_addr=remote_ip6_ll, reply_src=self.pg0.local_ip6_ll
        )
        initiator.send_packet()
        wait_for_sbfd_reply(self, initiator, self.pg0)

    def test_mpls_path(self):
        """S-BFD request over an MPLS path is answered from the interface"""
        reflector = self.reflector()
        reflected = self.counter("reflected")
        for dst in self.mpls_path_dsts:
            initiator = self.mpls_path_initiator(reflector, dst)
            initiator.send_packet()
            wait_for_sbfd_reply(self, initiator, self.pg0)
        self.assert_equal(
            self.counter("reflected"),
            reflected + len(self.mpls_path_dsts),
            "reflected",
        )

    def test_mpls_path_src_address(self):
        """S-BFD reply over an MPLS path comes from the configured source"""
        src = {"src_ip4": "192.0.2.20", "src_ip6": "2001:db8::20"}
        configured = src["src_ip6"] if self.af == AF_INET6 else src["src_ip4"]
        reflector = self.reflector(**src)
        initiator = self.mpls_path_initiator(reflector, reply_src=configured)
        initiator.send_packet()
        wait_for_sbfd_reply(self, initiator, self.pg0)
        # a routed request is still answered from its destination
        routed = self.initiator(reflector)
        routed.send_packet()
        wait_for_sbfd_reply(self, routed, self.pg0)
        # with the source removed in place, pg0's address answers
        reflector.modify_parameters(src_ip4="0.0.0.0", src_ip6="::")
        initiator = self.mpls_path_initiator(reflector)
        initiator.send_packet()
        wait_for_sbfd_reply(self, initiator, self.pg0)
        # and the configured source again once it is set back
        reflector.modify_parameters(**src)
        initiator = self.mpls_path_initiator(reflector, reply_src=configured)
        initiator.send_packet()
        wait_for_sbfd_reply(self, initiator, self.pg0)

    def test_mpls_path_ttl(self):
        """S-BFD request is answered with any TTL or hop limit but 0"""
        reflector = self.reflector()
        label = self.explicit_null_label()
        # RFC 7881 section 5.1 has the initiator send TTL 1, but a uniform-mode
        # penultimate hop copies the label TTL into the IP header
        for ttl in (2, 64, 255):
            initiator = self.mpls_path_initiator(reflector, ttl=ttl)
            initiator.send_packet()
            wait_for_sbfd_reply(self, initiator, self.pg0)
        # the same with an explicit-null label
        for ttl in (64, 255):
            initiator = self.mpls_path_initiator(reflector, ttl=ttl)
            initiator.send_packet(
                self.labelled(initiator.create_packet(), self.pg0, label)
            )
            wait_for_sbfd_reply(self, initiator, self.pg0)
        # ip4-input and ip6-input drop TTL 0, so only a labelled request
        # brings one to the reflector
        request = self.mpls_path_initiator(reflector, ttl=0).create_packet()
        self.verify_dropped(self.labelled(request, self.pg0, label), "bad_ttl")
        # the same for a request to a local address: TTL 1 is answered, as
        # plain IP and with an explicit-null label, and TTL 0 is dropped
        routed = self.initiator(reflector, ttl=1)
        routed.send_packet()
        wait_for_sbfd_reply(self, routed, self.pg0)
        routed.send_packet(self.labelled(routed.create_packet(), self.pg0, label))
        wait_for_sbfd_reply(self, routed, self.pg0)
        request = self.initiator(reflector, ttl=0).create_packet()
        self.verify_dropped(self.labelled(request, self.pg0, label), "bad_ttl")

    def test_mpls_path_bad_checksum(self):
        """S-BFD request to 127/8 with bad UDP checksum is dropped"""
        request = self.mpls_path_initiator(self.reflector()).create_packet()
        if self.af == AF_INET6:
            good = IPv6(scapy.compat.raw(request[IPv6]))[UDP].chksum
            # ip6-local counts its errors as ip6-input
            path = "/err/ip6-input/udp_checksum"
        else:
            good = IP(scapy.compat.raw(request[IP]))[UDP].chksum
            path = "/err/ip4-local/udp_checksum"
        # 0 and 0xffff stand for the same checksum, so avoid both
        request[UDP].chksum = 1 if good != 1 else 2
        bad_checksum = self.statistics.get_err_counter(path)
        # dropped by ip4-local or ip6-local, as a routed request would be
        self.verify_dropped(request, "reflected", 0)
        self.assert_equal(self.statistics.get_err_counter(path), bad_checksum + 1, path)

    def enable_mpls(self):
        """enable MPLS on pg0 and pg1"""
        VppMplsTable(self, 0).add_vpp_config()
        self.pg0.enable_mpls()
        self.pg1.enable_mpls()
        self.mpls_enabled = True

    def explicit_null_label(self):
        """enable MPLS on pg0 and pg1, return the IPv4 or IPv6 Explicit NULL
        label (RFC 3032)"""
        self.enable_mpls()
        return 2 if self.af == AF_INET6 else 0

    def test_mpls_explicit_null(self):
        """S-BFD request with an explicit-null label is answered"""
        label = self.explicit_null_label()
        reflector = self.reflector()
        requests = self.counter("request", "dpo")
        initiator = self.mpls_path_initiator(reflector)
        initiator.send_packet(self.labelled(initiator.create_packet(), self.pg0, label))
        wait_for_sbfd_reply(self, initiator, self.pg0)
        # pg1 has no address to answer from
        no_src_addr = self.counter("no_src_addr")
        initiator = self.mpls_path_initiator(reflector, interface=self.pg1)
        initiator.send_packet(self.labelled(initiator.create_packet(), self.pg1, label))
        verify_no_sbfd_reply(self, self.pg0)
        self.assert_equal(self.counter("no_src_addr"), no_src_addr + 1, "no_src_addr")
        self.assert_equal(self.counter("request", "dpo"), requests + 2, "request")

    def local_label(self, label=34):
        """enable MPLS on pg0 and pg1, add a local label that is popped for a
        lookup in the default table, return it"""
        self.enable_mpls()
        if self.af == AF_INET6:
            nh, eos_proto = "::", FibPathProto.FIB_PATH_NH_PROTO_IP6
        else:
            nh, eos_proto = "0.0.0.0", FibPathProto.FIB_PATH_NH_PROTO_IP4
        VppMplsRoute(
            self,
            label,
            1,
            [VppRoutePath(nh, 0xFFFFFFFF, nh_table_id=0)],
            eos_proto=eos_proto,
        ).add_vpp_config()
        return label

    def test_mpls_local_label(self):
        """S-BFD request on a local label popped for an IP lookup is answered"""
        label = self.local_label()
        initiator = self.mpls_path_initiator(self.reflector())
        initiator.send_packet(self.labelled(initiator.create_packet(), self.pg0, label))
        wait_for_sbfd_reply(self, initiator, self.pg0)

    def test_mpls_local_label_other_table(self):
        """S-BFD request on a local label is answered on a VRF interface"""
        local_addr, next_hop = self.pg1_in_vrf()
        label = self.local_label()
        # The label, not pg1's table, picks the default table for the lookup.
        # ip4-local and ip6-local check the source in that table, so it needs
        # a route back to the initiator. Here that route goes out pg0, so a
        # reply routed in the default table would leave pg0; the reply is
        # routed in pg1's table and leaves pg1.
        prefix_len = 128 if self.af == AF_INET6 else 32
        self.route_via_pg0(next_hop, prefix_len)
        initiator = self.mpls_path_initiator(
            self.reflector(),
            interface=self.pg1,
            peer_addr=next_hop,
            reply_src=local_addr,
        )
        initiator.send_packet(self.labelled(initiator.create_packet(), self.pg1, label))
        wait_for_sbfd_reply(self, initiator, self.pg1)
        verify_no_sbfd_reply(self, self.pg0)

    def explicit_null_request(self, **ip_fields):
        """S-BFD request over an MPLS path, with the given IP header fields"""
        request = self.mpls_path_initiator(self.reflector()).create_packet()
        ip = request[IPv6] if self.af == AF_INET6 else request[IP]
        for name, value in ip_fields.items():
            setattr(ip, name, value)
        return request

    def verify_explicit_null_dropped(self, request, counter, length=None):
        """send request, or its first length bytes, with an explicit-null
        label, verify that the -dpo node drops and counts it"""
        label = self.explicit_null_label()
        self.verify_dropped(
            self.labelled(request, self.pg0, label, length), counter, node="dpo"
        )

    def test_mpls_explicit_null_truncated_header(self):
        """S-BFD request with explicit-null label and truncated headers is dropped"""
        label = self.explicit_null_label()
        # covers dropping a truncated header; the -dpo node checks the length
        # first so that it reads nothing beyond the received data, and for
        # IPv6 the payload length check would drop this packet too
        # one byte short of the base header, which still holds enough of the
        # destination for the 127/8 or ::ffff:127.0.0.0/104 entry to match
        length = (40 if self.af == AF_INET6 else 20) - 1
        # a destination no other test uses, so that what an earlier packet
        # left in the buffer is unlikely to complete the cut-off byte
        dst = "::ffff:127.0.0.77" if self.af == AF_INET6 else "127.0.0.77"
        request = self.explicit_null_request(dst=dst)
        self.verify_dropped(
            self.labelled(request, self.pg0, label, length), "bad_length", node="dpo"
        )
        # The IP header alone, then the IP and UDP headers alone, with the IP
        # and UDP lengths to match: exactly what the -dpo node reads. It drops
        # the first as no request and passes the second to the reflector,
        # which drops it as malformed.
        if self.af == AF_INET6:
            ip_only = request[IPv6].copy()
            ip_only.nh = 17
        else:
            ip_only = request[IP].copy()
            ip_only.proto = 17
        ip_only.remove_payload()
        udp_only = ip_only / UDP(sport=request[UDP].sport, dport=BFD_UDP_SBFD_PORT)
        self.verify_dropped(
            self.labelled(ip_only, self.pg0, label), "not_request", node="dpo"
        )
        bad = self.counter("bad")
        self.verify_dropped(
            self.labelled(udp_only, self.pg0, label), "request", node="dpo"
        )
        self.assert_equal(self.counter("bad"), bad + 1, "bad")

    def test_mpls_explicit_null_ip4_options(self):
        """S-BFD request with explicit-null label and IPv4 options is dropped"""
        if self.af == AF_INET6:
            self.skipTest("IPv4 only")
        # eight zero option bytes, where ip4-local, which expects a 20-byte
        # header, would find a UDP checksum of 0, which means none
        request = self.explicit_null_request(options=IPOption(b"\x00" * 8))
        good = IP(scapy.compat.raw(request[IP]))[UDP].chksum
        request[UDP].chksum = 1 if good != 1 else 2
        self.verify_explicit_null_dropped(request, "bad_ihl")

    def test_mpls_explicit_null_bad_version(self):
        """S-BFD request with explicit-null label and bad IP version is dropped"""
        version = 4 if self.af == AF_INET6 else 6
        request = self.explicit_null_request(version=version)
        self.verify_explicit_null_dropped(request, "bad_version")

    def test_mpls_explicit_null_bad_ihl(self):
        """S-BFD request with explicit-null label and IPv4 IHL 4 is dropped"""
        if self.af == AF_INET6:
            self.skipTest("IPv4 only")
        self.verify_explicit_null_dropped(self.explicit_null_request(ihl=4), "bad_ihl")

    def test_mpls_explicit_null_bad_ip4_checksum(self):
        """S-BFD request with explicit-null label and bad IPv4 checksum is dropped"""
        if self.af == AF_INET6:
            self.skipTest("IPv4 only")
        request = self.explicit_null_request()
        good = IP(scapy.compat.raw(request[IP])).chksum
        request[IP].chksum = 1 if good != 1 else 2
        self.verify_explicit_null_dropped(request, "bad_checksum")

    def test_mpls_explicit_null_bad_length(self):
        """S-BFD request with explicit-null label and wrong IP length is dropped"""
        label = self.explicit_null_label()
        request = self.explicit_null_request()
        if self.af == AF_INET6:
            request[IPv6].plen = len(request[UDP]) + 1
        else:
            request[IP].len = len(request[IP]) + 1
            # without a UDP checksum, ip4-local does not notice either
            request[UDP].chksum = 0
        self.verify_dropped(
            self.labelled(request, self.pg0, label), "bad_length", node="dpo"
        )
        if self.af == AF_INET:
            # a total length of just the header is not below the header
            # length: the -dpo node passes it on, and the UDP datagram after
            # the header does not fit in it, so it is not answered
            request[IP].len = 20
            self.verify_dropped(
                self.labelled(request, self.pg0, label), "request", node="dpo"
            )

    def other_traffic(self, ttl, dst=None):
        """packets to 127/8 or ::ffff:127.0.0.0/104 which are not S-BFD"""
        dst = dst or self.mpls_path_dsts[0]
        ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        if self.af == AF_INET6:
            ip, echo = IPv6(src=self.peer_addr, dst=dst, hlim=ttl), ICMPv6EchoRequest()
        else:
            ip, echo = IP(src=self.peer_addr, dst=dst, ttl=ttl), ICMP()
        return [
            ether / ip / UDP(sport=50000, dport=1234) / Raw(b"\xa5" * 24),
            # TCP has its destination port where UDP has it
            ether / ip / TCP(sport=50000, dport=BFD_UDP_SBFD_PORT),
            ether / ip / echo,
        ]

    def route_via_pg0(self, prefix, prefix_len):
        """add route to prefix via pg0's remote host"""
        nh = self.pg0.remote_ip6 if self.af == AF_INET6 else self.pg0.remote_ip4
        route = VppIpRoute(
            self, prefix, prefix_len, [VppRoutePath(nh, self.pg0.sw_if_index)]
        )
        route.add_vpp_config()
        return route

    def verify_forwarded(self, packets, dst=None):
        """send packets with TTL 64 and verify they leave pg0 with TTL 63"""
        dst = dst or self.mpls_path_dsts[0]
        for p in self.send_and_expect(self.pg0, packets, self.pg0):
            if self.af == AF_INET6:
                self.assert_equal(p[IPv6].hlim, 63, "IPv6 hop limit")
                self.assert_equal(p[IPv6].dst, dst, "IPv6 dst")
            else:
                self.assert_equal(p[IP].ttl, 63, "IPv4 TTL")
                self.assert_equal(p[IP].dst, dst, "IPv4 dst")

    def test_mpls_path_other_traffic(self):
        """other traffic to 127/8 is dropped while a reflector exists"""
        names = ("reflected", "bad", "bad_ttl", "no_src_addr")
        packets = self.other_traffic(1) + self.other_traffic(64)
        not_request = self.counter("not_request", "dpo")
        # without a route covering 127/8, dropped with or without a reflector
        self.send_and_assert_no_replies(self.pg0, packets)
        r0 = self.reflector(0x0A0B0C0D)
        before = {name: self.counter(name) for name in names}
        self.send_and_assert_no_replies(self.pg0, packets)
        r0.remove_vpp_config()
        # a default route forwards it, but not while a reflector exists
        if self.af == AF_INET6:
            self.route_via_pg0("::", 0)
        else:
            self.route_via_pg0("0.0.0.0", 0)
        self.verify_forwarded(self.other_traffic(64))
        r1 = self.reflector(0x01020304)
        r2 = self.reflector(0xFFFFFFFF)
        self.send_and_assert_no_replies(self.pg0, packets)
        r1.remove_vpp_config()
        self.send_and_assert_no_replies(self.pg0, packets)
        r2.remove_vpp_config()
        self.verify_forwarded(self.other_traffic(64))
        for name in names:
            self.assert_equal(self.counter(name), before[name], name)
        # sent three times while a reflector existed
        self.assert_equal(
            self.counter("not_request", "dpo"),
            not_request + 3 * len(packets),
            "not_request",
        )

    def test_mpls_path_fragments(self):
        """fragments of an S-BFD request to 127/8 are dropped"""
        if self.af == AF_INET6:
            self.skipTest("IPv4 only")
        request = self.mpls_path_initiator(self.reflector()).create_packet()
        # the first fragment holds the UDP header, to port 7784
        self.verify_dropped(fragment(request, fragsize=16), "not_request", 2, "dpo")

    def test_mpls_path_operator_route(self):
        """an operator route to 127/8 is overridden while a reflector exists"""
        self.route_via_pg0(*self.mpls_path_prefix)
        packets = self.other_traffic(64)
        self.verify_forwarded(packets)
        reflector = self.reflector()
        initiator = self.mpls_path_initiator(reflector)
        initiator.send_packet()
        wait_for_sbfd_reply(self, initiator, self.pg0)
        self.send_and_assert_no_replies(self.pg0, packets)
        reflector.remove_vpp_config()
        self.verify_forwarded(packets)

    def test_mpls_path_longer_prefix(self):
        """a route to part of 127/8 is still used while a reflector exists"""
        if self.af == AF_INET6:
            dst, prefix_len = "::ffff:127.1.2.3", 128
        else:
            dst, prefix_len = "127.1.2.3", 32
        self.route_via_pg0(dst, prefix_len)
        reflector = self.reflector()
        names = ("request", "not_request")
        before = {name: self.counter(name, "dpo") for name in names}
        reflected = self.counter("reflected")
        # an S-BFD request to that address is forwarded too, not answered
        request = self.mpls_path_initiator(reflector, dst, ttl=64).create_packet()
        self.verify_forwarded(self.other_traffic(64, dst) + [request], dst)
        for name in names:
            self.assert_equal(self.counter(name, "dpo"), before[name], name)
        self.assert_equal(self.counter("reflected"), reflected, "reflected")

    def test_mpls_path_vrf(self):
        """S-BFD request over an MPLS path in another table is not answered"""
        local_addr, next_hop = self.pg1_in_vrf()
        label = self.explicit_null_label()
        initiator = self.mpls_path_initiator(
            self.reflector(),
            interface=self.pg1,
            peer_addr=next_hop,
            reply_src=local_addr,
        )
        request = initiator.create_packet()
        # only the default tables have the 127/8 and ::ffff:127.0.0.0/104
        # entries, so neither form reaches the -dpo node
        for packet in (request, self.labelled(request, self.pg1, label)):
            self.verify_dropped(packet, "request", 0, "dpo", self.pg1)

    def test_mpls_path_last_discriminator_deleted(self):
        """MPLS path delivery is removed with the last S-BFD discriminator"""
        names = ("reflected", "bad", "bad_ttl", "no_disc")
        self.assertFalse(find_route(self, *self.mpls_path_prefix))
        r1 = self.reflector(0x01020304)
        r2 = self.reflector(0xFFFFFFFF)
        self.assertTrue(find_route(self, *self.mpls_path_prefix))
        # the entry and its path show the S-BFD DPO; the CLI takes no dotted
        # quad in an IPv6 address
        if self.af == AF_INET6:
            show_entry = "show ip6 fib ::ffff:7f00:0/104"
        else:
            show_entry = "show ip fib 127.0.0.0/8"
        for cli in (show_entry, "show fib paths"):
            self.assertIn("bfd-sbfd-reflector", self.vapi.cli(cli), cli)
        r1.remove_vpp_config()
        self.assertTrue(find_route(self, *self.mpls_path_prefix))
        initiator = self.mpls_path_initiator(r2)
        initiator.send_packet()
        wait_for_sbfd_reply(self, initiator, self.pg0)
        r2.remove_vpp_config()
        self.assertFalse(find_route(self, *self.mpls_path_prefix))
        before = {name: self.counter(name) for name in names}
        self.send_and_assert_no_replies(self.pg0, initiator.create_packet())
        for name in names:
            self.assert_equal(self.counter(name), before[name], name)
        r2.add_vpp_config()
        self.assertTrue(find_route(self, *self.mpls_path_prefix))
        initiator.send_packet()
        wait_for_sbfd_reply(self, initiator, self.pg0)


@parameterized_class(
    [
        {"multihop": False},
        {"multihop": True},
    ]
)
@tag_run_solo
@tag_fixme_vpp_workers
class BFD6TestCase(VppTestCase):
    """BFD v6 test"""

    pg0 = None
    interface0 = None
    vpp_clock_offset = None
    vpp_session = None
    test_session = None
    src_ip6_net = ""
    dst_ip6_net = ""

    @classmethod
    def setUpClass(cls):
        super(BFD6TestCase, cls).setUpClass()
        hoptype_str = "MultiHop" if cls.multihop else "SingleHop"
        cls.__doc__ = (
            f"""""Bidirectional Forwarding Detection (BFD) - IPv6, {hoptype_str}"""
        )
        cls.vapi.cli("set log class bfd level debug")
        try:
            cls.create_pg_interfaces([0])
            cls.pg0.config_ip6()
            cls.pg0.configure_ipv6_neighbors()
            cls.pg0.admin_up()
            cls.pg0.resolve_ndp()
            cls.create_loopback_interfaces(1)
            cls.loopback0 = cls.lo_interfaces[0]
            cls.loopback0.config_ip6()
            cls.loopback0.admin_up()

        except Exception:
            super(BFD6TestCase, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(BFD6TestCase, cls).tearDownClass()

    def setUp(self):
        super(BFD6TestCase, self).setUp()
        self.factory = AuthKeyFactory()
        self.vapi.want_bfd_events()
        self.pg0.enable_capture()
        set_ipv6_pfx_route_info(self, self.pg0, BFD_IPV6_REMOTE_ADDR, True)

        try:
            if self.multihop:
                self.interface0 = None
                self.bfd_udp4_sessions = self.statistics[BFD_STATS_V4_MH_PATH]
                self.bfd_udp6_sessions = self.statistics[BFD_STATS_V6_MH_PATH]
            else:
                self.interface0 = self.pg0
                self.bfd_udp4_sessions = self.statistics[BFD_STATS_V4_SH_PATH]
                self.bfd_udp6_sessions = self.statistics[BFD_STATS_V6_SH_PATH]

            self.vpp_session = VppBFDUDPSession(
                self,
                self.interface0,
                self.dst_ip6_net,
                local_addr=self.src_ip6_net,
                af=AF_INET6,
                multihop=self.multihop,
            )
            self.vpp_session.add_vpp_config()
            self.vpp_session.admin_up()
            self.test_session = BFDTestSession(
                self,
                self.pg0,
                AF_INET6,
                local_addr=self.src_ip6_net,
                peer_addr=self.dst_ip6_net,
                multihop=self.multihop,
            )
            self.logger.debug(self.vapi.cli("show adj nbr"))
        except BaseException:
            self.vapi.want_bfd_events(enable_disable=0)
            raise

    def tearDown(self):
        self.vpp_session.remove_vpp_config()
        if not self.vpp_dead:
            self.vapi.want_bfd_events(enable_disable=0)
        self.vapi.collect_events()  # clear the event queue
        super(BFD6TestCase, self).tearDown()

    def test_session_up(self):
        """bring BFD session up"""
        bfd_session_up(self)
        if self.multihop:
            bfd_udp4_sessions = self.statistics[BFD_STATS_V4_MH_PATH]
            bfd_udp6_sessions = self.statistics[BFD_STATS_V6_MH_PATH]
        else:
            bfd_udp4_sessions = self.statistics[BFD_STATS_V4_SH_PATH]
            bfd_udp6_sessions = self.statistics[BFD_STATS_V6_SH_PATH]

        self.assert_equal(bfd_udp4_sessions, self.bfd_udp4_sessions)
        self.assert_equal(bfd_udp6_sessions - self.bfd_udp6_sessions, 1)

    def test_session_up_by_ip(self):
        """bring BFD session up - first frame looked up by address pair"""
        self.logger.info("BFD: Sending Slow control frame")
        self.test_session.update(my_discriminator=randint(0, 40000000))
        self.test_session.send_packet()
        self.pg0.enable_capture()
        p = self.pg0.wait_for_packet(1)
        self.assert_equal(
            p[BFD].your_discriminator,
            self.test_session.my_discriminator,
            "BFD - your discriminator",
        )
        self.assert_equal(p[BFD].state, BFDState.init, BFDState)
        self.test_session.update(
            your_discriminator=p[BFD].my_discriminator, state=BFDState.up
        )
        self.logger.info("BFD: Waiting for event")
        e = self.vapi.wait_for_event(1, "bfd_udp_session_event")
        verify_event(self, e, expected_state=BFDState.init)
        self.logger.info("BFD: Sending Up")
        self.test_session.send_packet()
        self.logger.info("BFD: Waiting for event")
        e = self.vapi.wait_for_event(1, "bfd_udp_session_event")
        verify_event(self, e, expected_state=BFDState.up)
        self.logger.info("BFD: Session is Up")
        self.test_session.update(state=BFDState.up)
        self.test_session.send_packet()
        self.assert_equal(self.vpp_session.state, BFDState.up, BFDState)

    def test_hold_up(self):
        """hold BFD session up"""
        bfd_session_up(self)
        for dummy in range(self.test_session.detect_mult * 2):
            wait_for_bfd_packet(self)
            self.test_session.send_packet()
        self.assert_equal(len(self.vapi.collect_events()), 0, "number of bfd events")
        self.assert_equal(self.vpp_session.state, BFDState.up, BFDState)

    def test_sbfd_reflector_coexistence(self):
        """S-BFD reflector next to an Up BFD session"""
        sbfd_reflector_coexistence(self)

    def test_echo_looped_back(self):
        """echo packets looped back"""

        if self.multihop:
            self.skipTest(
                f"Skipping because echo functionality is not supported with multihop"
            )

        bfd_session_up(self)
        stats_before = bfd_grab_stats_snapshot(self)
        self.pg0.enable_capture()
        echo_packet_count = 10
        # random source port low enough to increment a few times..
        udp_sport_tx = randint(1, 50000)
        udp_sport_rx = udp_sport_tx
        echo_packet = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IPv6(src=self.pg0.remote_ip6, dst=self.pg0.remote_ip6)
            / UDP(dport=BFD.udp_dport_echo)
            / Raw("this should be looped back")
        )
        for dummy in range(echo_packet_count):
            self.sleep(0.01, "delay between echo packets")
            echo_packet[UDP].sport = udp_sport_tx
            udp_sport_tx += 1
            self.logger.debug(ppp("Sending packet:", echo_packet))
            self.pg0.add_stream(echo_packet)
            self.pg_start()
        counter = 0
        bfd_control_packets_rx = 0
        while counter < echo_packet_count:
            p = self.pg0.wait_for_packet(1)
            self.logger.debug(ppp("Got packet:", p))
            ether = p[Ether]
            self.assert_equal(self.pg0.remote_mac, ether.dst, "Destination MAC")
            self.assert_equal(self.pg0.local_mac, ether.src, "Source MAC")
            ip = p[IPv6]
            self.assert_equal(self.pg0.remote_ip6, ip.dst, "Destination IP")
            udp = p[UDP]
            if udp.dport == BFD.udp_dport:
                bfd_control_packets_rx += 1
                continue
            self.assert_equal(self.pg0.remote_ip6, ip.src, "Source IP")
            self.assert_equal(udp.dport, BFD.udp_dport_echo, "UDP destination port")
            self.assert_equal(udp.sport, udp_sport_rx, "UDP source port")
            udp_sport_rx += 1
            # need to compare the hex payload here, otherwise BFD_vpp_echo
            # gets in way
            self.assertEqual(
                scapy.compat.raw(p[UDP].payload),
                scapy.compat.raw(echo_packet[UDP].payload),
                "Received packet is not the echo packet sent",
            )
            counter += 1
        self.assert_equal(
            udp_sport_tx,
            udp_sport_rx,
            "UDP source port (== ECHO packet identifier for test purposes)",
        )
        stats_after = bfd_grab_stats_snapshot(self)
        diff = bfd_stats_diff(stats_before, stats_after)
        self.assertEqual(0, diff.rx, "RX counter bumped but no BFD packets sent")
        self.assertEqual(
            0, diff.rx_echo, "RX echo counter bumped but no BFD session exists"
        )
        self.assertEqual(
            0, diff.tx_echo, "TX echo counter bumped but no BFD session exists"
        )

    def test_echo(self):
        """echo function"""

        if self.multihop:
            self.skipTest(
                f"Skipping because echo functionality is not supported with multihop"
            )

        stats_before = bfd_grab_stats_snapshot(self)
        bfd_session_up(self)
        self.test_session.update(required_min_echo_rx=150000)
        self.test_session.send_packet()
        detection_time = (
            self.test_session.detect_mult
            * self.vpp_session.required_min_rx
            / USEC_IN_SEC
        )
        # echo shouldn't work without echo source set
        for dummy in range(10):
            sleep = self.vpp_session.required_min_rx / USEC_IN_SEC
            self.sleep(sleep, "delay before sending bfd packet")
            self.test_session.send_packet()
        p = wait_for_bfd_packet(self, pcap_time_min=time.time() - self.vpp_clock_offset)
        self.assert_equal(
            p[BFD].required_min_rx_interval,
            self.vpp_session.required_min_rx,
            "BFD required min rx interval",
        )
        self.test_session.send_packet()
        self.vapi.bfd_udp_set_echo_source(sw_if_index=self.loopback0.sw_if_index)
        echo_seen = False
        # should be turned on - loopback echo packets
        for dummy in range(3):
            loop_until = time.time() + 0.75 * detection_time
            while time.time() < loop_until:
                p = self.pg0.wait_for_packet(1)
                self.logger.debug(ppp("Got packet:", p))
                if p[UDP].dport == BFD.udp_dport_echo:
                    self.assert_equal(
                        p[IPv6].dst, self.pg0.local_ip6, "BFD ECHO dst IP"
                    )
                    self.assertNotEqual(
                        p[IPv6].src,
                        self.loopback0.local_ip6,
                        "BFD ECHO src IP equal to loopback IP",
                    )
                    self.logger.debug(ppp("Looping back packet:", p))
                    self.assert_equal(
                        p[Ether].dst,
                        self.pg0.remote_mac,
                        "ECHO packet destination MAC address",
                    )
                    self.test_session.rx_packets_echo += 1
                    self.test_session.tx_packets_echo += 1
                    p[Ether].dst = self.pg0.local_mac
                    self.pg0.add_stream(p)
                    self.pg_start()
                    echo_seen = True
                elif p.haslayer(BFD):
                    self.test_session.rx_packets += 1
                    if echo_seen:
                        self.assertGreaterEqual(
                            p[BFD].required_min_rx_interval, 1000000
                        )
                    if "P" in p.sprintf("%BFD.flags%"):
                        final = self.test_session.create_packet()
                        final[BFD].flags = "F"
                        self.test_session.send_packet(final)
                else:
                    raise Exception(ppp("Received unknown packet:", p))

                self.assert_equal(
                    len(self.vapi.collect_events()), 0, "number of bfd events"
                )
            self.test_session.send_packet()
        self.assertTrue(echo_seen, "No echo packets received")

        stats_after = bfd_grab_stats_snapshot(self)
        diff = bfd_stats_diff(stats_before, stats_after)
        # our rx is vpp tx and vice versa, also tolerate one packet off
        self.assert_in_range(
            self.test_session.tx_packets, diff.rx - 1, diff.rx + 1, "RX counter"
        )
        self.assert_in_range(
            self.test_session.rx_packets, diff.tx - 1, diff.tx + 1, "TX counter"
        )
        self.assert_in_range(
            self.test_session.tx_packets_echo,
            diff.rx_echo - 1,
            diff.rx_echo + 1,
            "RX echo counter",
        )
        self.assert_in_range(
            self.test_session.rx_packets_echo,
            diff.tx_echo - 1,
            diff.tx_echo + 1,
            "TX echo counter",
        )

    def test_intf_deleted(self):
        """interface with bfd session deleted"""
        intf = VppLoInterface(self)
        intf.config_ip6()
        intf.admin_up()
        sw_if_index = intf.sw_if_index

        # Setup routing info for multihop
        set_ipv6_pfx_route_info(self, intf, BFD_IPV6_REMOTE_ADDR2, False)

        vpp_session = VppBFDUDPSession(
            self,
            intf,
            self.dst_ip6_net,
            local_addr=self.src_ip6_net,
            af=AF_INET6,
            multihop=self.multihop,
        )

        vpp_session.add_vpp_config()
        vpp_session.admin_up()
        intf.remove_vpp_config()

        # BFD session is removed only for single-hop session
        if self.multihop:
            self.assertTrue(vpp_session.query_vpp_config())
        else:
            e = self.vapi.wait_for_event(1, "bfd_udp_session_event")
            self.assert_equal(e.sw_if_index, sw_if_index, "sw_if_index")
            self.assertFalse(vpp_session.query_vpp_config())


@parameterized_class(
    [
        {"multihop": False},
        {"multihop": True},
    ]
)
@tag_run_solo
class BFDFIBTestCase(VppTestCase):
    """BFD-FIB interactions (IPv6)"""

    vpp_session = None
    test_session = None
    src_ip6_net = ""
    dst_ip6_net = ""

    @classmethod
    def setUpClass(cls):
        super(BFDFIBTestCase, cls).setUpClass()
        hoptype_str = "MultiHop" if cls.multihop else "SingleHop"
        cls.__doc__ = f"""""BFD-FIB interactions (IPv6) - {hoptype_str}"""
        cls.vapi.cli("set log class bfd level debug")

    @classmethod
    def tearDownClass(cls):
        super(BFDFIBTestCase, cls).tearDownClass()

    def setUp(self):
        super(BFDFIBTestCase, self).setUp()
        self.create_pg_interfaces(range(1))
        self.create_loopback_interfaces(1)
        self.loopback0 = self.lo_interfaces[0]
        self.loopback0.config_ip6()
        self.loopback0.admin_up()

        self.vapi.want_bfd_events()
        self.pg0.enable_capture()

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip6()
            i.configure_ipv6_neighbors()

        set_ipv6_pfx_route_info(self, self.pg0, BFD_IPV6_REMOTE_ADDR, True)

    def tearDown(self):
        if not self.vpp_dead:
            self.vapi.want_bfd_events(enable_disable=False)

        super(BFDFIBTestCase, self).tearDown()

    @staticmethod
    def pkt_is_not_data_traffic(p):
        """not data traffic implies BFD or the usual IPv6 ND/RA"""
        if p.haslayer(BFD) or is_ipv6_misc(p):
            return True
        return False

    def test_session_with_fib(self):
        """BFD-FIB interactions"""

        # packets to match against both of the routes
        p = [
            (
                Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
                / IPv6(src="3001::1", dst="2001::1")
                / UDP(sport=1234, dport=1234)
                / Raw(b"\xa5" * 100)
            ),
            (
                Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
                / IPv6(src="3001::1", dst="2002::1")
                / UDP(sport=1234, dport=1234)
                / Raw(b"\xa5" * 100)
            ),
        ]

        # Two different routes via a next-hop that will have a BFD session.
        # One of the routes is non-recursive route only for single-hop.
        if self.multihop:
            intf_index = 0xFFFFFFFF
        else:
            intf_index = self.pg0.sw_if_index

        ip_2001_s_64 = VppIpRoute(
            self,
            "2001::",
            64,
            [VppRoutePath(self.dst_ip6_net, intf_index)],
        )
        ip_2002_s_64 = VppIpRoute(
            self, "2002::", 64, [VppRoutePath(self.dst_ip6_net, 0xFFFFFFFF)]
        )
        ip_2001_s_64.add_vpp_config()
        ip_2002_s_64.add_vpp_config()

        # bring the session up now the routes are present
        self.vpp_session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip6_net,
            local_addr=self.src_ip6_net,
            af=AF_INET6,
            multihop=self.multihop,
        )
        self.vpp_session.add_vpp_config()
        self.vpp_session.admin_up()
        self.test_session = BFDTestSession(
            self,
            self.pg0,
            AF_INET6,
            local_addr=self.src_ip6_net,
            peer_addr=self.dst_ip6_net,
            multihop=self.multihop,
        )

        # session is up - traffic passes
        bfd_session_up(self)

        self.pg0.add_stream(p)
        self.pg_start()
        for packet in p:
            captured = self.pg0.wait_for_packet(
                1, filter_out_fn=self.pkt_is_not_data_traffic
            )
            self.assertEqual(captured[IPv6].dst, packet[IPv6].dst)

        # session is down - traffic is dropped
        bfd_session_down(self)

        self.pg0.add_stream(p)
        self.pg_start()
        with self.assertRaises(CaptureTimeoutError):
            self.pg0.wait_for_packet(1, self.pkt_is_not_data_traffic)

        # session is up - traffic passes
        bfd_session_up(self)

        self.pg0.add_stream(p)
        self.pg_start()
        for packet in p:
            captured = self.pg0.wait_for_packet(
                1, filter_out_fn=self.pkt_is_not_data_traffic
            )
            self.assertEqual(captured[IPv6].dst, packet[IPv6].dst)


@unittest.skipUnless(config.extended, "part of extended tests")
class BFDTunTestCase(VppTestCase):
    """BFD over GRE tunnel"""

    vpp_session = None
    test_session = None

    @classmethod
    def setUpClass(cls):
        super(BFDTunTestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(BFDTunTestCase, cls).tearDownClass()

    def setUp(self):
        super(BFDTunTestCase, self).setUp()
        self.create_pg_interfaces(range(1))

        self.vapi.want_bfd_events()
        self.pg0.enable_capture()

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        if not self.vpp_dead:
            self.vapi.want_bfd_events(enable_disable=0)

        super(BFDTunTestCase, self).tearDown()

    @staticmethod
    def pkt_is_not_data_traffic(p):
        """not data traffic implies BFD or the usual IPv6 ND/RA"""
        if p.haslayer(BFD) or is_ipv6_misc(p):
            return True
        return False

    def test_bfd_o_gre(self):
        """BFD-o-GRE"""

        # A GRE interface over which to run a BFD session
        gre_if = VppGreInterface(self, self.pg0.local_ip4, self.pg0.remote_ip4)
        gre_if.add_vpp_config()
        gre_if.admin_up()
        gre_if.config_ip4()

        # bring the session up now the routes are present
        self.vpp_session = VppBFDUDPSession(
            self, gre_if, gre_if.remote_ip4, is_tunnel=True
        )
        self.vpp_session.add_vpp_config()
        self.vpp_session.admin_up()

        self.test_session = BFDTestSession(
            self,
            gre_if,
            AF_INET,
            tunnel_header=(IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) / GRE()),
            phy_interface=self.pg0,
        )

        # packets to match against both of the routes
        p = [
            (
                Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
                / IP(src=self.pg0.remote_ip4, dst=gre_if.remote_ip4)
                / UDP(sport=1234, dport=1234)
                / Raw(b"\xa5" * 100)
            )
        ]

        # session is up - traffic passes
        bfd_session_up(self)

        self.send_and_expect(self.pg0, p, self.pg0)

        # bring session down
        bfd_session_down(self)


@parameterized_class(
    [
        {"multihop": False},
        {"multihop": True},
    ]
)
@tag_run_solo
class BFDSHA1TestCase(VppTestCase):
    """BFD SHA1 test"""

    pg0 = None
    vpp_clock_offset = None
    vpp_session = None
    test_session = None
    src_ip_net = ""
    dst_ip_net = ""

    @classmethod
    def setUpClass(cls):
        super(BFDSHA1TestCase, cls).setUpClass()
        hoptype_str = "MultiHop" if cls.multihop else "SingleHop"
        cls.__doc__ = f"""""Bidirectional Forwarding Detection (BFD) - SHA1 auth - {hoptype_str}"""
        cls.vapi.cli("set log class bfd level debug")
        try:
            cls.create_pg_interfaces([0])
            cls.create_loopback_interfaces(1)
            cls.loopback0 = cls.lo_interfaces[0]
            cls.loopback0.config_ip4()
            cls.loopback0.admin_up()
            cls.pg0.config_ip4()
            cls.pg0.configure_ipv4_neighbors()
            cls.pg0.admin_up()
            cls.pg0.resolve_arp()

        except Exception:
            super(BFDSHA1TestCase, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(BFDSHA1TestCase, cls).tearDownClass()

    def setUp(self):
        super(BFDSHA1TestCase, self).setUp()
        self.factory = AuthKeyFactory()
        self.vapi.want_bfd_events()
        self.pg0.enable_capture()
        set_ipv4_pfx_route_info(self, self.pg0, BFD_IPV4_REMOTE_ADDR, True)

    def tearDown(self):
        if not self.vpp_dead:
            self.vapi.want_bfd_events(enable_disable=False)
        self.vapi.collect_events()  # clear the event queue
        super(BFDSHA1TestCase, self).tearDown()

    def test_session_up(self):
        """bring BFD session up"""
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        self.vpp_session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
            sha1_key=key,
        )
        self.vpp_session.add_vpp_config()
        self.vpp_session.admin_up()
        self.test_session = BFDTestSession(
            self,
            self.pg0,
            AF_INET,
            local_addr=self.src_ip_net,
            peer_addr=self.dst_ip_net,
            multihop=self.multihop,
            sha1_key=key,
            bfd_key_id=self.vpp_session.bfd_key_id,
        )
        bfd_session_up(self)

    def test_hold_up(self):
        """hold BFD session up"""
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        self.vpp_session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
            sha1_key=key,
        )
        self.vpp_session.add_vpp_config()
        self.vpp_session.admin_up()
        self.test_session = BFDTestSession(
            self,
            self.pg0,
            AF_INET,
            local_addr=self.src_ip_net,
            peer_addr=self.dst_ip_net,
            multihop=self.multihop,
            sha1_key=key,
            bfd_key_id=self.vpp_session.bfd_key_id,
        )
        bfd_session_up(self)
        for dummy in range(self.test_session.detect_mult * 2):
            wait_for_bfd_packet(self)
            self.test_session.send_packet()
        self.assert_equal(self.vpp_session.state, BFDState.up, BFDState)

    def test_hold_up_meticulous(self):
        """hold BFD session up - meticulous auth"""
        key = self.factory.create_random_key(self, BFDAuthType.meticulous_keyed_sha1)
        key.add_vpp_config()
        self.vpp_session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
            sha1_key=key,
        )
        self.vpp_session.add_vpp_config()
        self.vpp_session.admin_up()
        # specify sequence number so that it wraps
        self.test_session = BFDTestSession(
            self,
            self.pg0,
            AF_INET,
            local_addr=self.src_ip_net,
            peer_addr=self.dst_ip_net,
            multihop=self.multihop,
            sha1_key=key,
            bfd_key_id=self.vpp_session.bfd_key_id,
            our_seq_number=0xFFFFFFFF - 4,
        )
        bfd_session_up(self)
        for dummy in range(30):
            wait_for_bfd_packet(self)
            self.test_session.inc_seq_num()
            self.test_session.send_packet()
        self.assert_equal(self.vpp_session.state, BFDState.up, BFDState)

    def test_send_bad_seq_number(self):
        """session is not kept alive by msgs with bad sequence numbers"""
        key = self.factory.create_random_key(self, BFDAuthType.meticulous_keyed_sha1)
        key.add_vpp_config()
        self.vpp_session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
            sha1_key=key,
        )
        self.vpp_session.add_vpp_config()
        self.test_session = BFDTestSession(
            self,
            self.pg0,
            AF_INET,
            local_addr=self.src_ip_net,
            peer_addr=self.dst_ip_net,
            multihop=self.multihop,
            sha1_key=key,
            bfd_key_id=self.vpp_session.bfd_key_id,
        )
        bfd_session_up(self)
        detection_time = (
            self.test_session.detect_mult
            * self.vpp_session.required_min_rx
            / USEC_IN_SEC
        )
        send_until = time.time() + 2 * detection_time
        while time.time() < send_until:
            self.test_session.send_packet()
            self.sleep(
                0.7 * self.vpp_session.required_min_rx / USEC_IN_SEC,
                "time between bfd packets",
            )
        e = self.vapi.collect_events()
        # session should be down now, because the sequence numbers weren't
        # updated
        self.assert_equal(len(e), 1, "number of bfd events")
        verify_event(self, e[0], expected_state=BFDState.down)

    def execute_rogue_session_scenario(
        self,
        vpp_bfd_udp_session,
        legitimate_test_session,
        rogue_test_session,
        rogue_bfd_values=None,
    ):
        """execute a rogue session interaction scenario

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
            auth_type=self.test_session.auth_type,
        )
        if rogue_bfd_values:
            rogue_test_session.update(**rogue_bfd_values)
        rogue_test_session.update(state=BFDState.down)
        rogue_test_session.send_packet()
        wait_for_bfd_packet(self)
        self.assert_equal(self.vpp_session.state, BFDState.up, BFDState)

    def test_mismatch_auth(self):
        """session is not brought down by unauthenticated msg"""
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        vpp_session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
            sha1_key=key,
        )
        legitimate_test_session = BFDTestSession(
            self,
            self.pg0,
            AF_INET,
            local_addr=self.src_ip_net,
            peer_addr=self.dst_ip_net,
            multihop=self.multihop,
            sha1_key=key,
            bfd_key_id=vpp_session.bfd_key_id,
        )
        rogue_test_session = BFDTestSession(
            self,
            self.pg0,
            AF_INET,
            local_addr=self.src_ip_net,
            peer_addr=self.dst_ip_net,
            multihop=self.multihop,
        )
        self.execute_rogue_session_scenario(
            vpp_session, legitimate_test_session, rogue_test_session
        )

    def test_mismatch_bfd_key_id(self):
        """session is not brought down by msg with non-existent key-id"""
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        vpp_session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
            sha1_key=key,
        )
        # pick a different random bfd key id
        x = randint(0, 255)
        while x == vpp_session.bfd_key_id:
            x = randint(0, 255)
        legitimate_test_session = BFDTestSession(
            self,
            self.pg0,
            AF_INET,
            local_addr=self.src_ip_net,
            peer_addr=self.dst_ip_net,
            multihop=self.multihop,
            sha1_key=key,
            bfd_key_id=vpp_session.bfd_key_id,
        )
        rogue_test_session = BFDTestSession(
            self,
            self.pg0,
            AF_INET,
            local_addr=self.src_ip_net,
            peer_addr=self.dst_ip_net,
            multihop=self.multihop,
            sha1_key=key,
            bfd_key_id=x,
        )
        self.execute_rogue_session_scenario(
            vpp_session, legitimate_test_session, rogue_test_session
        )

    def test_mismatched_auth_type(self):
        """session is not brought down by msg with wrong auth type"""
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        vpp_session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
            sha1_key=key,
        )
        legitimate_test_session = BFDTestSession(
            self,
            self.pg0,
            AF_INET,
            local_addr=self.src_ip_net,
            peer_addr=self.dst_ip_net,
            multihop=self.multihop,
            sha1_key=key,
            bfd_key_id=vpp_session.bfd_key_id,
        )
        rogue_test_session = BFDTestSession(
            self,
            self.pg0,
            AF_INET,
            local_addr=self.src_ip_net,
            peer_addr=self.dst_ip_net,
            multihop=self.multihop,
            sha1_key=key,
            bfd_key_id=vpp_session.bfd_key_id,
        )
        self.execute_rogue_session_scenario(
            vpp_session,
            legitimate_test_session,
            rogue_test_session,
            {"auth_type": BFDAuthType.keyed_md5},
        )

    def test_restart(self):
        """simulate remote peer restart and resynchronization"""
        key = self.factory.create_random_key(self, BFDAuthType.meticulous_keyed_sha1)
        key.add_vpp_config()
        self.vpp_session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
            sha1_key=key,
        )
        self.vpp_session.add_vpp_config()
        self.test_session = BFDTestSession(
            self,
            self.pg0,
            AF_INET,
            local_addr=self.src_ip_net,
            peer_addr=self.dst_ip_net,
            multihop=self.multihop,
            sha1_key=key,
            bfd_key_id=self.vpp_session.bfd_key_id,
            our_seq_number=0,
        )
        bfd_session_up(self)
        # don't send any packets for 2*detection_time
        detection_time = (
            self.test_session.detect_mult
            * self.vpp_session.required_min_rx
            / USEC_IN_SEC
        )
        self.sleep(2 * detection_time, "simulating peer restart")
        events = self.vapi.collect_events()
        self.assert_equal(len(events), 1, "number of bfd events")
        verify_event(self, events[0], expected_state=BFDState.down)
        self.test_session.update(state=BFDState.down)
        # reset sequence number
        self.test_session.our_seq_number = 0
        self.test_session.vpp_seq_number = None
        # now throw away any pending packets
        self.pg0.enable_capture()
        self.test_session.my_discriminator = 0
        bfd_session_up(self)


@parameterized_class(
    [
        {"multihop": False},
        {"multihop": True},
    ]
)
@tag_run_solo
class BFDAuthOnOffTestCase(VppTestCase):
    """BFD Auth On/Off test"""

    pg0 = None
    vpp_session = None
    test_session = None

    @classmethod
    def setUpClass(cls):
        super(BFDAuthOnOffTestCase, cls).setUpClass()
        hoptype_str = "MultiHop" if cls.multihop else "SingleHop"
        cls.__doc__ = f"""""Bidirectional Forwarding Detection (BFD) - changing auth - {hoptype_str}"""
        cls.vapi.cli("set log class bfd level debug")
        try:
            cls.create_pg_interfaces([0])
            cls.create_loopback_interfaces(1)
            cls.loopback0 = cls.lo_interfaces[0]
            cls.loopback0.config_ip4()
            cls.loopback0.admin_up()
            cls.pg0.config_ip4()
            cls.pg0.configure_ipv4_neighbors()
            cls.pg0.admin_up()
            cls.pg0.resolve_arp()

        except Exception:
            super(BFDAuthOnOffTestCase, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(BFDAuthOnOffTestCase, cls).tearDownClass()

    def setUp(self):
        super(BFDAuthOnOffTestCase, self).setUp()
        self.factory = AuthKeyFactory()
        self.vapi.want_bfd_events()
        self.pg0.enable_capture()
        set_ipv4_pfx_route_info(self, self.pg0, BFD_IPV4_REMOTE_ADDR, True)

    def tearDown(self):
        if not self.vpp_dead:
            self.vapi.want_bfd_events(enable_disable=False)
        self.vapi.collect_events()  # clear the event queue
        super(BFDAuthOnOffTestCase, self).tearDown()

    def test_auth_on_immediate(self):
        """turn auth on without disturbing session state (immediate)"""
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        self.vpp_session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
        )
        self.vpp_session.add_vpp_config()
        self.test_session = BFDTestSession(
            self,
            self.pg0,
            AF_INET,
            local_addr=self.src_ip_net,
            peer_addr=self.dst_ip_net,
            multihop=self.multihop,
        )
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
        self.assert_equal(len(self.vapi.collect_events()), 0, "number of bfd events")

    def test_auth_off_immediate(self):
        """turn auth off without disturbing session state (immediate)"""
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        self.vpp_session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
            sha1_key=key,
        )
        self.vpp_session.add_vpp_config()
        self.test_session = BFDTestSession(
            self,
            self.pg0,
            AF_INET,
            local_addr=self.src_ip_net,
            peer_addr=self.dst_ip_net,
            multihop=self.multihop,
            sha1_key=key,
            bfd_key_id=self.vpp_session.bfd_key_id,
        )
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
        self.assert_equal(len(self.vapi.collect_events()), 0, "number of bfd events")

    def test_auth_change_key_immediate(self):
        """change auth key without disturbing session state (immediate)"""
        key1 = self.factory.create_random_key(self)
        key1.add_vpp_config()
        key2 = self.factory.create_random_key(self)
        key2.add_vpp_config()
        self.vpp_session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
            sha1_key=key1,
        )
        self.vpp_session.add_vpp_config()
        self.test_session = BFDTestSession(
            self,
            self.pg0,
            AF_INET,
            local_addr=self.src_ip_net,
            peer_addr=self.dst_ip_net,
            multihop=self.multihop,
            sha1_key=key1,
            bfd_key_id=self.vpp_session.bfd_key_id,
        )
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
        self.assert_equal(len(self.vapi.collect_events()), 0, "number of bfd events")

    def test_auth_on_delayed(self):
        """turn auth on without disturbing session state (delayed)"""
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        self.vpp_session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
        )
        self.vpp_session.add_vpp_config()
        self.test_session = BFDTestSession(
            self,
            self.pg0,
            AF_INET,
            local_addr=self.src_ip_net,
            peer_addr=self.dst_ip_net,
            multihop=self.multihop,
        )
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
        self.assert_equal(len(self.vapi.collect_events()), 0, "number of bfd events")

    def test_auth_off_delayed(self):
        """turn auth off without disturbing session state (delayed)"""
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        self.vpp_session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
            sha1_key=key,
        )
        self.vpp_session.add_vpp_config()
        self.test_session = BFDTestSession(
            self,
            self.pg0,
            AF_INET,
            local_addr=self.src_ip_net,
            peer_addr=self.dst_ip_net,
            multihop=self.multihop,
            sha1_key=key,
            bfd_key_id=self.vpp_session.bfd_key_id,
        )
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
        self.assert_equal(len(self.vapi.collect_events()), 0, "number of bfd events")

    def test_auth_change_key_delayed(self):
        """change auth key without disturbing session state (delayed)"""
        key1 = self.factory.create_random_key(self)
        key1.add_vpp_config()
        key2 = self.factory.create_random_key(self)
        key2.add_vpp_config()
        self.vpp_session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
            sha1_key=key1,
        )
        self.vpp_session.add_vpp_config()
        self.vpp_session.admin_up()
        self.test_session = BFDTestSession(
            self,
            self.pg0,
            AF_INET,
            local_addr=self.src_ip_net,
            peer_addr=self.dst_ip_net,
            multihop=self.multihop,
            sha1_key=key1,
            bfd_key_id=self.vpp_session.bfd_key_id,
        )
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
        self.assert_equal(len(self.vapi.collect_events()), 0, "number of bfd events")


@parameterized_class(
    [
        {"multihop": False},
        {"multihop": True},
    ]
)
@tag_run_solo
class BFDCLITestCase(VppTestCase):
    """Bidirectional Forwarding Detection (BFD) (CLI)"""

    pg0 = None

    @classmethod
    def setUpClass(cls):
        super(BFDCLITestCase, cls).setUpClass()
        hoptype_str = "MultiHop" if cls.multihop else "SingleHop"
        cls.__doc__ = (
            f"""""Bidirectional Forwarding Detection (BFD) - CLI - {hoptype_str}"""
        )
        cls.vapi.cli("set log class bfd level debug")
        try:
            cls.create_pg_interfaces([0])
            cls.create_loopback_interfaces(1)
            cls.loopback0 = cls.lo_interfaces[0]
            cls.loopback0.config_ip4()
            cls.loopback0.config_ip6()
            cls.loopback0.admin_up()
            cls.pg0.config_ip4()
            cls.pg0.config_ip6()
            cls.pg0.configure_ipv4_neighbors()
            cls.pg0.admin_up()
            cls.pg0.resolve_arp()
            cls.pg0.resolve_ndp()

        except Exception:
            super(BFDCLITestCase, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(BFDCLITestCase, cls).tearDownClass()

    def setUp(self):
        super(BFDCLITestCase, self).setUp()
        self.factory = AuthKeyFactory()
        self.pg0.enable_capture()
        set_ipv4_pfx_route_info(self, self.pg0, BFD_IPV4_REMOTE_ADDR, True)
        set_ipv6_pfx_route_info(self, self.pg0, BFD_IPV6_REMOTE_ADDR, True)

        if self.multihop:
            self.cli_str = "multihop"
        else:
            self.cli_str = "interface %s" % self.pg0.name

    def tearDown(self):
        try:
            self.vapi.want_bfd_events(enable_disable=False)
        except UnexpectedApiReturnValueError:
            # some tests aren't subscribed, so this is not an issue
            pass
        self.vapi.collect_events()  # clear the event queue
        super(BFDCLITestCase, self).tearDown()

    def cli_verify_no_response(self, cli):
        """execute a CLI, asserting that the response is empty"""
        self.assert_equal(self.vapi.cli(cli), "", "CLI command response")

    def cli_verify_response(self, cli, expected):
        """execute a CLI, asserting that the response matches expectation"""
        try:
            reply = self.vapi.cli(cli)
        except CliFailedCommandError as cli_error:
            reply = str(cli_error)
        self.assert_equal(reply.strip(), expected, "CLI command response")

    def test_show(self):
        """show commands"""
        k1 = self.factory.create_random_key(self)
        k1.add_vpp_config()
        k2 = self.factory.create_random_key(
            self, auth_type=BFDAuthType.meticulous_keyed_sha1
        )
        k2.add_vpp_config()
        s1 = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
        )
        s1.add_vpp_config()
        s2 = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip6_net,
            local_addr=self.src_ip6_net,
            af=AF_INET6,
            multihop=self.multihop,
            sha1_key=k2,
        )
        s2.add_vpp_config()
        self.logger.info(self.vapi.ppcli("show bfd keys"))
        self.logger.info(self.vapi.ppcli("show bfd sessions"))
        self.logger.info(self.vapi.ppcli("show bfd"))

    def test_set_del_sha1_key(self):
        """set/delete SHA1 auth key"""
        k = self.factory.create_random_key(self)
        self.registry.register(k, self.logger)
        self.cli_verify_no_response(
            "bfd key set conf-key-id %s type keyed-sha1 secret %s"
            % (
                k.conf_key_id,
                "".join("{:02x}".format(scapy.compat.orb(c)) for c in k.key),
            )
        )
        self.assertTrue(k.query_vpp_config())
        self.vpp_session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
            sha1_key=k,
        )
        self.vpp_session.add_vpp_config()
        self.test_session = BFDTestSession(
            self,
            self.pg0,
            AF_INET,
            local_addr=self.src_ip_net,
            peer_addr=self.dst_ip_net,
            multihop=self.multihop,
            sha1_key=k,
            bfd_key_id=self.vpp_session.bfd_key_id,
        )
        self.vapi.want_bfd_events()
        bfd_session_up(self)
        bfd_session_down(self)
        # try to replace the secret for the key - should fail because the key
        # is in-use
        k2 = self.factory.create_random_key(self)
        self.cli_verify_response(
            "bfd key set conf-key-id %s type keyed-sha1 secret %s"
            % (
                k.conf_key_id,
                "".join("{:02x}".format(scapy.compat.orb(c)) for c in k2.key),
            ),
            "bfd key set: `bfd_auth_set_key' API call failed, "
            "rv=-103:BFD object in use",
        )
        # manipulating the session using old secret should still work
        bfd_session_up(self)
        bfd_session_down(self)
        self.vpp_session.remove_vpp_config()
        self.cli_verify_no_response("bfd key del conf-key-id %s" % k.conf_key_id)
        self.assertFalse(k.query_vpp_config())

    def test_set_del_meticulous_sha1_key(self):
        """set/delete meticulous SHA1 auth key"""
        k = self.factory.create_random_key(
            self, auth_type=BFDAuthType.meticulous_keyed_sha1
        )
        self.registry.register(k, self.logger)
        self.cli_verify_no_response(
            "bfd key set conf-key-id %s type meticulous-keyed-sha1 secret %s"
            % (
                k.conf_key_id,
                "".join("{:02x}".format(scapy.compat.orb(c)) for c in k.key),
            )
        )
        self.assertTrue(k.query_vpp_config())
        self.vpp_session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip6_net,
            local_addr=self.src_ip6_net,
            af=AF_INET6,
            multihop=self.multihop,
            sha1_key=k,
        )
        self.vpp_session.add_vpp_config()
        self.vpp_session.admin_up()
        self.test_session = BFDTestSession(
            self,
            self.pg0,
            AF_INET6,
            local_addr=self.src_ip6_net,
            peer_addr=self.dst_ip6_net,
            multihop=self.multihop,
            sha1_key=k,
            bfd_key_id=self.vpp_session.bfd_key_id,
        )
        self.vapi.want_bfd_events()
        bfd_session_up(self)
        bfd_session_down(self)
        # try to replace the secret for the key - should fail because the key
        # is in-use
        k2 = self.factory.create_random_key(self)
        self.cli_verify_response(
            "bfd key set conf-key-id %s type keyed-sha1 secret %s"
            % (
                k.conf_key_id,
                "".join("{:02x}".format(scapy.compat.orb(c)) for c in k2.key),
            ),
            "bfd key set: `bfd_auth_set_key' API call failed, "
            "rv=-103:BFD object in use",
        )
        # manipulating the session using old secret should still work
        bfd_session_up(self)
        bfd_session_down(self)
        self.vpp_session.remove_vpp_config()
        self.cli_verify_no_response("bfd key del conf-key-id %s" % k.conf_key_id)
        self.assertFalse(k.query_vpp_config())

    def test_add_mod_del_bfd_udp(self):
        """create/modify/delete IPv4 BFD UDP session"""
        vpp_session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
        )
        self.registry.register(vpp_session, self.logger)
        cli_add_cmd = (
            "bfd udp session add %s local-addr %s "
            "peer-addr %s desired-min-tx %s required-min-rx %s "
            "detect-mult %s"
            % (
                self.cli_str,
                self.src_ip_net,
                self.dst_ip_net,
                vpp_session.desired_min_tx,
                vpp_session.required_min_rx,
                vpp_session.detect_mult,
            )
        )
        self.cli_verify_no_response(cli_add_cmd)
        # 2nd add should fail
        self.cli_verify_response(
            cli_add_cmd,
            "bfd udp session add: `bfd_add_add_session' API call"
            " failed, rv=-101:Duplicate BFD object",
        )
        verify_bfd_session_config(self, vpp_session)

        mod_session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
            required_min_rx=2 * vpp_session.required_min_rx,
            desired_min_tx=3 * vpp_session.desired_min_tx,
            detect_mult=4 * vpp_session.detect_mult,
        )
        self.cli_verify_no_response(
            "bfd udp session mod %s local-addr %s peer-addr %s "
            "desired-min-tx %s required-min-rx %s detect-mult %s"
            % (
                self.cli_str,
                self.src_ip_net,
                self.dst_ip_net,
                mod_session.desired_min_tx,
                mod_session.required_min_rx,
                mod_session.detect_mult,
            )
        )
        verify_bfd_session_config(self, mod_session)
        cli_del_cmd = "bfd udp session del %s local-addr %s peer-addr %s" % (
            self.cli_str,
            self.src_ip_net,
            self.dst_ip_net,
        )
        self.cli_verify_no_response(cli_del_cmd)
        # 2nd del is expected to fail
        self.cli_verify_response(
            cli_del_cmd,
            "bfd udp session del: `bfd_udp_del_session' API call"
            " failed, rv=-102:No such BFD object",
        )
        self.assertFalse(vpp_session.query_vpp_config())

        if self.multihop:
            # specifying multihop and interface should fail
            cli_add_cmd = (
                "bfd udp session add multihop interface %s local-addr 1.1.1.1 "
                "peer-addr 2.2.2.2 desired-min-tx 50000 required-min-rx 1000 "
                "detect-mult 3" % (self.pg0.name)
            )
            self.cli_verify_response(
                cli_add_cmd,
                "bfd udp session add: Incompatible parameter combination, "
                "interface cannot be specified when multihop is enabled",
            )
            cli_mod_cmd = (
                "bfd udp session mod multihop interface %s local-addr 1.1.1.1 "
                "peer-addr 2.2.2.2 desired-min-tx 50000 required-min-rx 1000 "
                "detect-mult 3" % (self.pg0.name)
            )
            self.cli_verify_response(
                cli_mod_cmd,
                "bfd udp session mod: Incompatible parameter combination, "
                "interface cannot be specified when multihop is enabled",
            )
            cli_del_cmd = (
                "bfd udp session del multihop interface %s local-addr 1.1.1.1 "
                "peer-addr 2.2.2.2" % (self.pg0.name)
            )
            self.cli_verify_response(
                cli_del_cmd,
                "bfd udp session del: Incompatible parameter combination, "
                "interface cannot be specified when multihop is enabled",
            )

            # Not specifying multihop or interface should fail
            cli_add_cmd = (
                "bfd udp session add local-addr 1.1.1.1 peer-addr 2.2.2.2 "
                "desired-min-tx 50000 required-min-rx 1000 detect-mult 3"
            )
            self.cli_verify_response(
                cli_add_cmd,
                "bfd udp session add: Incompatible parameter combination, "
                "interface must be set if not multihop",
            )
            cli_mod_cmd = (
                "bfd udp session mod local-addr 1.1.1.1 peer-addr 2.2.2.2 "
                "desired-min-tx 50000 required-min-rx 1000 detect-mult 3"
            )
            self.cli_verify_response(
                cli_mod_cmd,
                "bfd udp session mod: Incompatible parameter combination, "
                "interface must be set if not multihop",
            )
            cli_del_cmd = "bfd udp session del local-addr 1.1.1.1 peer-addr 2.2.2.2 "
            self.cli_verify_response(
                cli_del_cmd,
                "bfd udp session del: Incompatible parameter combination, "
                "interface must be set if not multihop",
            )

    def test_add_mod_del_bfd_udp6(self):
        """create/modify/delete IPv6 BFD UDP session"""
        vpp_session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip6_net,
            local_addr=self.src_ip6_net,
            af=AF_INET6,
            multihop=self.multihop,
        )
        self.registry.register(vpp_session, self.logger)
        cli_add_cmd = (
            "bfd udp session add %s local-addr %s "
            "peer-addr %s desired-min-tx %s required-min-rx %s "
            "detect-mult %s"
            % (
                self.cli_str,
                self.src_ip6_net,
                self.dst_ip6_net,
                vpp_session.desired_min_tx,
                vpp_session.required_min_rx,
                vpp_session.detect_mult,
            )
        )
        self.cli_verify_no_response(cli_add_cmd)
        # 2nd add should fail
        self.cli_verify_response(
            cli_add_cmd,
            "bfd udp session add: `bfd_add_add_session' API call"
            " failed, rv=-101:Duplicate BFD object",
        )
        verify_bfd_session_config(self, vpp_session)
        mod_session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip6_net,
            local_addr=self.src_ip6_net,
            af=AF_INET6,
            multihop=self.multihop,
            required_min_rx=2 * vpp_session.required_min_rx,
            desired_min_tx=3 * vpp_session.desired_min_tx,
            detect_mult=4 * vpp_session.detect_mult,
        )
        self.cli_verify_no_response(
            "bfd udp session mod %s local-addr %s peer-addr %s "
            "desired-min-tx %s required-min-rx %s detect-mult %s"
            % (
                self.cli_str,
                self.src_ip6_net,
                self.dst_ip6_net,
                mod_session.desired_min_tx,
                mod_session.required_min_rx,
                mod_session.detect_mult,
            )
        )
        verify_bfd_session_config(self, mod_session)
        cli_del_cmd = "bfd udp session del %s local-addr %s peer-addr %s" % (
            self.cli_str,
            self.src_ip6_net,
            self.dst_ip6_net,
        )
        self.cli_verify_no_response(cli_del_cmd)
        # 2nd del is expected to fail
        self.cli_verify_response(
            cli_del_cmd,
            "bfd udp session del: `bfd_udp_del_session' API call"
            " failed, rv=-102:No such BFD object",
        )
        self.assertFalse(vpp_session.query_vpp_config())

    def test_add_mod_del_bfd_udp_auth(self):
        """create/modify/delete IPv4 BFD UDP session (authenticated)"""
        key = self.factory.create_random_key(self)
        key.add_vpp_config()
        vpp_session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
            sha1_key=key,
        )
        self.registry.register(vpp_session, self.logger)
        cli_add_cmd = (
            "bfd udp session add %s local-addr %s "
            "peer-addr %s desired-min-tx %s required-min-rx %s "
            "detect-mult %s conf-key-id %s bfd-key-id %s"
            % (
                self.cli_str,
                self.src_ip_net,
                self.dst_ip_net,
                vpp_session.desired_min_tx,
                vpp_session.required_min_rx,
                vpp_session.detect_mult,
                key.conf_key_id,
                vpp_session.bfd_key_id,
            )
        )
        self.cli_verify_no_response(cli_add_cmd)
        # 2nd add should fail
        self.cli_verify_response(
            cli_add_cmd,
            "bfd udp session add: `bfd_add_add_session' API call"
            " failed, rv=-101:Duplicate BFD object",
        )
        verify_bfd_session_config(self, vpp_session)
        mod_session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
            sha1_key=key,
            bfd_key_id=vpp_session.bfd_key_id,
            required_min_rx=2 * vpp_session.required_min_rx,
            desired_min_tx=3 * vpp_session.desired_min_tx,
            detect_mult=4 * vpp_session.detect_mult,
        )
        self.cli_verify_no_response(
            "bfd udp session mod %s local-addr %s peer-addr %s "
            "desired-min-tx %s required-min-rx %s detect-mult %s"
            % (
                self.cli_str,
                self.src_ip_net,
                self.dst_ip_net,
                mod_session.desired_min_tx,
                mod_session.required_min_rx,
                mod_session.detect_mult,
            )
        )
        verify_bfd_session_config(self, mod_session)
        cli_del_cmd = "bfd udp session del %s local-addr %s peer-addr %s" % (
            self.cli_str,
            self.src_ip_net,
            self.dst_ip_net,
        )
        self.cli_verify_no_response(cli_del_cmd)
        # 2nd del is expected to fail
        self.cli_verify_response(
            cli_del_cmd,
            "bfd udp session del: `bfd_udp_del_session' API call"
            " failed, rv=-102:No such BFD object",
        )
        self.assertFalse(vpp_session.query_vpp_config())

    def test_add_mod_del_bfd_udp6_auth(self):
        """create/modify/delete IPv6 BFD UDP session (authenticated)"""
        key = self.factory.create_random_key(
            self, auth_type=BFDAuthType.meticulous_keyed_sha1
        )
        key.add_vpp_config()
        vpp_session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip6_net,
            local_addr=self.src_ip6_net,
            af=AF_INET6,
            multihop=self.multihop,
            sha1_key=key,
        )
        self.registry.register(vpp_session, self.logger)
        cli_add_cmd = (
            "bfd udp session add %s local-addr %s "
            "peer-addr %s desired-min-tx %s required-min-rx %s "
            "detect-mult %s conf-key-id %s bfd-key-id %s"
            % (
                self.cli_str,
                self.src_ip6_net,
                self.dst_ip6_net,
                vpp_session.desired_min_tx,
                vpp_session.required_min_rx,
                vpp_session.detect_mult,
                key.conf_key_id,
                vpp_session.bfd_key_id,
            )
        )
        self.cli_verify_no_response(cli_add_cmd)
        # 2nd add should fail
        self.cli_verify_response(
            cli_add_cmd,
            "bfd udp session add: `bfd_add_add_session' API call"
            " failed, rv=-101:Duplicate BFD object",
        )
        verify_bfd_session_config(self, vpp_session)
        mod_session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip6_net,
            local_addr=self.src_ip6_net,
            af=AF_INET6,
            multihop=self.multihop,
            sha1_key=key,
            bfd_key_id=vpp_session.bfd_key_id,
            required_min_rx=2 * vpp_session.required_min_rx,
            desired_min_tx=3 * vpp_session.desired_min_tx,
            detect_mult=4 * vpp_session.detect_mult,
        )
        self.cli_verify_no_response(
            "bfd udp session mod %s local-addr %s peer-addr %s "
            "desired-min-tx %s required-min-rx %s detect-mult %s"
            % (
                self.cli_str,
                self.src_ip6_net,
                self.dst_ip6_net,
                mod_session.desired_min_tx,
                mod_session.required_min_rx,
                mod_session.detect_mult,
            )
        )
        verify_bfd_session_config(self, mod_session)
        cli_del_cmd = "bfd udp session del %s local-addr %s peer-addr %s" % (
            self.cli_str,
            self.src_ip6_net,
            self.dst_ip6_net,
        )
        self.cli_verify_no_response(cli_del_cmd)
        # 2nd del is expected to fail
        self.cli_verify_response(
            cli_del_cmd,
            "bfd udp session del: `bfd_udp_del_session' API call"
            " failed, rv=-102:No such BFD object",
        )
        self.assertFalse(vpp_session.query_vpp_config())

    def test_auth_on_off(self):
        """turn authentication on and off"""
        key = self.factory.create_random_key(
            self, auth_type=BFDAuthType.meticulous_keyed_sha1
        )
        key.add_vpp_config()
        session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
        )
        auth_session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
            sha1_key=key,
        )
        session.add_vpp_config()
        cli_activate = (
            "bfd udp session auth activate %s local-addr %s "
            "peer-addr %s conf-key-id %s bfd-key-id %s"
            % (
                self.cli_str,
                self.src_ip_net,
                self.dst_ip_net,
                key.conf_key_id,
                auth_session.bfd_key_id,
            )
        )
        self.cli_verify_no_response(cli_activate)
        verify_bfd_session_config(self, auth_session)
        self.cli_verify_no_response(cli_activate)
        verify_bfd_session_config(self, auth_session)
        cli_deactivate = (
            "bfd udp session auth deactivate %s local-addr %s "
            "peer-addr %s" % (self.cli_str, self.src_ip_net, self.dst_ip_net)
        )
        self.cli_verify_no_response(cli_deactivate)
        verify_bfd_session_config(self, session)
        self.cli_verify_no_response(cli_deactivate)
        verify_bfd_session_config(self, session)

        if self.multihop:
            # specifying multihop and interface should fail
            cli_activate = (
                "bfd udp session auth activate multihop interface %s "
                "local-addr %s peer-addr %s conf-key-id %s bfd-key-id %s"
                % (
                    self.pg0.name,
                    self.src_ip_net,
                    self.dst_ip_net,
                    key.conf_key_id,
                    auth_session.bfd_key_id,
                )
            )
            self.cli_verify_response(
                cli_activate,
                "bfd udp session auth activate: Incompatible parameter "
                "combination, interface cannot be specified when multihop "
                "is enabled",
            )
            cli_deactivate = (
                "bfd udp session auth deactivate multihop interface %s "
                "local-addr %s peer-addr %s"
                % (
                    self.pg0.name,
                    self.src_ip_net,
                    self.dst_ip_net,
                )
            )
            self.cli_verify_response(
                cli_deactivate,
                "bfd udp session auth deactivate: Incompatible parameter "
                "combination, interface cannot be specified when multihop "
                "is enabled",
            )
            # Not specifying multihop or interface should fail
            cli_activate = (
                "bfd udp session auth activate local-addr %s peer-addr %s "
                "conf-key-id %s bfd-key-id %s"
                % (
                    self.src_ip_net,
                    self.dst_ip_net,
                    key.conf_key_id,
                    auth_session.bfd_key_id,
                )
            )
            self.cli_verify_response(
                cli_activate,
                "bfd udp session auth activate: Incompatible parameter "
                "combination, interface must be set if not multihop",
            )
            cli_deactivate = (
                "bfd udp session auth deactivate local-addr %s peer-addr %s "
                % (
                    self.src_ip_net,
                    self.dst_ip_net,
                )
            )
            self.cli_verify_response(
                cli_deactivate,
                "bfd udp session auth deactivate: Incompatible parameter "
                "combination, interface must be set if not multihop",
            )

    def test_auth_on_off_delayed(self):
        """turn authentication on and off (delayed)"""
        key = self.factory.create_random_key(
            self, auth_type=BFDAuthType.meticulous_keyed_sha1
        )
        key.add_vpp_config()
        session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
        )
        auth_session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
            sha1_key=key,
        )
        session.add_vpp_config()
        cli_activate = (
            "bfd udp session auth activate %s local-addr %s "
            "peer-addr %s conf-key-id %s bfd-key-id %s delayed yes"
            % (
                self.cli_str,
                self.src_ip_net,
                self.dst_ip_net,
                key.conf_key_id,
                auth_session.bfd_key_id,
            )
        )
        self.cli_verify_no_response(cli_activate)
        verify_bfd_session_config(self, auth_session)
        self.cli_verify_no_response(cli_activate)
        verify_bfd_session_config(self, auth_session)
        cli_deactivate = (
            "bfd udp session auth deactivate %s local-addr %s "
            "peer-addr %s delayed yes"
            % (self.cli_str, self.src_ip_net, self.dst_ip_net)
        )
        self.cli_verify_no_response(cli_deactivate)
        verify_bfd_session_config(self, session)
        self.cli_verify_no_response(cli_deactivate)
        verify_bfd_session_config(self, session)

    def test_admin_up_down(self):
        """put session admin-up and admin-down"""
        session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
        )
        session.add_vpp_config()
        cli_down = (
            "bfd udp session set-flags admin down %s local-addr %s "
            "peer-addr %s " % (self.cli_str, self.src_ip_net, self.dst_ip_net)
        )
        cli_up = (
            "bfd udp session set-flags admin up %s local-addr %s "
            "peer-addr %s " % (self.cli_str, self.src_ip_net, self.dst_ip_net)
        )
        self.cli_verify_no_response(cli_down)
        verify_bfd_session_config(self, session, state=BFDState.admin_down)
        self.cli_verify_no_response(cli_up)
        verify_bfd_session_config(self, session, state=BFDState.down)

        if self.multihop:
            # specifying multihop and interface should fail
            cli_up = (
                "bfd udp session set-flags admin up multihop interface %s "
                "local-addr %s peer-addr %s"
                % (
                    self.pg0.name,
                    self.src_ip_net,
                    self.dst_ip_net,
                )
            )
            self.cli_verify_response(
                cli_up,
                "bfd udp session set-flags: Incompatible parameter "
                "combination, interface cannot be specified when multihop "
                "is enabled",
            )
            # Not specifying multihop or interface should fail
            cli_up = (
                "bfd udp session set-flags admin up local-addr %s peer-addr %s "
                % (
                    self.src_ip_net,
                    self.dst_ip_net,
                )
            )
            self.cli_verify_response(
                cli_up,
                "bfd udp session set-flags: Incompatible parameter "
                "combination, interface must be set if not multihop",
            )

    def test_set_del_udp_echo_source(self):
        """set/del udp echo source"""

        if self.multihop:
            self.skipTest(
                f"Skipping because echo functionality is not supported with multihop"
            )

        self.create_loopback_interfaces(1)
        self.loopback0 = self.lo_interfaces[0]
        self.loopback0.admin_up()
        self.cli_verify_response("show bfd echo-source", "UDP echo source is not set.")
        cli_set = "bfd udp echo-source set interface %s" % self.loopback0.name
        self.cli_verify_no_response(cli_set)
        self.cli_verify_response(
            "show bfd echo-source",
            "UDP echo source is: %s\n"
            "IPv4 address usable as echo source: none\n"
            "IPv6 address usable as echo source: none" % self.loopback0.name,
        )
        self.loopback0.config_ip4()
        echo_ip4 = str(
            ipaddress.IPv4Address(
                int(ipaddress.IPv4Address(self.loopback0.local_ip4)) ^ 1
            )
        )
        self.cli_verify_response(
            "show bfd echo-source",
            "UDP echo source is: %s\n"
            "IPv4 address usable as echo source: %s\n"
            "IPv6 address usable as echo source: none"
            % (self.loopback0.name, echo_ip4),
        )
        echo_ip6 = str(
            ipaddress.IPv6Address(
                int(ipaddress.IPv6Address(self.loopback0.local_ip6)) ^ 1
            )
        )
        self.loopback0.config_ip6()
        self.cli_verify_response(
            "show bfd echo-source",
            "UDP echo source is: %s\n"
            "IPv4 address usable as echo source: %s\n"
            "IPv6 address usable as echo source: %s"
            % (self.loopback0.name, echo_ip4, echo_ip6),
        )
        cli_del = "bfd udp echo-source del"
        self.cli_verify_no_response(cli_del)
        self.cli_verify_response("show bfd echo-source", "UDP echo source is not set.")

    def test_add_del_sbfd_reflector(self):
        """add/show/delete S-BFD reflector discriminators"""
        r1 = VppSBFDReflector(self, 0x01020304)
        r2 = VppSBFDReflector(
            self,
            0xFFFFFFFF,
            admin_up=False,
            required_min_rx=1000000,
            src_ip4="192.0.2.20",
            src_ip6="2001:db8::20",
        )
        cli_add_cmd = "bfd udp sbfd reflector add discriminator %s" % r1.discriminator
        self.cli_verify_no_response(cli_add_cmd)
        self.registry.register(r1, self.logger)
        # 2nd add should fail
        self.cli_verify_response(
            cli_add_cmd,
            "bfd udp sbfd reflector add: `bfd_sbfd_reflector_add' API call"
            " failed, rv=-101:Duplicate BFD object",
        )
        self.cli_verify_no_response(
            "bfd udp sbfd reflector add discriminator %s required-min-rx %s "
            "admin-down src-address %s src-address %s"
            % (r2.discriminator, r2.required_min_rx, r2.src_ip6, r2.src_ip4)
        )
        self.registry.register(r2, self.logger)
        verify_sbfd_reflector_config(self, r1)
        verify_sbfd_reflector_config(self, r2)
        rows = [
            line.split()
            for line in self.vapi.cli("show bfd sbfd-reflectors").splitlines()
        ]
        self.assertIn(
            [str(r1.discriminator), "Up", str(r1.required_min_rx), "-", "-"], rows
        )
        self.assertIn(
            [
                str(r2.discriminator),
                "AdminDown",
                str(r2.required_min_rx),
                r2.src_ip4,
                r2.src_ip6,
            ],
            rows,
        )
        cli_del_cmd = "bfd udp sbfd reflector del discriminator %s" % r1.discriminator
        self.cli_verify_no_response(cli_del_cmd)
        # 2nd del is expected to fail
        self.cli_verify_response(
            cli_del_cmd,
            "bfd udp sbfd reflector del: `bfd_sbfd_reflector_del' API call"
            " failed, rv=-102:No such BFD object",
        )
        self.assertFalse(r1.query_vpp_config())
        verify_sbfd_reflector_config(self, r2)

    def sbfd_reflector_show_row(self, discriminator):
        """columns of the discriminator's row in "show bfd sbfd-reflectors" """
        for line in self.vapi.cli("show bfd sbfd-reflectors").splitlines():
            row = line.split()
            if row and row[0] == str(discriminator):
                return row
        return None

    def test_mod_sbfd_reflector(self):
        """modify S-BFD reflector discriminator in place"""
        discriminator = 0x01020304
        self.cli_verify_no_response(
            "bfd udp sbfd reflector add discriminator %s" % discriminator
        )
        self.registry.register(VppSBFDReflector(self, discriminator), self.logger)
        cli_mod_cmd = "bfd udp sbfd reflector mod discriminator %s " % discriminator
        # settings that are not given keep their values
        for args, admin_up, required_min_rx in (
            ("admin down", False, SBFD_DEFAULT_REQUIRED_MIN_RX),
            ("required-min-rx 1000000", False, 1000000),
            ("admin up required-min-rx 20000", True, 20000),
        ):
            self.cli_verify_no_response(cli_mod_cmd + args)
            verify_sbfd_reflector_config(
                self,
                VppSBFDReflector(
                    self,
                    discriminator,
                    admin_up=admin_up,
                    required_min_rx=required_min_rx,
                ),
            )
            self.assert_equal(
                self.sbfd_reflector_show_row(discriminator)[1:3],
                ["Up" if admin_up else "AdminDown", str(required_min_rx)],
                "state and required min rx",
            )
        # a source of 0.0.0.0 or :: removes it, shown as "-"
        for args, src_ip4, src_ip6 in (
            (
                "src-address 192.0.2.30 src-address 2001:db8::30",
                "192.0.2.30",
                "2001:db8::30",
            ),
            ("src-address 0.0.0.0", None, "2001:db8::30"),
            ("src-address ::", None, None),
        ):
            self.cli_verify_no_response(cli_mod_cmd + args)
            verify_sbfd_reflector_config(
                self,
                VppSBFDReflector(
                    self,
                    discriminator,
                    required_min_rx=20000,
                    src_ip4=src_ip4,
                    src_ip6=src_ip6,
                ),
            )
            self.assert_equal(
                self.sbfd_reflector_show_row(discriminator)[3:],
                [src_ip4 or "-", src_ip6 or "-"],
                "sources",
            )

    def cli_verify_sbfd_reflector_not_added(self, cli, expected):
        """execute a CLI that must fail with the expected response and add no
        S-BFD reflector. One it adds anyway is deleted before the checks, even
        if the CLI raises, so that the failure stays in this test; it is
        registered first, so that teardown retries a delete that fails."""
        before = {r.discriminator for r in self.vapi.bfd_udp_sbfd_reflector_dump()}
        returned = False
        try:
            try:
                reply = self.vapi.cli(cli)
            except CliFailedCommandError as cli_error:
                reply = str(cli_error)
            returned = True
        finally:
            try:
                added = [
                    VppSBFDReflector(self, r.discriminator)
                    for r in self.vapi.bfd_udp_sbfd_reflector_dump()
                    if r.discriminator not in before
                ]
                for reflector in added:
                    self.registry.register(reflector, self.logger)
                for reflector in added:
                    reflector.remove_vpp_config()
            except Exception:
                # if the CLI raised, its exception is the one to report
                if returned:
                    raise
        self.assert_equal(reply.strip(), expected, "CLI command response")
        self.assert_equal(
            [r.discriminator for r in added], [], "S-BFD reflectors added"
        )

    def test_sbfd_reflector_cli_errors(self):
        """S-BFD reflector CLI errors"""
        self.cli_verify_sbfd_reflector_not_added(
            "bfd udp sbfd reflector add required-min-rx 1000",
            "bfd udp sbfd reflector add: Required parameter `discriminator' missing.",
        )
        self.cli_verify_sbfd_reflector_not_added(
            "bfd udp sbfd reflector add discriminator 0",
            "bfd udp sbfd reflector add: `bfd_sbfd_reflector_add' API call"
            " failed, rv=-7:Invalid value",
        )
        self.cli_verify_response(
            "bfd udp sbfd reflector mod admin down",
            "bfd udp sbfd reflector mod: Required parameter `discriminator' missing.",
        )
        self.cli_verify_response(
            "bfd udp sbfd reflector mod discriminator 1 admin down",
            "bfd udp sbfd reflector mod: `bfd_sbfd_reflector_mod' API call"
            " failed, rv=-102:No such BFD object",
        )
        self.cli_verify_no_response("bfd udp sbfd reflector add discriminator 1")
        self.registry.register(VppSBFDReflector(self, 1), self.logger)
        self.cli_verify_response(
            "bfd udp sbfd reflector mod discriminator 1 required-min-rx 0",
            "bfd udp sbfd reflector mod: `bfd_sbfd_reflector_mod' API call"
            " failed, rv=-7:Invalid value",
        )
        self.cli_verify_response(
            "bfd udp sbfd reflector mod discriminator 1 admin sideways",
            "bfd udp sbfd reflector mod: Unknown input `admin sideways'",
        )
        self.cli_verify_no_response("bfd udp sbfd reflector del discriminator 1")
        self.cli_verify_sbfd_reflector_not_added(
            "bfd udp sbfd reflector add discriminator 1 required-min-rx 0",
            "bfd udp sbfd reflector add: `bfd_sbfd_reflector_add' API call"
            " failed, rv=-7:Invalid value",
        )
        self.cli_verify_sbfd_reflector_not_added(
            "bfd udp sbfd reflector add discriminator 1 foo",
            "bfd udp sbfd reflector add: Unknown input `foo'",
        )
        self.cli_verify_sbfd_reflector_not_added(
            "bfd udp sbfd reflector add discriminator 1 src-address 127.0.0.1",
            "bfd udp sbfd reflector add: `bfd_sbfd_reflector_add' API call"
            " failed, rv=-57:Invalid src address",
        )
        self.cli_verify_sbfd_reflector_not_added(
            "bfd udp sbfd reflector add discriminator 1 src-address fe80::1",
            "bfd udp sbfd reflector add: `bfd_sbfd_reflector_add' API call"
            " failed, rv=-57:Invalid src address",
        )
        # ::ffff:10.1.2.3, IPv4-mapped; the CLI takes no dotted quad in an
        # IPv6 address
        self.cli_verify_sbfd_reflector_not_added(
            "bfd udp sbfd reflector add discriminator 1 src-address ::ffff:a01:203",
            "bfd udp sbfd reflector add: `bfd_sbfd_reflector_add' API call"
            " failed, rv=-57:Invalid src address",
        )
        self.cli_verify_no_response("bfd udp sbfd reflector add discriminator 2")
        self.registry.register(VppSBFDReflector(self, 2), self.logger)
        self.cli_verify_response(
            "bfd udp sbfd reflector mod discriminator 2 src-address 127.0.0.1",
            "bfd udp sbfd reflector mod: `bfd_sbfd_reflector_mod' API call"
            " failed, rv=-57:Invalid src address",
        )
        for verb in ("add", "mod"):
            for second in (
                "192.0.2.1 src-address 192.0.2.2",
                "2001:db8::1 src-address 2001:db8::2",
            ):
                self.cli_verify_response(
                    "bfd udp sbfd reflector %s discriminator 2 src-address %s"
                    % (verb, second),
                    "bfd udp sbfd reflector %s: Only one `src-address' per address"
                    " family." % verb,
                )
        self.cli_verify_no_response("bfd udp sbfd reflector del discriminator 2")
        self.assert_equal(
            len(self.vapi.bfd_udp_sbfd_reflector_dump()), 0, "number of reflectors"
        )

    def test_sbfd_reflector_with_classic_session(self):
        """S-BFD reflector and classic BFD session shown together"""
        session = VppBFDUDPSession(
            self,
            self.pg0,
            self.dst_ip_net,
            local_addr=self.src_ip_net,
            multihop=self.multihop,
        )
        session.add_vpp_config()
        reflector = VppSBFDReflector(self, 0x01020304)
        self.cli_verify_no_response(
            "bfd udp sbfd reflector add discriminator %s" % reflector.discriminator
        )
        self.registry.register(reflector, self.logger)
        self.assertIn(
            "Number of configured BFD sessions: 1",
            self.vapi.cli("show bfd sessions"),
        )
        self.assertIn(
            "Number of configured S-BFD reflectors: 1",
            self.vapi.cli("show bfd sbfd-reflectors"),
        )


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
