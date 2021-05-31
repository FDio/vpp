#!/usr/bin/env python3

#
# Copyright 2019-2020 Rubicon Communications, LLC (Netgate)
#
# SPDX-License-Identifier: Apache-2.0
#

import unittest
import time
import socket
from socket import inet_pton, inet_ntop

from vpp_object import VppObject
from vpp_papi import VppEnum

from scapy.packet import raw
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, ICMP, icmptypes
from scapy.layers.inet6 import IPv6, ipv6nh, IPv6ExtHdrHopByHop, \
    ICMPv6MLReport2, ICMPv6ND_NA, ICMPv6ND_NS, ICMPv6NDOptDstLLAddr, \
    ICMPv6NDOptSrcLLAddr, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3mr, IGMPv3gr
from scapy.layers.vrrp import IPPROTO_VRRP, VRRPv3
from scapy.utils6 import in6_getnsma, in6_getnsmac
from config import config
from framework import VppTestCase, VppTestRunner
from util import ip6_normalize

VRRP_VR_FLAG_PREEMPT = 1
VRRP_VR_FLAG_ACCEPT = 2
VRRP_VR_FLAG_UNICAST = 4
VRRP_VR_FLAG_IPV6 = 8

VRRP_VR_STATE_INIT = 0
VRRP_VR_STATE_BACKUP = 1
VRRP_VR_STATE_MASTER = 2
VRRP_VR_STATE_INTF_DOWN = 3


def is_non_arp(p):
    """ Want to filter out advertisements, igmp, etc"""
    if p.haslayer(ARP):
        return False

    return True


def is_not_adv(p):
    """ Filter out everything but advertisements. E.g. multicast RD/ND """
    if p.haslayer(VRRPv3):
        return False

    return True


def is_not_echo_reply(p):
    """ filter out advertisements and other while waiting for echo reply """
    if p.haslayer(IP) and p.haslayer(ICMP):
        if icmptypes[p[ICMP].type] == "echo-reply":
            return False
    elif p.haslayer(IPv6) and p.haslayer(ICMPv6EchoReply):
        return False

    return True


class VppVRRPVirtualRouter(VppObject):

    def __init__(self,
                 test,
                 intf,
                 vr_id,
                 prio=100,
                 intvl=100,
                 flags=VRRP_VR_FLAG_PREEMPT,
                 vips=None):
        self._test = test
        self._intf = intf
        self._sw_if_index = self._intf.sw_if_index
        self._vr_id = vr_id
        self._prio = prio
        self._intvl = intvl
        self._flags = flags
        if (flags & VRRP_VR_FLAG_IPV6):
            self._is_ipv6 = 1
            self._adv_dest_mac = "33:33:00:00:00:12"
            self._virtual_mac = "00:00:5e:00:02:%02x" % vr_id
            self._adv_dest_ip = "ff02::12"
            self._vips = ([intf.local_ip6] if vips is None else vips)
        else:
            self._is_ipv6 = 0
            self._adv_dest_mac = "01:00:5e:00:00:12"
            self._virtual_mac = "00:00:5e:00:01:%02x" % vr_id
            self._adv_dest_ip = "224.0.0.18"
            self._vips = ([intf.local_ip4] if vips is None else vips)
        self._tracked_ifs = []

    def add_vpp_config(self):
        self._test.vapi.vrrp_vr_add_del(is_add=1,
                                        sw_if_index=self._intf.sw_if_index,
                                        vr_id=self._vr_id,
                                        priority=self._prio,
                                        interval=self._intvl,
                                        flags=self._flags,
                                        n_addrs=len(self._vips),
                                        addrs=self._vips)

    def query_vpp_config(self):
        vrs = self._test.vapi.vrrp_vr_dump(sw_if_index=self._intf.sw_if_index)
        for vr in vrs:
            if vr.config.vr_id != self._vr_id:
                continue

            is_ipv6 = (1 if (vr.config.flags & VRRP_VR_FLAG_IPV6) else 0)
            if is_ipv6 != self._is_ipv6:
                continue

            return vr

        return None

    def remove_vpp_config(self):
        self._test.vapi.vrrp_vr_add_del(is_add=0,
                                        sw_if_index=self._intf.sw_if_index,
                                        vr_id=self._vr_id,
                                        priority=self._prio,
                                        interval=self._intvl,
                                        flags=self._flags,
                                        n_addrs=len(self._vips),
                                        addrs=self._vips)

    def start_stop(self, is_start):
        self._test.vapi.vrrp_vr_start_stop(is_start=is_start,
                                           sw_if_index=self._intf.sw_if_index,
                                           vr_id=self._vr_id,
                                           is_ipv6=self._is_ipv6)
        self._start_time = (time.time() if is_start else None)

    def add_del_tracked_interface(self, is_add, sw_if_index, prio):
        args = {
            'sw_if_index': self._intf.sw_if_index,
            'is_ipv6': self._is_ipv6,
            'vr_id': self._vr_id,
            'is_add': is_add,
            'n_ifs': 1,
            'ifs': [{'sw_if_index': sw_if_index, 'priority': prio}]
        }
        self._test.vapi.vrrp_vr_track_if_add_del(**args)
        self._tracked_ifs.append(args['ifs'][0])

    def set_unicast_peers(self, addrs):
        args = {
            'sw_if_index': self._intf.sw_if_index,
            'is_ipv6': self._is_ipv6,
            'vr_id': self._vr_id,
            'n_addrs': len(addrs),
            'addrs': addrs
        }
        self._test.vapi.vrrp_vr_set_peers(**args)
        self._unicast_peers = addrs

    def start_time(self):
        return self._start_time

    def virtual_mac(self):
        return self._virtual_mac

    def virtual_ips(self):
        return self._vips

    def adv_dest_mac(self):
        return self._adv_dest_mac

    def adv_dest_ip(self):
        return self._adv_dest_ip

    def priority(self):
        return self._prio

    def vr_id(self):
        return self._vr_id

    def adv_interval(self):
        return self._intvl

    def interface(self):
        return self._intf

    def assert_state_equals(self, state):
        vr_details = self.query_vpp_config()
        self._test.assertEqual(vr_details.runtime.state, state)

    def master_down_seconds(self):
        vr_details = self.query_vpp_config()
        return (vr_details.runtime.master_down_int * 0.01)

    def vrrp_adv_packet(self, prio=None, src_ip=None):
        dst_ip = self._adv_dest_ip
        if prio is None:
            prio = self._prio
        eth = Ether(dst=self._adv_dest_mac, src=self._virtual_mac)
        vrrp = VRRPv3(vrid=self._vr_id, priority=prio,
                      ipcount=len(self._vips), adv=self._intvl)
        if self._is_ipv6:
            src_ip = (self._intf.local_ip6_ll if src_ip is None else src_ip)
            ip = IPv6(src=src_ip, dst=dst_ip, nh=IPPROTO_VRRP, hlim=255)
            vrrp.addrlist = self._vips
        else:
            src_ip = (self._intf.local_ip4 if src_ip is None else src_ip)
            ip = IP(src=src_ip, dst=dst_ip, proto=IPPROTO_VRRP, ttl=255, id=0)
            vrrp.addrlist = self._vips

        # Fill in default values & checksums
        pkt = Ether(raw(eth / ip / vrrp))
        return pkt


@unittest.skipUnless(config.extended, "part of extended tests")
class TestVRRP4(VppTestCase):
    """ IPv4 VRRP Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestVRRP4, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestVRRP4, cls).tearDownClass()

    def setUp(self):
        super(TestVRRP4, self).setUp()

        self.create_pg_interfaces(range(2))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.generate_remote_hosts(5)
            i.configure_ipv4_neighbors()

        self._vrs = []
        self._default_flags = VRRP_VR_FLAG_PREEMPT
        self._default_adv = 100

    def tearDown(self):
        for vr in self._vrs:
            try:
                vr_api = vr.query_vpp_config()
                if vr_api.runtime.state != VRRP_VR_STATE_INIT:
                    vr.start_stop(is_start=0)
                vr.remove_vpp_config()
            except:
                self.logger.error("Error cleaning up")

        for i in self.pg_interfaces:
            i.admin_down()
            i.unconfig_ip4()
            i.unconfig_ip6()

        self._vrs = []

        super(TestVRRP4, self).tearDown()

    def verify_vrrp4_igmp(self, pkt):
        ip = pkt[IP]
        self.assertEqual(ip.dst, "224.0.0.22")
        self.assertEqual(ip.proto, 2)

        igmp = pkt[IGMPv3]
        self.assertEqual(IGMPv3.igmpv3types[igmp.type],
                         "Version 3 Membership Report")

        igmpmr = pkt[IGMPv3mr]
        self.assertEqual(igmpmr.numgrp, 1)
        self.assertEqual(igmpmr.records[0].maddr, "224.0.0.18")

    def verify_vrrp4_garp(self, pkt, vip, vmac):
        arp = pkt[ARP]

        # ARP "who-has" op == 1
        self.assertEqual(arp.op, 1)
        self.assertEqual(arp.pdst, arp.psrc)
        self.assertEqual(arp.pdst, vip)
        self.assertEqual(arp.hwsrc, vmac)

    def verify_vrrp4_adv(self, rx_pkt, vr, prio=None):
        vips = vr.virtual_ips()
        eth = rx_pkt[Ether]
        ip = rx_pkt[IP]
        vrrp = rx_pkt[VRRPv3]

        pkt = vr.vrrp_adv_packet(prio=prio)

        # Source MAC is virtual MAC, destination is multicast MAC
        self.assertEqual(eth.src, vr.virtual_mac())
        self.assertEqual(eth.dst, vr.adv_dest_mac())

        self.assertEqual(ip.dst, "224.0.0.18")
        self.assertEqual(ip.ttl, 255)
        self.assertEqual(ip.proto, IPPROTO_VRRP)

        self.assertEqual(vrrp.version, 3)
        self.assertEqual(vrrp.type, 1)
        self.assertEqual(vrrp.vrid, vr.vr_id())
        if prio is None:
            prio = vr.priority()
        self.assertEqual(vrrp.priority, prio)
        self.assertEqual(vrrp.ipcount, len(vips))
        self.assertEqual(vrrp.adv, vr.adv_interval())
        self.assertListEqual(vrrp.addrlist, vips)

    # VR with priority 255 owns the virtual address and should
    # become master and start advertising immediately.
    def test_vrrp4_master_adv(self):
        """ IPv4 Master VR advertises """
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        prio = 255
        intvl = self._default_adv
        vr = VppVRRPVirtualRouter(self, self.pg0, 100,
                                  prio=prio, intvl=intvl,
                                  flags=self._default_flags)

        vr.add_vpp_config()
        vr.start_stop(is_start=1)
        self.logger.info(self.vapi.cli("show vrrp vr"))
        vr.start_stop(is_start=0)
        self.logger.info(self.vapi.cli("show vrrp vr"))

        pkts = self.pg0.get_capture(4)

        # Init -> Master: IGMP Join, VRRP adv, gratuitous ARP are sent
        self.verify_vrrp4_igmp(pkts[0])
        self.verify_vrrp4_adv(pkts[1], vr, prio=prio)
        self.verify_vrrp4_garp(pkts[2], vr.virtual_ips()[0], vr.virtual_mac())
        # Master -> Init: Adv with priority 0 sent to force an election
        self.verify_vrrp4_adv(pkts[3], vr, prio=0)

        vr.remove_vpp_config()
        self._vrs = []

    # VR with priority < 255 enters backup state and does not advertise as
    # long as it receives higher priority advertisements
    def test_vrrp4_backup_noadv(self):
        """ IPv4 Backup VR does not advertise """
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        vr_id = 100
        prio = 100
        intvl = self._default_adv
        intvl_s = intvl * 0.01
        vr = VppVRRPVirtualRouter(self, self.pg0, vr_id,
                                  prio=prio, intvl=intvl,
                                  flags=self._default_flags,
                                  vips=[self.pg0.remote_ip4])
        self._vrs.append(vr)
        vr.add_vpp_config()

        vr.start_stop(is_start=1)

        vr.assert_state_equals(VRRP_VR_STATE_BACKUP)
        # watch for advertisements for 2x the master down preemption timeout
        end_time = vr.start_time() + 2 * vr.master_down_seconds()

        # Init -> Backup: An IGMP join should be sent
        pkts = self.pg0.get_capture(1)
        self.verify_vrrp4_igmp(pkts[0])

        # send higher prio advertisements, should not receive any
        src_ip = self.pg0.remote_ip4
        pkts = [vr.vrrp_adv_packet(prio=prio+10, src_ip=src_ip)]
        while time.time() < end_time:
            self.send_and_assert_no_replies(self.pg0, pkts, timeout=intvl_s)
            self.logger.info(self.vapi.cli("show trace"))

        vr.start_stop(is_start=0)
        self.logger.info(self.vapi.cli("show vrrp vr"))
        vr.remove_vpp_config()
        self._vrs = []

    def test_vrrp4_master_arp(self):
        """ IPv4 Master VR replies to ARP """
        self.pg_start()

        # VR virtual IP is the default, which is the pg local IP
        vr_id = 100
        prio = 255
        intvl = self._default_adv
        vr = VppVRRPVirtualRouter(self, self.pg0, 100,
                                  prio=prio, intvl=intvl,
                                  flags=self._default_flags)
        self._vrs.append(vr)

        vr.add_vpp_config()

        # before the VR is up, ARP should resolve to interface MAC
        self.pg0.resolve_arp()
        self.assertNotEqual(self.pg0.local_mac, vr.virtual_mac())

        # start the VR, ARP should now resolve to virtual MAC
        vr.start_stop(is_start=1)
        self.pg0.resolve_arp()
        self.assertEqual(self.pg0.local_mac, vr.virtual_mac())

        # stop the VR, ARP should resolve to interface MAC again
        vr.start_stop(is_start=0)
        self.pg0.resolve_arp()
        self.assertNotEqual(self.pg0.local_mac, vr.virtual_mac())

        vr.remove_vpp_config()
        self._vrs = []

    def test_vrrp4_backup_noarp(self):
        """ IPv4 Backup VR ignores ARP """
        # We need an address for a virtual IP that is not the IP that
        # ARP requests will originate from

        vr_id = 100
        prio = 100
        intvl = self._default_adv
        vip = self.pg0.remote_hosts[1].ip4
        vr = VppVRRPVirtualRouter(self, self.pg0, vr_id,
                                  prio=prio, intvl=intvl,
                                  flags=self._default_flags,
                                  vips=[vip])
        self._vrs.append(vr)
        vr.add_vpp_config()

        arp_req = (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.pg0.remote_mac) /
                   ARP(op=ARP.who_has, pdst=vip,
                   psrc=self.pg0.remote_ip4, hwsrc=self.pg0.remote_mac))

        # Before the VR is started make sure no reply to request for VIP
        self.pg_start()
        self.pg_enable_capture(self.pg_interfaces)
        self.send_and_assert_no_replies(self.pg0, [arp_req], timeout=1)

        # VR should start in backup state and still should not reply to ARP
        # send a higher priority adv to make sure it does not become master
        adv = vr.vrrp_adv_packet(prio=prio+10, src_ip=self.pg0.remote_ip4)
        vr.start_stop(is_start=1)
        self.send_and_assert_no_replies(self.pg0, [adv, arp_req], timeout=1)

        vr.start_stop(is_start=0)
        vr.remove_vpp_config()
        self._vrs = []

    def test_vrrp4_election(self):
        """ IPv4 Backup VR becomes master if no advertisements received """

        vr_id = 100
        prio = 100
        intvl = self._default_adv
        intvl_s = intvl * 0.01
        vip = self.pg0.remote_ip4
        vr = VppVRRPVirtualRouter(self, self.pg0, vr_id,
                                  prio=prio, intvl=intvl,
                                  flags=self._default_flags,
                                  vips=[vip])
        self._vrs.append(vr)
        vr.add_vpp_config()

        # After adding the VR, it should be in the init state
        vr.assert_state_equals(VRRP_VR_STATE_INIT)

        self.pg_start()
        vr.start_stop(is_start=1)

        # VR should be in backup state after starting
        vr.assert_state_equals(VRRP_VR_STATE_BACKUP)
        end_time = vr.start_time() + vr.master_down_seconds()

        # should not receive adverts until timer expires & state transition
        self.pg_enable_capture(self.pg_interfaces)
        while (time.time() + intvl_s) < end_time:
            time.sleep(intvl_s)
            self.pg0.assert_nothing_captured(filter_out_fn=is_not_adv)

        # VR should be in master state, should send an adv
        self.pg0.enable_capture()
        self.pg0.wait_for_packet(intvl_s, is_not_adv)
        vr.assert_state_equals(VRRP_VR_STATE_MASTER)

    def test_vrrp4_backup_preempts(self):
        """ IPv4 Backup VR preempts lower priority master """

        vr_id = 100
        prio = 100
        intvl = self._default_adv
        intvl_s = intvl * 0.01
        vip = self.pg0.remote_ip4
        vr = VppVRRPVirtualRouter(self, self.pg0, vr_id,
                                  prio=prio, intvl=intvl,
                                  flags=self._default_flags,
                                  vips=[vip])
        self._vrs.append(vr)
        vr.add_vpp_config()

        # After adding the VR, it should be in the init state
        vr.assert_state_equals(VRRP_VR_STATE_INIT)

        self.pg_start()
        vr.start_stop(is_start=1)

        # VR should be in backup state after starting
        vr.assert_state_equals(VRRP_VR_STATE_BACKUP)
        end_time = vr.start_time() + vr.master_down_seconds()

        # send lower prio advertisements until timer expires
        src_ip = self.pg0.remote_ip4
        pkts = [vr.vrrp_adv_packet(prio=prio-10, src_ip=src_ip)]
        while time.time() + intvl_s < end_time:
            self.send_and_assert_no_replies(self.pg0, pkts, timeout=intvl_s)
            self.logger.info(self.vapi.cli("show trace"))

        # when timer expires, VR should take over as master
        self.pg0.enable_capture()
        self.pg0.wait_for_packet(timeout=intvl_s, filter_out_fn=is_not_adv)
        vr.assert_state_equals(VRRP_VR_STATE_MASTER)

    def test_vrrp4_master_preempted(self):
        """ IPv4 Master VR preempted by higher priority backup """

        # A prio 255 VR cannot be preempted so the prio has to be lower and
        # we have to wait for it to take over
        vr_id = 100
        prio = 100
        intvl = self._default_adv
        vip = self.pg0.remote_ip4
        vr = VppVRRPVirtualRouter(self, self.pg0, vr_id,
                                  prio=prio, intvl=intvl,
                                  flags=self._default_flags,
                                  vips=[vip])
        self._vrs.append(vr)
        vr.add_vpp_config()

        # After adding the VR, it should be in the init state
        vr.assert_state_equals(VRRP_VR_STATE_INIT)

        # start VR
        vr.start_stop(is_start=1)
        vr.assert_state_equals(VRRP_VR_STATE_BACKUP)

        # wait for VR to take over as master
        end_time = vr.start_time() + vr.master_down_seconds()
        sleep_s = end_time - time.time()
        time.sleep(sleep_s)
        vr.assert_state_equals(VRRP_VR_STATE_MASTER)

        # Build advertisement packet and send it
        pkts = [vr.vrrp_adv_packet(prio=255, src_ip=self.pg0.remote_ip4)]
        self.pg_send(self.pg0, pkts)

        # VR should be in backup state again
        vr.assert_state_equals(VRRP_VR_STATE_BACKUP)

    def test_vrrp4_accept_mode_disabled(self):
        """ IPv4 Master VR does not reply for VIP w/ accept mode off """

        # accept mode only matters when prio < 255, so it will have to
        # come up as a backup and take over as master after the timeout
        vr_id = 100
        prio = 100
        intvl = self._default_adv
        vip = self.pg0.remote_hosts[4].ip4
        vr = VppVRRPVirtualRouter(self, self.pg0, vr_id,
                                  prio=prio, intvl=intvl,
                                  flags=self._default_flags,
                                  vips=[vip])
        self._vrs.append(vr)
        vr.add_vpp_config()

        # After adding the VR, it should be in the init state
        vr.assert_state_equals(VRRP_VR_STATE_INIT)

        # start VR
        vr.start_stop(is_start=1)
        vr.assert_state_equals(VRRP_VR_STATE_BACKUP)

        # wait for VR to take over as master
        end_time = vr.start_time() + vr.master_down_seconds()
        sleep_s = end_time - time.time()
        time.sleep(sleep_s)
        vr.assert_state_equals(VRRP_VR_STATE_MASTER)

        # send an ICMP echo to the VR virtual IP address
        echo = (Ether(dst=vr.virtual_mac(), src=self.pg0.remote_mac) /
                IP(dst=vip, src=self.pg0.remote_ip4) /
                ICMP(seq=1, id=self.pg0.sw_if_index, type='echo-request'))
        self.pg_send(self.pg0, [echo])

        # wait for an echo reply. none should be received
        time.sleep(1)
        self.pg0.assert_nothing_captured(filter_out_fn=is_not_echo_reply)

    def test_vrrp4_accept_mode_enabled(self):
        """ IPv4 Master VR replies for VIP w/ accept mode on """

        # A prio 255 VR cannot be preempted so the prio has to be lower and
        # we have to wait for it to take over
        vr_id = 100
        prio = 100
        intvl = self._default_adv
        vip = self.pg0.remote_hosts[4].ip4
        flags = (VRRP_VR_FLAG_PREEMPT | VRRP_VR_FLAG_ACCEPT)
        vr = VppVRRPVirtualRouter(self, self.pg0, vr_id,
                                  prio=prio, intvl=intvl,
                                  flags=flags,
                                  vips=[vip])
        self._vrs.append(vr)
        vr.add_vpp_config()

        # After adding the VR, it should be in the init state
        vr.assert_state_equals(VRRP_VR_STATE_INIT)

        # start VR
        vr.start_stop(is_start=1)
        vr.assert_state_equals(VRRP_VR_STATE_BACKUP)

        # wait for VR to take over as master
        end_time = vr.start_time() + vr.master_down_seconds()
        sleep_s = end_time - time.time()
        time.sleep(sleep_s)
        vr.assert_state_equals(VRRP_VR_STATE_MASTER)

        # send an ICMP echo to the VR virtual IP address
        echo = (Ether(dst=vr.virtual_mac(), src=self.pg0.remote_mac) /
                IP(dst=vip, src=self.pg0.remote_ip4) /
                ICMP(seq=1, id=self.pg0.sw_if_index, type='echo-request'))
        self.pg_send(self.pg0, [echo])

        # wait for an echo reply.
        time.sleep(1)
        rx_pkts = self.pg0.get_capture(expected_count=1, timeout=1,
                                       filter_out_fn=is_not_echo_reply)

        self.assertEqual(rx_pkts[0][IP].src, vip)
        self.assertEqual(rx_pkts[0][IP].dst, self.pg0.remote_ip4)
        self.assertEqual(icmptypes[rx_pkts[0][ICMP].type], "echo-reply")
        self.assertEqual(rx_pkts[0][ICMP].seq, 1)
        self.assertEqual(rx_pkts[0][ICMP].id, self.pg0.sw_if_index)

    def test_vrrp4_intf_tracking(self):
        """ IPv4 Master VR adjusts priority based on tracked interface """

        vr_id = 100
        prio = 255
        intvl = self._default_adv
        intvl_s = intvl * 0.01
        vip = self.pg0.local_ip4
        vr = VppVRRPVirtualRouter(self, self.pg0, vr_id,
                                  prio=prio, intvl=intvl,
                                  flags=self._default_flags,
                                  vips=[vip])
        self._vrs.append(vr)
        vr.add_vpp_config()

        # After adding the VR, it should be in the init state
        vr.assert_state_equals(VRRP_VR_STATE_INIT)

        # add pg1 as a tracked interface and start the VR
        adjustment = 50
        adjusted_prio = prio - adjustment
        vr.add_del_tracked_interface(is_add=1,
                                     sw_if_index=self.pg1.sw_if_index,
                                     prio=adjustment)
        vr.start_stop(is_start=1)
        vr.assert_state_equals(VRRP_VR_STATE_MASTER)

        adv_configured = vr.vrrp_adv_packet(prio=prio)
        adv_adjusted = vr.vrrp_adv_packet(prio=adjusted_prio)

        # tracked intf is up ->  advertised priority == configured priority
        self.pg0.enable_capture()
        rx = self.pg0.wait_for_packet(timeout=intvl_s,
                                      filter_out_fn=is_not_adv)
        self.assertEqual(rx, adv_configured)

        # take down pg1, verify priority is now being adjusted
        self.pg1.admin_down()
        self.pg0.enable_capture()
        rx = self.pg0.wait_for_packet(timeout=intvl_s,
                                      filter_out_fn=is_not_adv)
        self.assertEqual(rx, adv_adjusted)

        # bring up pg1, verify priority now matches configured value
        self.pg1.admin_up()
        self.pg0.enable_capture()
        rx = self.pg0.wait_for_packet(timeout=intvl_s,
                                      filter_out_fn=is_not_adv)
        self.assertEqual(rx, adv_configured)

        # remove IP address from pg1, verify priority now being adjusted
        self.pg1.unconfig_ip4()
        self.pg0.enable_capture()
        rx = self.pg0.wait_for_packet(timeout=intvl_s,
                                      filter_out_fn=is_not_adv)
        self.assertEqual(rx, adv_adjusted)

        # add IP address to pg1, verify priority now matches configured value
        self.pg1.config_ip4()
        self.pg0.enable_capture()
        rx = self.pg0.wait_for_packet(timeout=intvl_s,
                                      filter_out_fn=is_not_adv)
        self.assertEqual(rx, adv_configured)

    def test_vrrp4_master_adv_unicast(self):
        """ IPv4 Master VR advertises (unicast) """

        vr_id = 100
        prio = 255
        intvl = self._default_adv
        intvl_s = intvl * 0.01
        vip = self.pg0.local_ip4
        flags = (self._default_flags | VRRP_VR_FLAG_UNICAST)
        unicast_peer = self.pg0.remote_hosts[4]
        vr = VppVRRPVirtualRouter(self, self.pg0, vr_id,
                                  prio=prio, intvl=intvl,
                                  flags=flags,
                                  vips=[vip])
        self._vrs.append(vr)
        vr.add_vpp_config()
        vr.set_unicast_peers([unicast_peer.ip4])

        # After adding the VR, it should be in the init state
        vr.assert_state_equals(VRRP_VR_STATE_INIT)

        # Start VR, transition to master
        vr.start_stop(is_start=1)
        vr.assert_state_equals(VRRP_VR_STATE_MASTER)

        self.pg0.enable_capture()
        rx = self.pg0.wait_for_packet(timeout=intvl_s,
                                      filter_out_fn=is_not_adv)

        self.assertTrue(rx.haslayer(Ether))
        self.assertTrue(rx.haslayer(IP))
        self.assertTrue(rx.haslayer(VRRPv3))
        self.assertEqual(rx[Ether].src, self.pg0.local_mac)
        self.assertEqual(rx[Ether].dst, unicast_peer.mac)
        self.assertEqual(rx[IP].src, self.pg0.local_ip4)
        self.assertEqual(rx[IP].dst, unicast_peer.ip4)
        self.assertEqual(rx[VRRPv3].vrid, vr_id)
        self.assertEqual(rx[VRRPv3].priority, prio)
        self.assertEqual(rx[VRRPv3].ipcount, 1)
        self.assertEqual(rx[VRRPv3].addrlist, [vip])


@unittest.skipUnless(config.extended, "part of extended tests")
class TestVRRP6(VppTestCase):
    """ IPv6 VRRP Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestVRRP6, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestVRRP6, cls).tearDownClass()

    def setUp(self):
        super(TestVRRP6, self).setUp()

        self.create_pg_interfaces(range(2))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip6()
            i.generate_remote_hosts(5)
            i.configure_ipv6_neighbors()

        self._vrs = []
        self._default_flags = (VRRP_VR_FLAG_IPV6 | VRRP_VR_FLAG_PREEMPT)
        self._default_adv = 100

    def tearDown(self):
        for vr in self._vrs:
            try:
                vr_api = vr.query_vpp_config()
                if vr_api.runtime.state != VRRP_VR_STATE_INIT:
                    vr.start_stop(is_start=0)
                vr.remove_vpp_config()
            except:
                self.logger.error("Error cleaning up")

        for i in self.pg_interfaces:
            i.admin_down()
            i.unconfig_ip4()
            i.unconfig_ip6()

        self._vrs = []

        super(TestVRRP6, self).tearDown()

    def verify_vrrp6_mlr(self, pkt, vr):
        ip6 = pkt[IPv6]
        self.assertEqual(ip6.dst, "ff02::16")
        self.assertEqual(ipv6nh[ip6.nh], "Hop-by-Hop Option Header")

        hbh = pkt[IPv6ExtHdrHopByHop]
        self.assertEqual(ipv6nh[hbh.nh], "ICMPv6")

        self.assertTrue(pkt.haslayer(ICMPv6MLReport2))
        mlr = pkt[ICMPv6MLReport2]
        # should contain mc addr records for:
        # - VRRPv3 multicast addr
        # - solicited node mc addr record for each VR virtual IPv6 address
        vips = vr.virtual_ips()
        self.assertEqual(mlr.records_number, len(vips) + 1)
        self.assertEqual(mlr.records[0].dst, vr.adv_dest_ip())

    def verify_vrrp6_adv(self, rx_pkt, vr, prio=None):
        self.assertTrue(rx_pkt.haslayer(Ether))
        self.assertTrue(rx_pkt.haslayer(IPv6))
        self.assertTrue(rx_pkt.haslayer(VRRPv3))

        # generate a packet for this VR and compare it to the one received
        pkt = vr.vrrp_adv_packet(prio=prio)
        self.assertTrue(rx_pkt.haslayer(Ether))
        self.assertTrue(rx_pkt.haslayer(IPv6))
        self.assertTrue(rx_pkt.haslayer(VRRPv3))

        self.assertEqual(pkt, rx_pkt)

    def verify_vrrp6_gna(self, pkt, vr):
        self.assertTrue(pkt.haslayer(Ether))
        self.assertTrue(pkt.haslayer(IPv6))
        self.assertTrue(pkt.haslayer(ICMPv6ND_NA))
        self.assertTrue(pkt.haslayer(ICMPv6NDOptDstLLAddr))

        self.assertEqual(pkt[Ether].dst, "33:33:00:00:00:01")

        self.assertEqual(pkt[IPv6].dst, "ff02::1")
        # convert addrs to packed format since string versions could differ
        src_addr = inet_pton(socket.AF_INET6, pkt[IPv6].src)
        vr_ll_addr = inet_pton(socket.AF_INET6, vr.interface().local_ip6_ll)
        self.assertEqual(src_addr, vr_ll_addr)

        self.assertTrue(pkt[ICMPv6ND_NA].tgt in vr.virtual_ips())
        self.assertEqual(pkt[ICMPv6NDOptDstLLAddr].lladdr, vr.virtual_mac())

    # VR with priority 255 owns the virtual address and should
    # become master and start advertising immediately.
    def test_vrrp6_master_adv(self):
        """ IPv6 Master VR advertises """
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        prio = 255
        intvl = self._default_adv
        vr = VppVRRPVirtualRouter(self, self.pg0, 100,
                                  prio=prio, intvl=intvl,
                                  flags=self._default_flags)
        self._vrs.append(vr)

        vr.add_vpp_config()
        self.logger.info(self.vapi.cli("show vrrp vr"))
        vr.start_stop(is_start=1)
        self.logger.info(self.vapi.cli("show vrrp vr"))
        vr.start_stop(is_start=0)
        self.logger.info(self.vapi.cli("show vrrp vr"))

        pkts = self.pg0.get_capture(4, filter_out_fn=None)

        # Init -> Master: Multicast group Join, VRRP adv, gratuitous NAs sent
        self.verify_vrrp6_mlr(pkts[0], vr)
        self.verify_vrrp6_adv(pkts[1], vr, prio=prio)
        self.verify_vrrp6_gna(pkts[2], vr)
        # Master -> Init: Adv with priority 0 sent to force an election
        self.verify_vrrp6_adv(pkts[3], vr, prio=0)

        vr.remove_vpp_config()
        self._vrs = []

    # VR with priority < 255 enters backup state and does not advertise as
    # long as it receives higher priority advertisements
    def test_vrrp6_backup_noadv(self):
        """ IPv6 Backup VR does not advertise """
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        vr_id = 100
        prio = 100
        intvl = self._default_adv
        intvl_s = intvl * 0.01
        vr = VppVRRPVirtualRouter(self, self.pg0, vr_id,
                                  prio=prio, intvl=intvl,
                                  flags=self._default_flags,
                                  vips=[self.pg0.remote_ip6])
        vr.add_vpp_config()
        self._vrs.append(vr)

        vr.start_stop(is_start=1)

        vr.assert_state_equals(VRRP_VR_STATE_BACKUP)
        # watch for advertisements for 2x the master down preemption timeout
        end_time = vr.start_time() + 2 * vr.master_down_seconds()

        # Init -> Backup: A multicast listener report should be sent
        pkts = self.pg0.get_capture(1, filter_out_fn=None)

        # send higher prio advertisements, should not see VPP send any
        src_ip = self.pg0.remote_ip6_ll
        num_advs = 5
        pkts = [vr.vrrp_adv_packet(prio=prio+10, src_ip=src_ip)]
        self.logger.info(self.vapi.cli("show vlib graph"))
        while time.time() < end_time:
            self.send_and_assert_no_replies(self.pg0, pkts, timeout=intvl_s)
            self.logger.info(self.vapi.cli("show trace"))
            num_advs -= 1

        vr.start_stop(is_start=0)
        self.logger.info(self.vapi.cli("show vrrp vr"))
        vr.remove_vpp_config()
        self._vrs = []

    def test_vrrp6_master_nd(self):
        """ IPv6 Master VR replies to NDP """
        self.pg_start()

        # VR virtual IP is the default, which is the pg local IP
        vr_id = 100
        prio = 255
        intvl = self._default_adv
        vr = VppVRRPVirtualRouter(self, self.pg0, 100,
                                  prio=prio, intvl=intvl,
                                  flags=self._default_flags)
        vr.add_vpp_config()
        self._vrs.append(vr)

        # before the VR is up, NDP should resolve to interface MAC
        self.pg0.resolve_ndp()
        self.assertNotEqual(self.pg0.local_mac, vr.virtual_mac())

        # start the VR, NDP should now resolve to virtual MAC
        vr.start_stop(is_start=1)
        self.pg0.resolve_ndp()
        self.assertEqual(self.pg0.local_mac, vr.virtual_mac())

        # stop the VR, ARP should resolve to interface MAC again
        vr.start_stop(is_start=0)
        self.pg0.resolve_ndp()
        self.assertNotEqual(self.pg0.local_mac, vr.virtual_mac())

        vr.remove_vpp_config()
        self._vrs = []

    def test_vrrp6_backup_nond(self):
        """ IPv6 Backup VR ignores NDP """
        # We need an address for a virtual IP that is not the IP that
        # ARP requests will originate from

        vr_id = 100
        prio = 100
        intvl = self._default_adv
        intvl_s = intvl * 0.01
        vip = self.pg0.remote_hosts[1].ip6
        vr = VppVRRPVirtualRouter(self, self.pg0, vr_id,
                                  prio=prio, intvl=intvl,
                                  flags=self._default_flags,
                                  vips=[vip])
        vr.add_vpp_config()
        self._vrs.append(vr)

        nsma = in6_getnsma(inet_pton(socket.AF_INET6, vip))
        dmac = in6_getnsmac(nsma)
        dst_ip = inet_ntop(socket.AF_INET6, nsma)

        ndp_req = (Ether(dst=dmac, src=self.pg0.remote_mac) /
                   IPv6(dst=dst_ip, src=self.pg0.remote_ip6) /
                   ICMPv6ND_NS(tgt=vip) /
                   ICMPv6NDOptSrcLLAddr(lladdr=self.pg0.remote_mac))

        # Before the VR is started make sure no reply to request for VIP
        self.send_and_assert_no_replies(self.pg0, [ndp_req], timeout=1)

        # VR should start in backup state and still should not reply to NDP
        # send a higher priority adv to make sure it does not become master
        adv = vr.vrrp_adv_packet(prio=prio+10, src_ip=self.pg0.remote_ip6)
        pkts = [adv, ndp_req]
        vr.start_stop(is_start=1)
        self.send_and_assert_no_replies(self.pg0, pkts,  timeout=intvl_s)

        vr.start_stop(is_start=0)

    def test_vrrp6_election(self):
        """ IPv6 Backup VR becomes master if no advertisements received """

        vr_id = 100
        prio = 100
        intvl = self._default_adv
        intvl_s = intvl * 0.01
        vip = self.pg0.remote_ip6
        vr = VppVRRPVirtualRouter(self, self.pg0, vr_id,
                                  prio=prio, intvl=intvl,
                                  flags=self._default_flags,
                                  vips=[vip])
        self._vrs.append(vr)
        vr.add_vpp_config()

        # After adding the VR, it should be in the init state
        vr.assert_state_equals(VRRP_VR_STATE_INIT)

        self.pg_start()
        vr.start_stop(is_start=1)

        # VR should be in backup state after starting
        vr.assert_state_equals(VRRP_VR_STATE_BACKUP)
        end_time = vr.start_time() + vr.master_down_seconds()

        # no advertisements should arrive until timer expires
        self.pg0.enable_capture()
        while (time.time() + intvl_s) < end_time:
            time.sleep(intvl_s)
            self.pg0.assert_nothing_captured(filter_out_fn=is_not_adv)

        # VR should be in master state after timer expires
        self.pg0.enable_capture()
        self.pg0.wait_for_packet(intvl_s, is_not_adv)
        vr.assert_state_equals(VRRP_VR_STATE_MASTER)

    def test_vrrp6_backup_preempts(self):
        """ IPv6 Backup VR preempts lower priority master """

        vr_id = 100
        prio = 100
        intvl = self._default_adv
        intvl_s = intvl * 0.01
        vip = self.pg0.remote_ip6
        vr = VppVRRPVirtualRouter(self, self.pg0, vr_id,
                                  prio=prio, intvl=intvl,
                                  flags=self._default_flags,
                                  vips=[vip])
        self._vrs.append(vr)
        vr.add_vpp_config()

        # After adding the VR, it should be in the init state
        vr.assert_state_equals(VRRP_VR_STATE_INIT)

        self.pg_start()
        vr.start_stop(is_start=1)

        # VR should be in backup state after starting
        vr.assert_state_equals(VRRP_VR_STATE_BACKUP)
        end_time = vr.start_time() + vr.master_down_seconds()

        # send lower prio advertisements until timer expires
        src_ip = self.pg0.remote_ip6
        pkts = [vr.vrrp_adv_packet(prio=prio-10, src_ip=src_ip)]
        while (time.time() + intvl_s) < end_time:
            self.send_and_assert_no_replies(self.pg0, pkts, timeout=intvl_s)
            self.logger.info(self.vapi.cli("show trace"))

        # when timer expires, VR should take over as master
        self.pg0.enable_capture()
        self.pg0.wait_for_packet(timeout=intvl_s, filter_out_fn=is_not_adv)
        vr.assert_state_equals(VRRP_VR_STATE_MASTER)

    def test_vrrp6_master_preempted(self):
        """ IPv6 Master VR preempted by higher priority backup """

        # A prio 255 VR cannot be preempted so the prio has to be lower and
        # we have to wait for it to take over
        vr_id = 100
        prio = 100
        intvl = self._default_adv
        vip = self.pg0.remote_ip6
        vr = VppVRRPVirtualRouter(self, self.pg0, vr_id,
                                  prio=prio, intvl=intvl,
                                  flags=self._default_flags,
                                  vips=[vip])
        self._vrs.append(vr)
        vr.add_vpp_config()

        # After adding the VR, it should be in the init state
        vr.assert_state_equals(VRRP_VR_STATE_INIT)

        # start VR
        vr.start_stop(is_start=1)
        vr.assert_state_equals(VRRP_VR_STATE_BACKUP)

        # wait for VR to take over as master
        end_time = vr.start_time() + vr.master_down_seconds()
        sleep_s = end_time - time.time()
        time.sleep(sleep_s)
        vr.assert_state_equals(VRRP_VR_STATE_MASTER)

        # Build advertisement packet and send it
        pkts = [vr.vrrp_adv_packet(prio=255, src_ip=self.pg0.remote_ip6)]
        self.pg_send(self.pg0, pkts)

        # VR should be in backup state again
        vr.assert_state_equals(VRRP_VR_STATE_BACKUP)

    def test_vrrp6_accept_mode_disabled(self):
        """ IPv6 Master VR does not reply for VIP w/ accept mode off """

        # accept mode only matters when prio < 255, so it will have to
        # come up as a backup and take over as master after the timeout
        vr_id = 100
        prio = 100
        intvl = self._default_adv
        vip = self.pg0.remote_hosts[4].ip6
        vr = VppVRRPVirtualRouter(self, self.pg0, vr_id,
                                  prio=prio, intvl=intvl,
                                  flags=self._default_flags,
                                  vips=[vip])
        self._vrs.append(vr)
        vr.add_vpp_config()

        # After adding the VR, it should be in the init state
        vr.assert_state_equals(VRRP_VR_STATE_INIT)

        # start VR
        vr.start_stop(is_start=1)
        vr.assert_state_equals(VRRP_VR_STATE_BACKUP)

        # wait for VR to take over as master
        end_time = vr.start_time() + vr.master_down_seconds()
        sleep_s = end_time - time.time()
        time.sleep(sleep_s)
        vr.assert_state_equals(VRRP_VR_STATE_MASTER)

        # send an ICMPv6 echo to the VR virtual IP address
        echo = (Ether(dst=vr.virtual_mac(), src=self.pg0.remote_mac) /
                IPv6(dst=vip, src=self.pg0.remote_ip6) /
                ICMPv6EchoRequest(seq=1, id=self.pg0.sw_if_index))
        self.pg_send(self.pg0, [echo])

        # wait for an echo reply. none should be received
        time.sleep(1)
        self.pg0.assert_nothing_captured(filter_out_fn=is_not_echo_reply)

    def test_vrrp6_accept_mode_enabled(self):
        """ IPv6 Master VR replies for VIP w/ accept mode on """

        # A prio 255 VR cannot be preempted so the prio has to be lower and
        # we have to wait for it to take over
        vr_id = 100
        prio = 100
        intvl = self._default_adv
        vip = self.pg0.remote_hosts[4].ip6
        flags = (self._default_flags | VRRP_VR_FLAG_ACCEPT)
        vr = VppVRRPVirtualRouter(self, self.pg0, vr_id,
                                  prio=prio, intvl=intvl,
                                  flags=flags,
                                  vips=[vip])
        self._vrs.append(vr)
        vr.add_vpp_config()

        # After adding the VR, it should be in the init state
        vr.assert_state_equals(VRRP_VR_STATE_INIT)

        # start VR
        vr.start_stop(is_start=1)
        vr.assert_state_equals(VRRP_VR_STATE_BACKUP)

        # wait for VR to take over as master
        end_time = vr.start_time() + vr.master_down_seconds()
        sleep_s = end_time - time.time()
        time.sleep(sleep_s)
        vr.assert_state_equals(VRRP_VR_STATE_MASTER)

        # send an ICMP echo to the VR virtual IP address
        echo = (Ether(dst=vr.virtual_mac(), src=self.pg0.remote_mac) /
                IPv6(dst=vip, src=self.pg0.remote_ip6) /
                ICMPv6EchoRequest(seq=1, id=self.pg0.sw_if_index))
        self.pg_send(self.pg0, [echo])

        # wait for an echo reply.
        time.sleep(1)
        rx_pkts = self.pg0.get_capture(expected_count=1, timeout=1,
                                       filter_out_fn=is_not_echo_reply)

        self.assertEqual(rx_pkts[0][IPv6].src, vip)
        self.assertEqual(rx_pkts[0][IPv6].dst, self.pg0.remote_ip6)
        self.assertEqual(rx_pkts[0][ICMPv6EchoReply].seq, 1)
        self.assertEqual(rx_pkts[0][ICMPv6EchoReply].id, self.pg0.sw_if_index)

    def test_vrrp6_intf_tracking(self):
        """ IPv6 Master VR adjusts priority based on tracked interface """

        vr_id = 100
        prio = 255
        intvl = self._default_adv
        intvl_s = intvl * 0.01
        vip = self.pg0.local_ip6
        vr = VppVRRPVirtualRouter(self, self.pg0, vr_id,
                                  prio=prio, intvl=intvl,
                                  flags=self._default_flags,
                                  vips=[vip])
        self._vrs.append(vr)
        vr.add_vpp_config()

        # After adding the VR, it should be in the init state
        vr.assert_state_equals(VRRP_VR_STATE_INIT)

        # add pg1 as a tracked interface and start the VR
        adjustment = 50
        adjusted_prio = prio - adjustment
        vr.add_del_tracked_interface(is_add=1,
                                     sw_if_index=self.pg1.sw_if_index,
                                     prio=adjustment)
        vr.start_stop(is_start=1)
        vr.assert_state_equals(VRRP_VR_STATE_MASTER)

        adv_configured = vr.vrrp_adv_packet(prio=prio)
        adv_adjusted = vr.vrrp_adv_packet(prio=adjusted_prio)

        # tracked intf is up ->  advertised priority == configured priority
        self.pg0.enable_capture()
        rx = self.pg0.wait_for_packet(timeout=intvl_s,
                                      filter_out_fn=is_not_adv)
        self.assertEqual(rx, adv_configured)

        # take down pg1, verify priority is now being adjusted
        self.pg1.admin_down()
        self.pg0.enable_capture()
        rx = self.pg0.wait_for_packet(timeout=intvl_s,
                                      filter_out_fn=is_not_adv)
        self.assertEqual(rx, adv_adjusted)

        # bring up pg1, verify priority now matches configured value
        self.pg1.admin_up()
        self.pg0.enable_capture()
        rx = self.pg0.wait_for_packet(timeout=intvl_s,
                                      filter_out_fn=is_not_adv)
        self.assertEqual(rx, adv_configured)

        # remove IP address from pg1, verify priority now being adjusted
        self.pg1.unconfig_ip6()
        self.pg0.enable_capture()
        rx = self.pg0.wait_for_packet(timeout=intvl_s,
                                      filter_out_fn=is_not_adv)
        self.assertEqual(rx, adv_adjusted)

        # add IP address to pg1, verify priority now matches configured value
        self.pg1.config_ip6()
        self.pg0.enable_capture()
        rx = self.pg0.wait_for_packet(timeout=intvl_s,
                                      filter_out_fn=is_not_adv)
        self.assertEqual(rx, adv_configured)

    def test_vrrp6_master_adv_unicast(self):
        """ IPv6 Master VR advertises (unicast) """

        vr_id = 100
        prio = 255
        intvl = self._default_adv
        intvl_s = intvl * 0.01
        vip = self.pg0.local_ip6
        flags = (self._default_flags | VRRP_VR_FLAG_UNICAST)
        unicast_peer = self.pg0.remote_hosts[4]
        vr = VppVRRPVirtualRouter(self, self.pg0, vr_id,
                                  prio=prio, intvl=intvl,
                                  flags=flags,
                                  vips=[vip])
        self._vrs.append(vr)
        vr.add_vpp_config()
        vr.set_unicast_peers([unicast_peer.ip6])

        # After adding the VR, it should be in the init state
        vr.assert_state_equals(VRRP_VR_STATE_INIT)

        # Start VR, transition to master
        vr.start_stop(is_start=1)
        vr.assert_state_equals(VRRP_VR_STATE_MASTER)

        self.pg0.enable_capture()
        rx = self.pg0.wait_for_packet(timeout=intvl_s,
                                      filter_out_fn=is_not_adv)

        self.assertTrue(rx.haslayer(Ether))
        self.assertTrue(rx.haslayer(IPv6))
        self.assertTrue(rx.haslayer(VRRPv3))
        self.assertEqual(rx[Ether].src, self.pg0.local_mac)
        self.assertEqual(rx[Ether].dst, unicast_peer.mac)
        self.assertEqual(ip6_normalize(rx[IPv6].src),
                         ip6_normalize(self.pg0.local_ip6_ll))
        self.assertEqual(ip6_normalize(rx[IPv6].dst),
                         ip6_normalize(unicast_peer.ip6))
        self.assertEqual(rx[VRRPv3].vrid, vr_id)
        self.assertEqual(rx[VRRPv3].priority, prio)
        self.assertEqual(rx[VRRPv3].ipcount, 1)
        self.assertEqual(rx[VRRPv3].addrlist, [vip])


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
