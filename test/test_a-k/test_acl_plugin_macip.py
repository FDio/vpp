#!/usr/bin/env python
"""ACL plugin - MACIP tests
"""
import random
import re
import unittest

from socket import inet_ntop, inet_pton, AF_INET, AF_INET6
from struct import *
from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6

from framework import VppTestCase, VppTestRunner, running_extended_tests
from vpp_lo_interface import VppLoInterface
from vpp_papi_provider import L2_VTR_OP
from vpp_sub_interface import VppSubInterface, VppDot1QSubint, VppDot1ADSubint


class MethodHolder(VppTestCase):
    DEBUG = False

    BRIDGED = True
    ROUTED = False

    IS_IP4 = False
    IS_IP6 = True

    DOT1AD = "dot1ad"
    DOT1Q = "dot1q"
    PERMIT_TAGS = True
    DENY_TAGS = False

    # rule types
    DENY = 0
    PERMIT = 1

    # ACL types
    EXACT_IP = 1
    SUBNET_IP = 2
    WILD_IP = 3

    EXACT_MAC = 1
    WILD_MAC = 2
    OUI_MAC = 3

    ACLS = []

    @classmethod
    def setUpClass(cls):
        """
        Perform standard class setup (defined by class method setUpClass in
        class VppTestCase) before running the test case, set test case related
        variables and configure VPP.
        """
        super(MethodHolder, cls).setUpClass()

        cls.pg_if_packet_sizes = [64, 512, 1518, 9018]  # packet sizes
        cls.bd_id = 111
        cls.remote_hosts_count = 200

        try:
            # create 4 pg interfaces, 1 loopback interface
            cls.create_pg_interfaces(range(4))
            cls.create_loopback_interfaces(range(1))

            # create 2 subinterfaces
            cls.subifs = [
                 VppDot1QSubint(cls, cls.pg1, 10),
                 VppDot1ADSubint(cls, cls.pg2, 20, 300, 400),
                 VppDot1QSubint(cls, cls.pg3, 30),
                 VppDot1ADSubint(cls, cls.pg3, 40, 600, 700)]

            cls.subifs[0].set_vtr(L2_VTR_OP.L2_POP_1,
                                  inner=10, push1q=1)
            cls.subifs[1].set_vtr(L2_VTR_OP.L2_POP_2,
                                  outer=300, inner=400, push1q=1)
            cls.subifs[2].set_vtr(L2_VTR_OP.L2_POP_1,
                                  inner=30, push1q=1)
            cls.subifs[3].set_vtr(L2_VTR_OP.L2_POP_2,
                                  outer=600, inner=700, push1q=1)

            cls.interfaces = list(cls.pg_interfaces)
            cls.interfaces.extend(cls.lo_interfaces)
            cls.interfaces.extend(cls.subifs)

            for i in cls.interfaces:
                i.admin_up()

            # Create BD with MAC learning enabled and put interfaces to this BD
            cls.vapi.sw_interface_set_l2_bridge(
                cls.loop0.sw_if_index, bd_id=cls.bd_id, bvi=1)
            cls.vapi.sw_interface_set_l2_bridge(
                cls.pg0.sw_if_index, bd_id=cls.bd_id)
            cls.vapi.sw_interface_set_l2_bridge(
                cls.pg1.sw_if_index, bd_id=cls.bd_id)
            cls.vapi.sw_interface_set_l2_bridge(
                cls.subifs[0].sw_if_index, bd_id=cls.bd_id)
            cls.vapi.sw_interface_set_l2_bridge(
                cls.subifs[1].sw_if_index, bd_id=cls.bd_id)

            # Configure IPv4/6 addresses on loop interface and routed interface
            cls.loop0.config_ip4()
            cls.loop0.config_ip6()
            cls.pg2.config_ip4()
            cls.pg2.config_ip6()
            cls.pg3.config_ip4()
            cls.pg3.config_ip6()

            # Configure MAC address binding to IPv4 neighbors on loop0
            cls.loop0.generate_remote_hosts(cls.remote_hosts_count)
            # Modify host mac addresses to have different OUI parts
            for i in range(2, cls.remote_hosts_count + 2):
                mac = cls.loop0.remote_hosts[i-2]._mac.split(':')
                mac[2] = format(int(mac[2], 16) + i, "02x")
                cls.loop0.remote_hosts[i - 2]._mac = ":".join(mac)

            cls.loop0.configure_ipv4_neighbors()
            cls.loop0.configure_ipv6_neighbors()

            # configure MAC address on pg3
            cls.pg3.resolve_arp()
            cls.pg3.resolve_ndp()

            # configure MAC address on subifs
            for i in cls.subifs:
                i.config_ip4()
                i.resolve_arp()
                i.config_ip6()

            # configure MAC address on pg2
            cls.pg2.resolve_arp()
            cls.pg2.resolve_ndp()

            # Loopback BVI interface has remote hosts
            # one half of hosts are behind pg0 second behind pg1,pg2,pg3 subifs
            cls.pg0.remote_hosts = cls.loop0.remote_hosts[:100]
            cls.subifs[0].remote_hosts = cls.loop0.remote_hosts[100:125]
            cls.subifs[1].remote_hosts = cls.loop0.remote_hosts[125:150]
            cls.subifs[2].remote_hosts = cls.loop0.remote_hosts[150:175]
            cls.subifs[3].remote_hosts = cls.loop0.remote_hosts[175:]

        except Exception:
            super(TestMACIP, cls).tearDownClass()
            raise

    def setUp(self):
        super(MethodHolder, self).setUp()
        self.reset_packet_infos()
        del self.ACLS[:]

    def tearDown(self):
        """
        Show various debug prints after each test.
        """
        super(MethodHolder, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.ppcli("show interface address"))
            self.logger.info(self.vapi.ppcli("show hardware"))
            self.logger.info(self.vapi.ppcli("sh acl-plugin macip acl"))
            self.logger.info(self.vapi.ppcli("sh acl-plugin macip interface"))
            self.logger.info(self.vapi.ppcli("sh classify tables verbose"))
            self.logger.info(self.vapi.ppcli("sh acl-plugin acl"))
            self.logger.info(self.vapi.ppcli("sh acl-plugin interface"))
            self.logger.info(self.vapi.ppcli("sh acl-plugin tables"))
            # print self.vapi.ppcli("show interface address")
            # print self.vapi.ppcli("show hardware")
            # print self.vapi.ppcli("sh acl-plugin macip interface")
            # print self.vapi.ppcli("sh acl-plugin macip acl")
        self.delete_acls()

    def macip_acl_dump_debug(self):
        acls = self.vapi.macip_acl_dump()
        if self.DEBUG:
            for acl in acls:
                print "ACL #"+str(acl.acl_index)
                for r in acl.r:
                    rule = "ACTION"
                    if r.is_permit == 1:
                        rule = "PERMIT"
                    elif r.is_permit == 0:
                        rule = "DENY  "
                    print "    IP6" if r.is_ipv6 else "    IP4", \
                          rule, \
                          r.src_mac.encode('hex'), \
                          r.src_mac_mask.encode('hex'),\
                          unpack('<16B', r.src_ip_addr), \
                          r.src_ip_prefix_len
        return acls

    def create_rules(self, mac_type=EXACT_MAC, ip_type=EXACT_IP,
                     acl_count=1, rules_count=[1]):
        acls = []
        src_mac = int("220000dead00", 16)
        for acl in range(2, (acl_count+1) * 2):
            rules = []
            host = random.choice(self.loop0.remote_hosts)
            is_ip6 = acl % 2
            ip4 = host.ip4.split('.')
            ip6 = list(unpack('<16B', inet_pton(AF_INET6, host.ip6)))

            if ip_type == self.EXACT_IP:
                prefix_len4 = 32
                prefix_len6 = 128
            elif ip_type == self.WILD_IP:
                ip4 = [0, 0, 0, 0]
                ip6 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                prefix_len4 = 0
                prefix_len6 = 0
                rules_count[(acl / 2) - 1] = 1
            else:
                prefix_len4 = 24
                prefix_len6 = 64

            if mac_type == self.EXACT_MAC:
                mask = "ff:ff:ff:ff:ff:ff"
            elif mac_type == self.WILD_MAC:
                mask = "00:00:00:00:00:00"
            elif mac_type == self.OUI_MAC:
                mask = "ff:ff:ff:00:00:00"
            else:
                mask = "ff:ff:ff:ff:ff:00"

            ip = ip6 if is_ip6 else ip4
            ip_len = prefix_len6 if is_ip6 else prefix_len4

            for i in range(0, rules_count[(acl / 2) - 1]):
                src_mac += 16777217
                if mac_type == self.WILD_MAC:
                    mac = "00:00:00:00:00:00"
                elif mac_type == self.OUI_MAC:
                    mac = ':'.join(re.findall('..', '{:02x}'.format(
                        src_mac))[:3])+":00:00:00"
                else:
                    mac = ':'.join(re.findall('..', '{:02x}'.format(src_mac)))

                if ip_type == self.EXACT_IP:
                    ip4[3] = random.randint(100, 200)
                    ip6[15] = random.randint(100, 200)
                elif ip_type == self.SUBNET_IP:
                    ip4[2] = random.randint(100, 200)
                    ip4[3] = 0
                    ip6[8] = random.randint(100, 200)
                    ip6[15] = 0
                ip_pack = ''
                for j in range(0, len(ip)):
                    ip_pack += pack('<B', int(ip[j]))

                rule = ({'is_permit': self.PERMIT,
                         'is_ipv6': is_ip6,
                         'src_ip_addr': ip_pack,
                         'src_ip_prefix_len': ip_len,
                         'src_mac': mac.replace(':', '').decode('hex'),
                         'src_mac_mask': mask.replace(':', '').decode('hex')})
                rules.append(rule)
                if ip_type == self.WILD_IP:
                    break

            acls.append(rules)
            src_mac += 1099511627776
        return acls

    def apply_macip_rules(self, acls):
        for acl in acls:
            reply = self.vapi.macip_acl_add(acl)
            self.assertEqual(reply.retval, 0)
            self.ACLS.append(reply.acl_index)

    def verify_macip_acls(self, acl_count, rules_count, expected_count=2):
        reply = self.macip_acl_dump_debug()
        for acl in range(2, (acl_count+1) * 2):
            self.assertEqual(reply[acl - 2].count, rules_count[acl/2-1])

        self.vapi.macip_acl_interface_get()

        self.vapi.macip_acl_interface_add_del(sw_if_index=0, acl_index=0)
        self.vapi.macip_acl_interface_add_del(sw_if_index=1, acl_index=1)

        reply = self.vapi.macip_acl_interface_get()
        self.assertEqual(reply.count, expected_count)

    def delete_acls(self):
        for acl in range(len(self.ACLS)-1, -1, -1):
            self.vapi.macip_acl_del(self.ACLS[acl])

        reply = self.vapi.macip_acl_dump()
        self.assertEqual(len(reply), 0)

        intf_acls = self.vapi.ppcli("sh acl-plugin interface").split(
            "\nsw_if_index")
        for i_a in intf_acls:
            ia = i_a.split(":")
            if len(ia) == 3:
                sw_if_index = int(ia[0])
                acl_index = int(ia[2])
                self.vapi.acl_interface_add_del(sw_if_index, acl_index, 0)
                self.vapi.acl_del(acl_index)

    def create_stream(self, mac_type, ip_type, packet_count,
                      src_if, dst_if, traffic, is_ip6, tags=PERMIT_TAGS):
        # exact MAC and exact IP
        # exact MAC and subnet of IPs
        # exact MAC and wildcard IP
        # wildcard MAC and exact IP
        # wildcard MAC and subnet of IPs
        # wildcard MAC and wildcard IP
        # OUI restricted MAC and exact IP
        # OUI restricted MAC and subnet of IPs
        # OUI restricted MAC and wildcard IP

        packets = []
        macip_rules = []
        acl_rules = []
        ip_permit = ""
        mac_permit = ""
        dst_mac = ""
        mac_rule = "00:00:00:00:00:00"
        mac_mask = "00:00:00:00:00:00"
        for p in range(0, packet_count):
            remote_dst_index = p % len(dst_if.remote_hosts)
            remote_dst_host = dst_if.remote_hosts[remote_dst_index]

            dst_port = 1234 + p
            src_port = 4321 + p
            is_permit = self.PERMIT if p % 3 == 0 else self.DENY
            denyMAC = True if not is_permit and p % 3 == 1 else False
            denyIP = True if not is_permit and p % 3 == 2 else False
            if not is_permit and ip_type == self.WILD_IP:
                denyMAC = True
            if not is_permit and mac_type == self.WILD_MAC:
                denyIP = True

            if traffic == self.BRIDGED:
                if is_permit:
                    src_mac = remote_dst_host._mac
                    dst_mac = 'de:ad:00:00:00:00'
                    src_ip4 = remote_dst_host.ip4
                    dst_ip4 = src_if.remote_ip4
                    src_ip6 = remote_dst_host.ip6
                    dst_ip6 = src_if.remote_ip6
                    ip_permit = src_ip6 if is_ip6 else src_ip4
                    mac_permit = src_mac
                if denyMAC:
                    mac = src_mac.split(':')
                    mac[0] = format(int(mac[0], 16)+1, "02x")
                    src_mac = ":".join(mac)
                    if is_ip6:
                        src_ip6 = ip_permit
                    else:
                        src_ip4 = ip_permit
                if denyIP:
                    if ip_type != self.WILD_IP:
                        src_mac = mac_permit
                    src_ip4 = remote_dst_host.ip4
                    dst_ip4 = src_if.remote_ip4
                    src_ip6 = remote_dst_host.ip6
                    dst_ip6 = src_if.remote_ip6
            else:
                if is_permit:
                    src_mac = remote_dst_host._mac
                    dst_mac = src_if.local_mac
                    src_ip4 = src_if.remote_ip4
                    dst_ip4 = remote_dst_host.ip4
                    src_ip6 = src_if.remote_ip6
                    dst_ip6 = remote_dst_host.ip6
                    ip_permit = src_ip6 if is_ip6 else src_ip4
                    mac_permit = src_mac
                if denyMAC:
                    mac = src_mac.split(':')
                    mac[0] = format(int(mac[0], 16) + 1, "02x")
                    src_mac = ":".join(mac)
                    if is_ip6:
                        src_ip6 = ip_permit
                    else:
                        src_ip4 = ip_permit
                if denyIP:
                    src_mac = remote_dst_host._mac
                    if ip_type != self.WILD_IP:
                        src_mac = mac_permit
                    src_ip4 = remote_dst_host.ip4
                    dst_ip4 = src_if.remote_ip4
                    src_ip6 = remote_dst_host.ip6
                    dst_ip6 = src_if.remote_ip6

            if is_permit:
                info = self.create_packet_info(src_if, dst_if)
                payload = self.info_to_payload(info)
            else:
                payload = "to be blocked"

            if mac_type == self.WILD_MAC:
                mac = src_mac.split(':')
                for i in range(1, 5):
                    mac[i] = format(random.randint(0, 255), "02x")
                src_mac = ":".join(mac)

            # create packet
            packet = Ether(src=src_mac, dst=dst_mac)
            ip_rule = src_ip6 if is_ip6 else src_ip4
            if is_ip6:
                if ip_type != self.EXACT_IP:
                    sub_ip = list(unpack('<16B', inet_pton(AF_INET6, ip_rule)))
                    if ip_type == self.WILD_IP:
                        sub_ip[0] = random.randint(240, 254)
                        sub_ip[1] = random.randint(230, 239)
                        sub_ip[14] = random.randint(100, 199)
                        sub_ip[15] = random.randint(200, 255)
                    elif ip_type == self.SUBNET_IP:
                        if denyIP:
                            sub_ip[2] = str(int(sub_ip[2]) + 1)
                        sub_ip[14] = random.randint(100, 199)
                        sub_ip[15] = random.randint(200, 255)
                    src_ip6 = inet_ntop(AF_INET6, str(bytearray(sub_ip)))
                packet /= IPv6(src=src_ip6, dst=dst_ip6)
            else:
                if ip_type != self.EXACT_IP:
                    sub_ip = ip_rule.split('.')
                    if ip_type == self.WILD_IP:
                        sub_ip[0] = str(random.randint(1, 49))
                        sub_ip[1] = str(random.randint(50, 99))
                        sub_ip[2] = str(random.randint(100, 199))
                        sub_ip[3] = str(random.randint(200, 255))
                    elif ip_type == self.SUBNET_IP:
                        if denyIP:
                            sub_ip[1] = str(int(sub_ip[1])+1)
                        sub_ip[2] = str(random.randint(100, 199))
                        sub_ip[3] = str(random.randint(200, 255))
                    src_ip4 = ".".join(sub_ip)
                packet /= IP(src=src_ip4, dst=dst_ip4, frag=0, flags=0)

            packet /= UDP(sport=src_port, dport=dst_port)/Raw(payload)

            packet[Raw].load += " mac:"+src_mac

            size = self.pg_if_packet_sizes[p % len(self.pg_if_packet_sizes)]
            if isinstance(src_if, VppSubInterface):
                size = size + 4
            if isinstance(src_if, VppDot1QSubint):
                if src_if is self.subifs[0]:
                    if tags == self.PERMIT_TAGS:
                        packet = src_if.add_dot1q_layer(packet, 10)
                    else:
                        packet = src_if.add_dot1q_layer(packet, 11)
                else:
                    if tags == self.PERMIT_TAGS:
                        packet = src_if.add_dot1q_layer(packet, 30)
                    else:
                        packet = src_if.add_dot1q_layer(packet, 33)
            elif isinstance(src_if, VppDot1ADSubint):
                if src_if is self.subifs[1]:
                    if tags == self.PERMIT_TAGS:
                        packet = src_if.add_dot1ad_layer(packet, 300, 400)
                    else:
                        packet = src_if.add_dot1ad_layer(packet, 333, 444)
                else:
                    if tags == self.PERMIT_TAGS:
                        packet = src_if.add_dot1ad_layer(packet, 600, 700)
                    else:
                        packet = src_if.add_dot1ad_layer(packet, 666, 777)
            self.extend_packet(packet, size)
            packets.append(packet)

            # create suitable MACIP rule
            if mac_type == self.EXACT_MAC:
                mac_rule = src_mac
                mac_mask = "ff:ff:ff:ff:ff:ff"
            elif mac_type == self.WILD_MAC:
                mac_rule = "00:00:00:00:00:00"
                mac_mask = "00:00:00:00:00:00"
            elif mac_type == self.OUI_MAC:
                mac = src_mac.split(':')
                mac[3] = mac[4] = mac[5] = '00'
                mac_rule = ":".join(mac)
                mac_mask = "ff:ff:ff:00:00:00"

            if is_ip6:
                if ip_type == self.WILD_IP:
                    ip = "0::0"
                else:
                    ip = src_ip6
                    if ip_type == self.SUBNET_IP:
                        sub_ip = list(unpack('<16B', inet_pton(AF_INET6, ip)))
                        for i in range(8, 16):
                            sub_ip[i] = 0
                        ip = inet_ntop(AF_INET6, str(bytearray(sub_ip)))
            else:
                if ip_type == self.WILD_IP:
                    ip = "0.0.0.0"
                else:
                    ip = src_ip4
                    if ip_type == self.SUBNET_IP:
                        sub_ip = ip.split('.')
                        sub_ip[2] = sub_ip[3] = '0'
                        ip = ".".join(sub_ip)

            prefix_len = 128 if is_ip6 else 32
            if ip_type == self.WILD_IP:
                prefix_len = 0
            elif ip_type == self.SUBNET_IP:
                prefix_len = 64 if is_ip6 else 16
            ip_rule = inet_pton(AF_INET6 if is_ip6 else AF_INET, ip)

            # create suitable ACL rule
            if is_permit:
                rule_l4_sport = packet[UDP].sport
                rule_l4_dport = packet[UDP].dport
                rule_family = AF_INET6 if packet.haslayer(IPv6) else AF_INET
                rule_prefix_len = 128 if packet.haslayer(IPv6) else 32
                rule_l3_layer = IPv6 if packet.haslayer(IPv6) else IP
                if packet.haslayer(IPv6):
                    rule_l4_proto = packet[UDP].overload_fields[IPv6]['nh']
                else:
                    rule_l4_proto = packet[IP].proto

                acl_rule = {
                    'is_permit': is_permit,
                    'is_ipv6': is_ip6,
                    'src_ip_addr': inet_pton(rule_family,
                                             packet[rule_l3_layer].src),
                    'src_ip_prefix_len': rule_prefix_len,
                    'dst_ip_addr': inet_pton(rule_family,
                                             packet[rule_l3_layer].dst),
                    'dst_ip_prefix_len': rule_prefix_len,
                    'srcport_or_icmptype_first': rule_l4_sport,
                    'srcport_or_icmptype_last': rule_l4_sport,
                    'dstport_or_icmpcode_first': rule_l4_dport,
                    'dstport_or_icmpcode_last': rule_l4_dport,
                    'proto': rule_l4_proto}
                acl_rules.append(acl_rule)

            if mac_type == self.WILD_MAC and ip_type == self.WILD_IP and p > 0:
                continue

            if is_permit:
                macip_rule = ({
                    'is_permit': is_permit,
                    'is_ipv6': is_ip6,
                    'src_ip_addr': ip_rule,
                    'src_ip_prefix_len': prefix_len,
                    'src_mac': mac_rule.replace(':', '').decode('hex'),
                    'src_mac_mask': mac_mask.replace(':', '').decode('hex')})
                macip_rules.append(macip_rule)

        # deny all other packets
        if not (mac_type == self.WILD_MAC and ip_type == self.WILD_IP):
            macip_rule = ({'is_permit': 0,
                           'is_ipv6': is_ip6,
                           'src_ip_addr': "",
                           'src_ip_prefix_len': 0,
                           'src_mac': "",
                           'src_mac_mask': ""})
            macip_rules.append(macip_rule)

        acl_rule = {'is_permit': 0,
                    'is_ipv6': is_ip6}
        acl_rules.append(acl_rule)
        return {'stream': packets,
                'macip_rules': macip_rules,
                'acl_rules': acl_rules}

    def verify_capture(self, stream, capture, is_ip6):
        """
        :param stream:
        :param capture:
        :param is_ip6:
        :return:
        """
        # p_l3 = IPv6 if is_ip6 else IP
        # if self.DEBUG:
        #     for p in stream:
        #         print p[Ether].src, p[Ether].dst, p[p_l3].src, p[p_l3].dst
        #
        # acls = self.macip_acl_dump_debug()

        # TODO : verify
        # for acl in acls:
        #     for r in acl.r:
        #         print r.src_mac.encode('hex'), \
        #               r.src_mac_mask.encode('hex'),\
        #               unpack('<16B', r.src_ip_addr), \
        #               r.src_ip_prefix_len
        #
        # for p in capture:
        #     print p[Ether].src, p[Ether].dst, p[p_l3].src, p[p_l3].dst
        #     data = p[Raw].load.split(':',1)[1]
        #     print p[p_l3].src, data

    def run_traffic(self, mac_type, ip_type, traffic, is_ip6, packets,
                    do_not_expected_capture=False, tags=None,
                    apply_rules=True, isMACIP=True, permit_tags=PERMIT_TAGS):
        self.reset_packet_infos()

        if tags is None:
            tx_if = self.pg0 if traffic == self.BRIDGED else self.pg3
            rx_if = self.pg3 if traffic == self.BRIDGED else self.pg0
            src_if = self.pg3
            dst_if = self.loop0
        else:
            if tags == self.DOT1Q:
                if traffic == self.BRIDGED:
                    tx_if = self.subifs[0]
                    rx_if = self.pg0
                    src_if = self.subifs[0]
                    dst_if = self.loop0
                else:
                    tx_if = self.subifs[2]
                    rx_if = self.pg0
                    src_if = self.subifs[2]
                    dst_if = self.loop0
            elif tags == self.DOT1AD:
                if traffic == self.BRIDGED:
                    tx_if = self.subifs[1]
                    rx_if = self.pg0
                    src_if = self.subifs[1]
                    dst_if = self.loop0
                else:
                    tx_if = self.subifs[3]
                    rx_if = self.pg0
                    src_if = self.subifs[3]
                    dst_if = self.loop0
            else:
                return

        test_dict = self.create_stream(mac_type, ip_type, packets,
                                       src_if, dst_if,
                                       traffic, is_ip6,
                                       tags=permit_tags)

        if apply_rules:
            if isMACIP:
                reply = self.vapi.macip_acl_add(test_dict['macip_rules'])
            else:
                reply = self.vapi.acl_add_replace(acl_index=4294967295,
                                                  r=test_dict['acl_rules'])
            self.assertEqual(reply.retval, 0)
            acl_index = reply.acl_index

            if isMACIP:
                self.vapi.macip_acl_interface_add_del(
                                                 sw_if_index=tx_if.sw_if_index,
                                                 acl_index=acl_index)
                reply = self.vapi.macip_acl_interface_get()
                self.assertEqual(reply.acls[tx_if.sw_if_index], acl_index)
                self.ACLS.append(reply.acls[tx_if.sw_if_index])
            else:
                self.vapi.acl_interface_add_del(
                    sw_if_index=tx_if.sw_if_index, acl_index=acl_index)
        else:
            self.vapi.macip_acl_interface_add_del(
                sw_if_index=tx_if.sw_if_index,
                acl_index=0)

        if not isinstance(src_if, VppSubInterface):
            tx_if.add_stream(test_dict['stream'])
        else:
            tx_if.parent.add_stream(test_dict['stream'])
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        if do_not_expected_capture:
            rx_if.get_capture(0)
        else:
            if traffic == self.BRIDGED and mac_type == self.WILD_MAC and \
                    ip_type == self.WILD_IP:
                capture = rx_if.get_capture(packets)
            else:
                capture = rx_if.get_capture(
                    self.get_packet_count_for_if_idx(dst_if.sw_if_index))
            self.verify_capture(test_dict['stream'], capture, is_ip6)
        if not isMACIP:
            self.vapi.acl_interface_add_del(sw_if_index=tx_if.sw_if_index,
                                            acl_index=acl_index, is_add=0)
            self.vapi.acl_del(acl_index)

    def run_test_acls(self, mac_type, ip_type, acl_count,
                      rules_count, traffic=None, ip=None):
        self.apply_macip_rules(self.create_rules(mac_type, ip_type, acl_count,
                                                 rules_count))
        self.verify_macip_acls(acl_count, rules_count)

        if traffic is not None:
            self.run_traffic(self.EXACT_MAC, self.EXACT_IP, traffic, ip, 9)


class TestMACIP_IP4(MethodHolder):
    """MACIP with IP4 traffic"""

    def test_acl_bridged_ip4_exactMAC_exactIP(self):
        """ IP4 MACIP exactMAC|exactIP ACL bridged traffic
        """
        self.run_traffic(self.EXACT_MAC, self.EXACT_IP,
                         self.BRIDGED, self.IS_IP4, 9)

    def test_acl_bridged_ip4_exactMAC_subnetIP(self):
        """ IP4 MACIP exactMAC|subnetIP ACL bridged traffic
        """

        self.run_traffic(self.EXACT_MAC, self.SUBNET_IP,
                         self.BRIDGED, self.IS_IP4, 9)

    def test_acl_bridged_ip4_exactMAC_wildIP(self):
        """ IP4 MACIP exactMAC|wildIP ACL bridged traffic
        """

        self.run_traffic(self.EXACT_MAC, self.WILD_IP,
                         self.BRIDGED, self.IS_IP4, 9)

    def test_acl_bridged_ip4_ouiMAC_exactIP(self):
        """ IP4 MACIP ouiMAC|exactIP ACL bridged traffic
        """

        self.run_traffic(self.OUI_MAC, self.EXACT_IP,
                         self.BRIDGED, self.IS_IP4, 3)

    def test_acl_bridged_ip4_ouiMAC_subnetIP(self):
        """ IP4 MACIP ouiMAC|subnetIP ACL bridged traffic
        """

        self.run_traffic(self.OUI_MAC, self.SUBNET_IP,
                         self.BRIDGED, self.IS_IP4, 9)

    def test_acl_bridged_ip4_ouiMAC_wildIP(self):
        """ IP4 MACIP ouiMAC|wildIP ACL bridged traffic
        """

        self.run_traffic(self.OUI_MAC, self.WILD_IP,
                         self.BRIDGED, self.IS_IP4, 9)

    def test_ac_bridgedl_ip4_wildMAC_exactIP(self):
        """ IP4 MACIP wildcardMAC|exactIP ACL bridged traffic
        """

        self.run_traffic(self.WILD_MAC, self.EXACT_IP,
                         self.BRIDGED, self.IS_IP4, 9)

    def test_acl_bridged_ip4_wildMAC_subnetIP(self):
        """ IP4 MACIP wildcardMAC|subnetIP ACL bridged traffic
        """

        self.run_traffic(self.WILD_MAC, self.SUBNET_IP,
                         self.BRIDGED, self.IS_IP4, 9)

    def test_acl_bridged_ip4_wildMAC_wildIP(self):
        """ IP4 MACIP wildcardMAC|wildIP ACL bridged traffic
        """

        self.run_traffic(self.WILD_MAC, self.WILD_IP,
                         self.BRIDGED, self.IS_IP4, 9)

    def test_acl_routed_ip4_exactMAC_exactIP(self):
        """ IP4 MACIP exactMAC|exactIP ACL routed traffic
        """
        self.run_traffic(self.EXACT_MAC, self.EXACT_IP,
                         self.ROUTED, self.IS_IP4, 9)

    def test_acl_routed_ip4_exactMAC_subnetIP(self):
        """ IP4 MACIP exactMAC|subnetIP ACL routed traffic
        """
        self.run_traffic(self.EXACT_MAC, self.SUBNET_IP,
                         self.ROUTED, self.IS_IP4, 9)

    def test_acl_routed_ip4_exactMAC_wildIP(self):
        """ IP4 MACIP exactMAC|wildIP ACL routed traffic
        """
        self.run_traffic(self.EXACT_MAC, self.WILD_IP,
                         self.ROUTED, self.IS_IP4, 9)

    def test_acl_routed_ip4_ouiMAC_exactIP(self):
        """ IP4 MACIP ouiMAC|exactIP ACL routed traffic
        """

        self.run_traffic(self.OUI_MAC, self.EXACT_IP,
                         self.ROUTED, self.IS_IP4, 9)

    def test_acl_routed_ip4_ouiMAC_subnetIP(self):
        """ IP4 MACIP ouiMAC|subnetIP ACL routed traffic
        """

        self.run_traffic(self.OUI_MAC, self.SUBNET_IP,
                         self.ROUTED, self.IS_IP4, 9)

    def test_acl_routed_ip4_ouiMAC_wildIP(self):
        """ IP4 MACIP ouiMAC|wildIP ACL routed traffic
        """

        self.run_traffic(self.OUI_MAC, self.WILD_IP,
                         self.ROUTED, self.IS_IP4, 9)

    def test_acl_routed_ip4_wildMAC_exactIP(self):
        """ IP4 MACIP wildcardMAC|exactIP ACL routed traffic
        """

        self.run_traffic(self.WILD_MAC, self.EXACT_IP,
                         self.ROUTED, self.IS_IP4, 9)

    def test_acl_routed_ip4_wildMAC_subnetIP(self):
        """ IP4 MACIP wildcardMAC|subnetIP ACL routed traffic
        """

        self.run_traffic(self.WILD_MAC, self.SUBNET_IP,
                         self.ROUTED, self.IS_IP4, 9)

    def test_acl_routed_ip4_wildMAC_wildIP(self):
        """ IP4 MACIP wildcardMAC|wildIP ACL
        """

        self.run_traffic(self.WILD_MAC, self.WILD_IP,
                         self.ROUTED, self.IS_IP4, 9)

    def test_acl_replace_traffic_ip4(self):
        """ MACIP replace ACL with IP4 traffic
        """
        self.run_traffic(self.OUI_MAC, self.SUBNET_IP,
                         self.BRIDGED, self.IS_IP4, 9)

        r = self.create_rules()
        # replace acls #2, #3 with new
        reply = self.vapi.macip_acl_add_replace(r[0], 0)
        self.assertEqual(reply.retval, 0)
        self.assertEqual(reply.acl_index, 0)

        self.run_traffic(self.EXACT_MAC, self.EXACT_IP,
                         self.BRIDGED, self.IS_IP4, 9, True)


class TestMACIP_IP6(MethodHolder):
    """MACIP with IP6 traffic"""

    def test_acl_bridged_ip6_exactMAC_exactIP(self):
        """ IP6 MACIP exactMAC|exactIP ACL bridged traffic
        """

        self.run_traffic(self.EXACT_MAC, self.EXACT_IP,
                         self.BRIDGED, self.IS_IP6, 9)

    def test_acl_bridged_ip6_exactMAC_subnetIP(self):
        """ IP6 MACIP exactMAC|subnetIP ACL bridged traffic
        """

        self.run_traffic(self.EXACT_MAC, self.SUBNET_IP,
                         self.BRIDGED, self.IS_IP6, 9)

    def test_acl_bridged_ip6_exactMAC_wildIP(self):
        """ IP6 MACIP exactMAC|wildIP ACL bridged traffic
        """

        self.run_traffic(self.EXACT_MAC, self.WILD_IP,
                         self.BRIDGED, self.IS_IP6, 9)

    def test_acl_bridged_ip6_ouiMAC_exactIP(self):
        """ IP6 MACIP oui_MAC|exactIP ACL bridged traffic
        """

        self.run_traffic(self.OUI_MAC, self.EXACT_IP,
                         self.BRIDGED, self.IS_IP6, 9)

    def test_acl_bridged_ip6_ouiMAC_subnetIP(self):
        """ IP6 MACIP ouiMAC|subnetIP ACL bridged traffic
        """

        self.run_traffic(self.OUI_MAC, self.SUBNET_IP,
                         self.BRIDGED, self.IS_IP6, 9)

    def test_acl_bridged_ip6_ouiMAC_wildIP(self):
        """ IP6 MACIP ouiMAC|wildIP ACL bridged traffic
        """

        self.run_traffic(self.OUI_MAC, self.WILD_IP,
                         self.BRIDGED, self.IS_IP6, 9)

    def test_acl_bridged_ip6_wildMAC_exactIP(self):
        """ IP6 MACIP wildcardMAC|exactIP ACL bridged traffic
        """

        self.run_traffic(self.WILD_MAC, self.EXACT_IP,
                         self.BRIDGED, self.IS_IP6, 9)

    def test_acl_bridged_ip6_wildMAC_subnetIP(self):
        """ IP6 MACIP wildcardMAC|subnetIP ACL bridged traffic
        """

        self.run_traffic(self.WILD_MAC, self.SUBNET_IP,
                         self.BRIDGED, self.IS_IP6, 9)

    def test_acl_bridged_ip6_wildMAC_wildIP(self):
        """ IP6 MACIP wildcardMAC|wildIP ACL bridged traffic
        """

        self.run_traffic(self.WILD_MAC, self.WILD_IP,
                         self.BRIDGED, self.IS_IP6, 9)

    def test_acl_routed_ip6_exactMAC_exactIP(self):
        """ IP6 MACIP exactMAC|exactIP ACL routed traffic
        """

        self.run_traffic(self.EXACT_MAC, self.EXACT_IP,
                         self.ROUTED, self.IS_IP6, 9)

    def test_acl_routed_ip6_exactMAC_subnetIP(self):
        """ IP6 MACIP exactMAC|subnetIP ACL routed traffic
        """

        self.run_traffic(self.EXACT_MAC, self.SUBNET_IP,
                         self.ROUTED, self.IS_IP6, 9)

    def test_acl_routed_ip6_exactMAC_wildIP(self):
        """ IP6 MACIP exactMAC|wildIP ACL routed traffic
        """

        self.run_traffic(self.EXACT_MAC, self.WILD_IP,
                         self.ROUTED, self.IS_IP6, 9)

    def test_acl_routed_ip6_ouiMAC_exactIP(self):
        """ IP6 MACIP ouiMAC|exactIP ACL routed traffic
        """

        self.run_traffic(self.OUI_MAC, self.EXACT_IP,
                         self.ROUTED, self.IS_IP6, 9)

    def test_acl_routed_ip6_ouiMAC_subnetIP(self):
        """ IP6 MACIP ouiMAC|subnetIP ACL routed traffic
        """

        self.run_traffic(self.OUI_MAC, self.SUBNET_IP,
                         self.ROUTED, self.IS_IP6, 9)

    def test_acl_routed_ip6_ouiMAC_wildIP(self):
        """ IP6 MACIP ouiMAC|wildIP ACL routed traffic
        """

        self.run_traffic(self.OUI_MAC, self.WILD_IP,
                         self.ROUTED, self.IS_IP6, 9)

    def test_acl_routed_ip6_wildMAC_exactIP(self):
        """ IP6 MACIP wildcardMAC|exactIP ACL routed traffic
        """

        self.run_traffic(self.WILD_MAC, self.EXACT_IP,
                         self.ROUTED, self.IS_IP6, 9)

    def test_acl_routed_ip6_wildMAC_subnetIP(self):
        """ IP6 MACIP wildcardMAC|subnetIP ACL routed traffic
        """

        self.run_traffic(self.WILD_MAC, self.SUBNET_IP,
                         self.ROUTED, self.IS_IP6, 9)

    def test_acl_routed_ip6_wildMAC_wildIP(self):
        """ IP6 MACIP wildcardMAC|wildIP ACL
        """

        self.run_traffic(self.WILD_MAC, self.WILD_IP,
                         self.ROUTED, self.IS_IP6, 9)

    def test_acl_replace_traffic_ip6(self):
        """ MACIP replace ACL with IP6 traffic
        """
        self.run_traffic(self.OUI_MAC, self.SUBNET_IP,
                         self.BRIDGED, self.IS_IP6, 9)

        r = self.create_rules()
        # replace acls #2, #3 with new
        reply = self.vapi.macip_acl_add_replace(r[0], 0)
        self.assertEqual(reply.retval, 0)
        self.assertEqual(reply.acl_index, 0)

        self.run_traffic(self.EXACT_MAC, self.EXACT_IP,
                         self.BRIDGED, self.IS_IP6, 9, True)


class TestMACIP(MethodHolder):
    """MACIP Tests"""

    def test_acl_1_2(self):
        """ MACIP ACL with 2 entries
        """

        self.run_test_acls(self.EXACT_MAC, self.WILD_IP, 1, [2])

    def test_acl_1_5(self):
        """ MACIP ACL with 5 entries
        """

        self.run_test_acls(self.EXACT_MAC, self.SUBNET_IP, 1, [5])

    def test_acl_1_10(self):
        """ MACIP ACL with 10 entries
        """

        self.run_test_acls(self.EXACT_MAC, self.EXACT_IP, 1, [10])

    def test_acl_1_20(self):
        """ MACIP ACL with 20 entries
        """

        self.run_test_acls(self.OUI_MAC, self.WILD_IP, 1, [20])

    def test_acl_1_50(self):
        """ MACIP ACL with 50 entries
        """

        self.run_test_acls(self.OUI_MAC, self.SUBNET_IP, 1, [50])

    def test_acl_1_100(self):
        """ MACIP ACL with 100 entries
        """

        self.run_test_acls(self.OUI_MAC, self.EXACT_IP, 1, [100])

    def test_acl_2_X(self):
        """ MACIP 2 ACLs each with 100+ entries
        """

        self.run_test_acls(self.OUI_MAC, self.SUBNET_IP, 2, [100, 200])

    def test_acl_10_X(self):
        """ MACIP 10 ACLs each with 100+ entries
        """

        self.run_test_acls(self.EXACT_MAC, self.EXACT_IP, 10,
                           [100, 120, 140, 160, 180, 200, 210, 220, 230, 240])

    def test_acl_10_X_traffic_ip4(self):
        """ MACIP 10 ACLs each with 100+ entries with IP4 traffic
        """

        self.run_test_acls(self.EXACT_MAC, self.EXACT_IP, 10,
                           [100, 120, 140, 160, 180, 200, 210, 220, 230, 240],
                           self.BRIDGED, self.IS_IP4)

    def test_acl_10_X_traffic_ip6(self):
        """ MACIP 10 ACLs each with 100+ entries with IP6 traffic
        """

        self.run_test_acls(self.EXACT_MAC, self.EXACT_IP, 10,
                           [100, 120, 140, 160, 180, 200, 210, 220, 230, 240],
                           self.BRIDGED, self.IS_IP6)

    def test_acl_replace(self):
        """ MACIP replace ACL
        """

        r1 = self.create_rules(acl_count=3, rules_count=[2, 2, 2])
        r2 = self.create_rules(mac_type=self.OUI_MAC, ip_type=self.SUBNET_IP)
        self.apply_macip_rules(r1)

        acls_before = self.macip_acl_dump_debug()

        # replace acls #2, #3 with new
        reply = self.vapi.macip_acl_add_replace(r2[0], 2)
        self.assertEqual(reply.retval, 0)
        self.assertEqual(reply.acl_index, 2)
        reply = self.vapi.macip_acl_add_replace(r2[1], 3)
        self.assertEqual(reply.retval, 0)
        self.assertEqual(reply.acl_index, 3)

        acls_after = self.macip_acl_dump_debug()

        # verify changes
        self.assertEqual(len(acls_before), len(acls_after))
        for acl1, acl2 in zip(
                acls_before[:2]+acls_before[4:],
                acls_after[:2]+acls_after[4:]):
            self.assertEqual(len(acl1), len(acl2))

            self.assertEqual(len(acl1.r), len(acl2.r))
            for r1, r2 in zip(acl1.r, acl2.r):
                self.assertEqual(len(acl1.r), len(acl2.r))
                self.assertEqual(acl1.r, acl2.r)
        for acl1, acl2 in zip(
                acls_before[2:4],
                acls_after[2:4]):
            self.assertEqual(len(acl1), len(acl2))

            self.assertNotEqual(len(acl1.r), len(acl2.r))
            for r1, r2 in zip(acl1.r, acl2.r):
                self.assertNotEqual(len(acl1.r), len(acl2.r))
                self.assertNotEqual(acl1.r, acl2.r)

    def test_delete_intf(self):
        """ MACIP ACL delete intf with acl
        """

        intf_count = len(self.interfaces)+1
        intf = []
        self.apply_macip_rules(self.create_rules(acl_count=3,
                                                 rules_count=[3, 5, 4]))

        intf.append(VppLoInterface(self, 0))
        intf.append(VppLoInterface(self, 1))

        sw_if_index0 = intf[0].sw_if_index
        self.vapi.macip_acl_interface_add_del(sw_if_index0, 1)

        reply = self.vapi.macip_acl_interface_get()
        self.assertEqual(reply.count, intf_count+1)
        self.assertEqual(reply.acls[sw_if_index0], 1)

        sw_if_index1 = intf[1].sw_if_index
        self.vapi.macip_acl_interface_add_del(sw_if_index1, 0)

        reply = self.vapi.macip_acl_interface_get()
        self.assertEqual(reply.count, intf_count+2)
        self.assertEqual(reply.acls[sw_if_index1], 0)

        intf[0].remove_vpp_config()
        reply = self.vapi.macip_acl_interface_get()
        self.assertEqual(reply.count, intf_count+2)
        self.assertEqual(reply.acls[sw_if_index0], 4294967295)
        self.assertEqual(reply.acls[sw_if_index1], 0)

        intf.append(VppLoInterface(self, 2))
        intf.append(VppLoInterface(self, 3))
        sw_if_index2 = intf[2].sw_if_index
        sw_if_index3 = intf[3].sw_if_index
        self.vapi.macip_acl_interface_add_del(sw_if_index2, 1)
        self.vapi.macip_acl_interface_add_del(sw_if_index3, 1)

        reply = self.vapi.macip_acl_interface_get()
        self.assertEqual(reply.count, intf_count+3)
        self.assertEqual(reply.acls[sw_if_index1], 0)
        self.assertEqual(reply.acls[sw_if_index2], 1)
        self.assertEqual(reply.acls[sw_if_index3], 1)

        intf[2].remove_vpp_config()
        intf[1].remove_vpp_config()

        reply = self.vapi.macip_acl_interface_get()
        self.assertEqual(reply.count, intf_count+3)
        self.assertEqual(reply.acls[sw_if_index0], 4294967295)
        self.assertEqual(reply.acls[sw_if_index1], 4294967295)
        self.assertEqual(reply.acls[sw_if_index2], 4294967295)
        self.assertEqual(reply.acls[sw_if_index3], 1)

        intf[3].remove_vpp_config()
        reply = self.vapi.macip_acl_interface_get()

        self.assertEqual(len([x for x in reply.acls if x != 4294967295]), 0)


class TestACL_dot1q_bridged(MethodHolder):
    """ACL on dot1q bridged subinterfaces Tests"""

    def test_acl_bridged_ip4_subif_dot1q(self):
        """ IP4 ACL SubIf Dot1Q bridged traffic"""
        self.run_traffic(self.EXACT_MAC, self.EXACT_IP, self.BRIDGED,
                         self.IS_IP4, 9, tags=self.DOT1Q, isMACIP=False)

    def test_acl_bridged_ip6_subif_dot1q(self):
        """ IP6 ACL SubIf Dot1Q bridged traffic"""
        self.run_traffic(self.EXACT_MAC, self.EXACT_IP, self.BRIDGED,
                         self.IS_IP6, 9, tags=self.DOT1Q, isMACIP=False)


class TestACL_dot1ad_bridged(MethodHolder):
    """ACL on dot1ad bridged subinterfaces Tests"""

    def test_acl_bridged_ip4_subif_dot1ad(self):
        """ IP4 ACL SubIf Dot1AD bridged traffic"""
        self.run_traffic(self.EXACT_MAC, self.EXACT_IP, self.BRIDGED,
                         self.IS_IP4, 9, tags=self.DOT1AD, isMACIP=False)

    def test_acl_bridged_ip6_subif_dot1ad(self):
        """ IP6 ACL SubIf Dot1AD bridged traffic"""
        self.run_traffic(self.EXACT_MAC, self.EXACT_IP, self.BRIDGED,
                         self.IS_IP6, 9, tags=self.DOT1AD, isMACIP=False)


class TestACL_dot1q_routed(MethodHolder):
    """ACL on dot1q routed subinterfaces Tests"""

    def test_acl_routed_ip4_subif_dot1q(self):
        """ IP4 ACL SubIf Dot1Q routed traffic"""
        self.run_traffic(self.EXACT_MAC, self.EXACT_IP, self.ROUTED,
                         self.IS_IP4, 9, tags=self.DOT1Q, isMACIP=False)

    def test_acl_routed_ip6_subif_dot1q(self):
        """ IP6 ACL SubIf Dot1Q routed traffic"""
        self.run_traffic(self.EXACT_MAC, self.EXACT_IP, self.ROUTED,
                         self.IS_IP6, 9, tags=self.DOT1Q, isMACIP=False)

    def test_acl_routed_ip4_subif_dot1q_deny_by_tags(self):
        """ IP4 ACL SubIf wrong tags Dot1Q routed traffic"""
        self.run_traffic(self.EXACT_MAC, self.EXACT_IP, self.ROUTED,
                         self.IS_IP4, 9, True, tags=self.DOT1Q, isMACIP=False,
                         permit_tags=self.DENY_TAGS)

    def test_acl_routed_ip6_subif_dot1q_deny_by_tags(self):
        """ IP6 ACL SubIf wrong tags Dot1Q routed traffic"""
        self.run_traffic(self.EXACT_MAC, self.EXACT_IP, self.ROUTED,
                         self.IS_IP6, 9, True, tags=self.DOT1Q, isMACIP=False,
                         permit_tags=self.DENY_TAGS)


class TestACL_dot1ad_routed(MethodHolder):
    """ACL on dot1ad routed subinterfaces Tests"""

    def test_acl_routed_ip6_subif_dot1ad(self):
        """ IP6 ACL SubIf Dot1AD routed traffic"""
        self.run_traffic(self.EXACT_MAC, self.EXACT_IP, self.ROUTED,
                         self.IS_IP6, 9, tags=self.DOT1AD, isMACIP=False)

    def test_acl_routed_ip4_subif_dot1ad(self):
        """ IP4 ACL SubIf Dot1AD routed traffic"""
        self.run_traffic(self.EXACT_MAC, self.EXACT_IP, self.ROUTED,
                         self.IS_IP4, 9, tags=self.DOT1AD, isMACIP=False)

    def test_acl_routed_ip6_subif_dot1ad_deny_by_tags(self):
        """ IP6 ACL SubIf wrong tags Dot1AD routed traffic"""
        self.run_traffic(self.EXACT_MAC, self.EXACT_IP, self.ROUTED,
                         self.IS_IP6, 9, True, tags=self.DOT1AD, isMACIP=False,
                         permit_tags=self.DENY_TAGS)

    def test_acl_routed_ip4_subif_dot1ad_deny_by_tags(self):
        """ IP4 ACL SubIf wrong tags Dot1AD routed traffic"""
        self.run_traffic(self.EXACT_MAC, self.EXACT_IP, self.ROUTED,
                         self.IS_IP4, 9, True, tags=self.DOT1AD, isMACIP=False,
                         permit_tags=self.DENY_TAGS)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
