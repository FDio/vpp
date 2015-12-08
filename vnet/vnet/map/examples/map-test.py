#!/usr/bin/env python
# Copyright (c) 2015 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys, time
from scapy.all import *

import mapalgs


ifname = "vpp-tap"

loc_v4_mac = "aa:aa:aa:aa:aa:a4"
loc_v6_mac = "aa:aa:aa:aa:aa:a6"
vpp_mac = "aa:aa:aa:aa:00:00"

map_t = 1

fragsize = 0
map_mtu = 200

def mac_to_vppmac(mac):
    mac = mac.replace(':', '')
    return mac[0:4]+"."+mac[4:8]+"."+mac[8:12]


map = mapalgs.MapCalc( rulev6 = 'bbbb::/32',
                     rulev4 = '20.0.0.0/24',
                     ratio = 256);

dmr = mapalgs.DmrCalc('cccc:bbbb::/96')


ICMP_TYPES_CODES = {
    0: 0,
    3: 15,
    4: 0,
    5: 3,
    6: 0,
    8: 0,
    9: 0,
    10: 0,
    11: 1,
    12: 2,
    13: 0,
    14: 0,
    15: 0,
    16: 0,
    17: 0,
    18: 0
}

ICMP6_TYPES_CODES = {
    1: 7,
    2: 0,
    3: 1,
    4: 3,
}

def net_conf():
    c = ""
    c += "tap connect "+ifname+" hwaddr "+mac_to_vppmac(vpp_mac)+" \n"
    c += "set int state tap-0 up \n"
    c += "set ip6 neighbor tap-0 2001:f00d::1 "+mac_to_vppmac(loc_v6_mac)+" \n"
    c += "set ip  arp      tap-0 10.0.0.1     "+mac_to_vppmac(loc_v4_mac)+" \n"
    c += "ip route add ::/0  via 2001:f00d::1 tap-0 \n"
    c += "ip route add 0.0.0.0/0 via 10.0.0.1 tap-0 \n"
    return c

def conf():
    c = net_conf()
    c += "map add domain ip4-pfx 20.0.0.0/24 ip6-pfx bbbb::/32 ea-bits-len 16 psid-offset 6 psid-len 8"
    if map_mtu != 0:
        c += " mtu "+str(map_mtu)
    if map_t:
        c += " ip6-src cccc:bbbb::/96 map-t"
    else:
        c += " ip6-src cccc:bbbb::ffff"

    c += "\n"
    return c

def send_packet(ip_header, ip_content):
    print("Send packet")
    if fragsize != 0:
        if ip_header.version == 4:
            frags = fragment(ip_header/ip_content, fragsize=fragsize)
            for f in frags:
                print("Fragmented IPv4 packet")
                sendp(Ether(dst=vpp_mac, src=loc_v4_mac)/f, iface=ifname)
        elif ip_header.version == 6:
            frags = fragment6(ip_header/IPv6ExtHdrFragment()/ip_content, fragsize)
            for f in frags:
                print("Fragmented IPv6 packet")
                sendp(Ether(dst=vpp_mac, src=loc_v6_mac)/f, iface=ifname)
    else:
        sendp(Ether(dst=vpp_mac)/ip_header/ip_content, iface=ifname)

def send_packet_frag_inner(packet, inner_header, inner_content):
    print("Send packet with inner ICMP packet")
    if fragsize != 0:
        if packet.version == 4:
            frags = fragment(inner_header/inner_content, fragsize=fragsize)
            for f in frags:
                print("Fragmented IPv4 inner packet")
                sendp(Ether(dst=vpp_mac, src=loc_v4_mac)/packet/f, iface=ifname)
        elif packet.version == 6:
            frags = fragment6(inner_header/IPv6ExtHdrFragment()/inner_content, fragsize)
            for f in frags:
                print("Fragmented IPv6 inner packet")
                sendp(Ether(dst=vpp_mac, src=loc_v6_mac)/packet/f, iface=ifname)
    else:
        sendp(Ether(dst=vpp_mac)/packet/inner_header/inner_content, iface=ifname)


def sendv6udp(src, dst, port):
    psid = map.gen_psid(port)
    ceaddr = str(map.get_mapce_addr(src, psid))
    dst = str(dmr.embed_6052addr(dst))
    send_packet(IPv6(dst=dst, src=ceaddr), UDP(sport=port)/('X'*900))

def sendv6tcp(src, dst, port):
    psid = map.gen_psid(port)
    ceaddr = str(map.get_mapce_addr(src, psid))
    dst = str(dmr.embed_6052addr(dst))
    send_packet(IPv6(dst=dst, src=ceaddr), TCP(sport=port)/('X'*900))

def sendv4udp(src, dst, port):
    send_packet(IP(dst=dst, src=src), UDP(dport=port)/('X'*900))

def sendv4tcp(src, dst, port):
    send_packet(IP(dst=dst, src=src), TCP(dport=port)/('X'*900))

def sendv6ping(src, dst, id):
    psid = map.gen_psid(id)
    ceaddr = str(map.get_mapce_addr(src, psid))
    dst = str(dmr.embed_6052addr(dst))
    send_packet(IPv6(dst=dst, src=ceaddr), ICMPv6EchoRequest(id=id, data='A'*500))
    send_packet(IPv6(dst=dst, src=ceaddr), ICMPv6EchoReply(id=id, data='A'*500))

def sendv4ping(src, dst, id):
    send_packet(IP(dst=dst, src=src), ICMP(id=id, type=0)/('X'*500))
    send_packet(IP(dst=dst, src=src), ICMP(id=id, type=8)/('X'*500))

def sendv4icmperr(src, dst, type, code, port, inner_src, inner_dst, payload_length):
    inner = IP(dst=inner_dst, src=inner_src)/TCP(sport=port, dport=8888)/('X'*payload_length)
    send_packet_frag_inner(IP(dst=dst, src=src)/ICMP(type=type, code=code), IP(dst=inner_dst, src=inner_src), TCP(sport=port, dport=8888)/('X'*payload_length))
    #send_packet(IP(dst=dst, src=src)/ICMP(type=type, code=code)/inner)

def sendv6icmperr(src, dst, type, code, port, payload_length):
    psid = map.gen_psid(port)
    src = str(map.get_mapce_addr(src, psid))
    dst = str(dmr.embed_6052addr(dst))
    inner_header = IPv6(dst=src, src=dst)
    inner_content = TCP(sport=8888, dport=port)/('X'*payload_length)
    send_packet_frag_inner(IPv6(dst=dst, src=src)/ICMPv6DestUnreach(type=type, code=code), inner_header, inner_content)
    #send_packet(IPv6(dst=dst, src=src)/ICMPv6DestUnreach(type=type, code=code)/inner)

def sendv4icmp_errors(src, dst, port, inner_src, inner_dst, payload_length):
    for type in ICMP_TYPES_CODES:
        for code in range(0, ICMP_TYPES_CODES[type] + 1):
            sendv4icmperr(src, dst, type, code, port, inner_src, inner_dst, payload_length)
        #sendv4icmperr(src, dst, type, ICMP_TYPES_CODES[type] + 2, port, inner_src, inner_dst, payload_length)
        #sendv4icmperr(src, dst, type, 255, port, inner_src, inner_dst, payload_length)
    #sendv4icmperr(src, dst, 1, 0, port, inner_src, inner_dst, payload_length)
    #sendv4icmperr(src, dst, 2, 10, port, inner_src, inner_dst, payload_length)
    #sendv4icmperr(src, dst, 255, 255, port, inner_src, inner_dst, payload_length)

    #TODO: Check wrong paramater with different pointer values

def sendv6icmp_errors(src, dst, port, payload_length):
    for type in ICMP6_TYPES_CODES:
        for code in range(0, ICMP6_TYPES_CODES[type] + 1):
            sendv6icmperr(src, dst, type, code, port, payload_length)
        #sendv6icmperr(src, dst, type, ICMP6_TYPES_CODES[type] + 2, port, payload_length)
        #sendv6icmperr(src, dst, type, 255, port, payload_length)


def traffic():
    delay = 2.0
    while 1:
        #sendp(Ether(dst="bb:bb:bb:bb:bb:b4")/IP(dst="20.0.0.1")/UDP(chksum=0)/('X'*900), iface="vpp-tapv4")
        #sendp(Ether(dst="bb:bb:bb:bb:bb:b6")/IPv6(dst="cccc:bbbb::a000:0001")/ICMPv6EchoRequest()/('X'*900), iface="vpp-tapv6")
        #sendp(Ether(dst="bb:bb:bb:bb:bb:b6")/IPv6(dst="cccc:bbbb::a000:0001")/UDP()/('X'*900), iface="vpp-tapv6")
        sendv6udp("20.0.0.1", "10.0.0.1", 12001)
        sendv6tcp("20.0.0.1", "10.0.0.1", 12002)
        sendv4udp("10.0.0.1", "20.0.0.1", 12003)
        sendv4tcp("10.0.0.1", "20.0.0.1", 12004)
        sendv6ping("20.0.0.1", "10.0.0.1", 12005)
        sendv4ping("10.0.0.1", "20.0.0.1", 12006)
        sendv4icmp_errors("10.0.0.1", "20.0.0.1", 12006, "20.0.0.1", "10.0.0.1", 500)
        sendv4icmp_errors("10.0.0.1", "20.0.0.1", 12006, "20.0.0.1", "10.0.0.1", 1500)
        sendv6icmp_errors("20.0.0.1", "10.0.0.1", 12006, 500)
        time.sleep(delay)
        delay *= 0.9

if len(sys.argv) <= 1:
    print("Usage: conf|traffic")
    exit(1)

if sys.argv[1] == "conf":
    print(conf())
elif sys.argv[1] == "traffic":
    traffic()