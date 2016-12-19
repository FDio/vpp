#!/usr/bin/env python3

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

import ipaddress
import argparse
import sys

# map add domain ip4-pfx <pfx> ip6-pfx ::/0 ip6-src <ip6-src> ea-bits-len 0 psid-offset 6 psid-len 6
# map add rule index <0> psid <psid> ip6-dst <ip6-dst>

def_ip4_pfx = '192.0.2.0/24'
def_ip6_pfx = '2001:db8::/32'
def_ip6_src = '2001:db8::1'
def_psid_offset = 6
def_psid_len = 6
def_ea_bits_len = 0

parser = argparse.ArgumentParser(description='MAP VPP configuration generator')
parser.add_argument('-t', action="store", dest="mapmode")
parser.add_argument('-f', action="store", dest="format", default="vpp")
parser.add_argument('--ip4-prefix', action="store", dest="ip4_pfx", default=def_ip4_pfx)
parser.add_argument('--ip6-prefix', action="store", dest="ip6_pfx", default=def_ip6_pfx)
parser.add_argument('--ip6-src', action="store", dest="ip6_src", default=def_ip6_src)
parser.add_argument('--psid-len', action="store", dest="psid_len", default=def_psid_len)
parser.add_argument('--psid-offset', action="store", dest="psid_offset", default=def_psid_offset)
parser.add_argument('--ea-bits-len', action="store", dest="ea_bits_len", default=def_ea_bits_len)
args = parser.parse_args()

#
# Print domain
#
def domain_print(i, ip4_pfx, ip6_pfx, ip6_src, eabits_len, psid_offset, psid_len):
    if format == 'vpp':
        print("map add domain ip4-pfx " + ip4_pfx + " ip6-pfx", ip6_pfx, "ip6-src " + ip6_src +
              " ea-bits-len", eabits_len, "psid-offset", psid_offset, "psid-len", psid_len)
    if format == 'confd':
        print("vpp softwire softwire-instances softwire-instance", i, "br-ipv6 " + ip6_src +
              " ipv6-prefix " + ip6_pfx + " ipv4-prefix " + ip4_pfx +
              " ea-bits-len", eabits_len, "psid-offset", psid_offset, "psid-len", psid_len)
    if format == 'xml':
        print("<softwire-instance>")
        print("<id>", i, "</id>");
        print("  <br-ipv6>" + ip6_src + "</br-ipv6>")
        print("  <ipv6-prefix>" + ip6_pfx + "</ipv6-prefix>")
        print("  <ipv4-prefix>" + ip4_pfx + "</ipv4-prefix>")
        print("  <ea-len>", eabits_len, "</ea-len>")
        print("  <psid-len>", psid_len, "</psid-len>")
        print("  <psid-offset>", psid_offset, "</psid-offset>")

def domain_print_end():
    if format == 'xml':
        print("</softwire-instance>")

def rule_print(i, psid, dst):
    if format == 'vpp':
        print("map add rule index", i, "psid", psid, "ip6-dst", dst)
    if format == 'confd':
        print("binding", psid, "ipv6-addr", dst)
    if format == 'xml':
        print("  <binding>")
        print("    <psid>", psid, "</psid>")
        print("    <ipv6-addr>", dst, "</ipv6-addr>")
        print("  </binding>")

#
# Algorithmic mapping Shared IPv4 address
#
def algo(ip4_pfx_str, ip6_pfx_str, ip6_src_str, ea_bits_len, psid_offset, psid_len, ip6_src_ecmp = False):
    domain_print(0, ip4_pfx_str, ip6_pfx_str, ip6_src_str, ea_bits_len, psid_offset, psid_len)
    domain_print_end()

#
# 1:1 Full IPv4 address
#
def lw46(ip4_pfx_str, ip6_pfx_str, ip6_src_str, ea_bits_len, psid_offset, psid_len, ip6_src_ecmp = False):
    ip4_pfx = ipaddress.ip_network(ip4_pfx_str)
    ip6_src = ipaddress.ip_address(ip6_src_str)
    ip6_dst = ipaddress.ip_network(ip6_pfx_str)
    psid_len = 0
    mod = ip4_pfx.num_addresses / 1024

    for i in range(ip4_pfx.num_addresses):
        domain_print(i, str(ip4_pfx[i]) + "/32", str(ip6_dst[i]) + "/128", str(ip6_src), 0, 0, 0)
        domain_print_end()
        if ip6_src_ecmp and not i % mod:
            ip6_src = ip6_src + 1

#
# 1:1 Shared IPv4 address, shared BR (16) VPP CLI
#
def lw46_shared(ip4_pfx_str, ip6_pfx_str, ip6_src_str, ea_bits_len, psid_offset, psid_len, ip6_src_ecmp = False):
    ip4_pfx = ipaddress.ip_network(ip4_pfx_str)
    ip6_src = ipaddress.ip_address(ip6_src_str)
    ip6_dst = ipaddress.ip_network(ip6_pfx_str)
    mod = ip4_pfx.num_addresses / 1024

    for i in range(ip4_pfx.num_addresses):
        domain_print(i, str(ip4_pfx[i]) + "/32", "::/0", str(ip6_src), 0, 0, psid_len)
        for psid in range(0x1 << int(psid_len)):
            rule_print(i, psid, str(ip6_dst[(i * (0x1<<int(psid_len))) + psid]))
        domain_print_end()
        if ip6_src_ecmp and not i % mod:
            ip6_src = ip6_src + 1


#
# 1:1 Shared IPv4 address, shared BR
#
def lw46_shared_b(ip4_pfx_str, ip6_pfx_str, ip6_src_str, ea_bits_len, psid_offset, psid_len, ip6_src_ecmp = False):
    ip4_pfx = ipaddress.ip_network(ip4_pfx_str)
    ip6_src = ipaddress.ip_address(ip6_src_str)
    ip6_dst = list(ipaddress.ip_network(ip6_pfx_str).subnets(new_prefix=56))
    mod = ip4_pfx.num_addresses / 1024

    for i in range(ip4_pfx.num_addresses):
        domain_print(i, str(ip4_pfx[i]) + "/32", "::/0", str(ip6_src), 0, 0, psid_len)
        for psid in range(0x1 << psid_len):
            enduserprefix = list(ip6_dst.pop(0).subnets(new_prefix=64))[255-1]
            rule_print(i, psid, enduserprefix[(i * (0x1<<psid_len)) + psid])
        domain_print_end()
        if ip6_src_ecmp and not i % mod:
            ip6_src = ip6_src + 1


def xml_header_print():
    print('''
<?xml version="1.0" encoding="UTF-8"?>
    <hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
    </capabilities>
    </hello>
]]>]]>

<?xml version="1.0" encoding="UTF-8"?>
    <rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"  message-id="1">
    <edit-config>
    <target>
    <candidate/>
    </target>
    <config>

    <vpp xmlns="http://www.cisco.com/yang/cisco-vpp">
 <softwire>
 <softwire-instances>

    ''')

def xml_footer_print():
    print('''
</softwire-instances>
</softwire>
</vpp>
    </config>
    </edit-config>
    </rpc>

]]>]]>

<?xml version="1.0" encoding="UTF-8"?>
    <rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="2">
    <close-session/>
    </rpc>

]]>]]>
    ''')


format = args.format
if format == 'xml':
    xml_header_print()
globals()[args.mapmode](args.ip4_pfx, args.ip6_pfx, args.ip6_src, args.ea_bits_len, args.psid_offset, args.psid_len)
if format == 'xml':
    xml_footer_print()
