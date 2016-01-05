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
def_ea_bits_len = 14


parser = argparse.ArgumentParser(description='MAP VPP configuration generator')
parser.add_argument('-t', action="store", dest="mapmode")
parser.add_argument('--ip4-prefix', action="store", dest="ip4_pfx", default=def_ip4_pfx)
parser.add_argument('--ip6-prefix', action="store", dest="ip6_pfx", default=def_ip6_pfx)
parser.add_argument('--ip6-src', action="store", dest="ip6_src", default=def_ip6_src)
parser.add_argument('--psid-len', action="store", dest="psid_len", default=def_psid_len)
parser.add_argument('--psid-offset', action="store", dest="psid_offset", default=def_psid_offset)
parser.add_argument('--ea-bits-len', action="store", dest="ea_bits_len", default=def_ea_bits_len)
args = parser.parse_args()


#
# Algorithmic mapping Shared IPv4 address
#
def algo(ip4_pfx_str, ip6_pfx_str, ip6_src_str, psid_len, ea_bits_len, ip6_src_ecmp = False):
    print("map add domain ip4-pfx " + ip4_pfx_str + " ip6-pfx " + ip6_pfx_str + " ip6-src " + ip6_src_str +
          " ea-bits-len " + str(ea_bits_len) + " psid-offset 6 psid-len " + str(psid_len))

#
# 1:1 Full IPv4 address
#
def lw46(ip4_pfx_str, ip6_pfx_str, ip6_src_str, psid_len, ea_bits_len, ip6_src_ecmp = False):
    ip4_pfx = ipaddress.ip_network(ip4_pfx_str)
    ip6_src = ipaddress.ip_address(ip6_src_str)
    ip6_dst = ipaddress.ip_network(ip6_pfx_str)
    psid_len = 0
    mod = ip4_pfx.num_addresses / 1024

    for i in range(ip4_pfx.num_addresses):
        print("map add domain ip4-pfx " + str(ip4_pfx[i]) +  "/32 ip6-pfx " + str(ip6_dst[i]) + "/128 ip6-src",
              ip6_src, "ea-bits-len 0 psid-offset 0 psid-len 0")
        if ip6_src_ecmp and not i % mod:
            ip6_src = ip6_src + 1

#
# 1:1 Shared IPv4 address, shared BR (16) VPP CLI
#
def lw46_shared(ip4_pfx_str, ip6_pfx_str, ip6_src_str, psid_len, ea_bits_len, ip6_src_ecmp = False):
    ip4_pfx = ipaddress.ip_network(ip4_pfx_str)
    ip6_src = ipaddress.ip_address(ip6_src_str)
    ip6_dst = ipaddress.ip_network(ip6_pfx_str)

    mod = ip4_pfx.num_addresses / 1024

    for i in range(ip4_pfx.num_addresses):
        print("map add domain ip4-pfx " + str(ip4_pfx[i]) +  "/32 ip6-pfx ::/0 ip6-src " + str(ip6_src) +
              " ea-bits-len 0 psid-offset 0 psid-len", psid_len)
        for psid in range(0x1 << psid_len):
            print("map add rule index", i, "psid", psid, "ip6-dst", ip6_dst[(i * (0x1<<psid_len)) + psid])
        if ip6_src_ecmp and not i % mod:
            ip6_src = ip6_src + 1

#
# 1:1 Shared IPv4 address, shared BR
#
def lw46_shared_b(ip4_pfx_str, ip6_pfx_str, ip6_src_str, psid_len, ea_bits_len, ip6_src_ecmp = False):
    ip4_pfx = ipaddress.ip_network(ip4_pfx_str)
    ip6_src = ipaddress.ip_address(ip6_src_str)
    ip6_dst = list(ipaddress.ip_network(ip6_pfx_str).subnets(new_prefix=56))
    psid_len = 6

    for i in range(ip4_pfx.num_addresses):
        if not i % 64:
            ip6_src = ip6_src + 1
        print("map add domain ip4-pfx " + str(ip4_pfx[i]) +  "/32 ip6-pfx ::/0 ip6-src " + str(ip6_src) +
              " ea-bits-len 0 psid-offset 6 psid-len", psid_len)
        for psid in range(0x1 << psid_len):
            enduserprefix = list(ip6_dst.pop(0).subnets(new_prefix=64))[255-1]
            print("map add rule index", i, "psid", psid, "ip6-dst", enduserprefix[(i * (0x1<<psid_len)) + psid])

globals()[args.mapmode](args.ip4_pfx, args.ip6_pfx, args.ip6_src, args.psid_len, args.psid_offset,
                        args.ea_bits_len)
