#!/usr/bin/env python3.4

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

parser = argparse.ArgumentParser(description='MAP VPP configuration generator')
parser.add_argument('-t', action="store", dest="mapmode")
args = parser.parse_args()

#
# 1:1 Shared IPv4 address, shared BR, Terastream
#
def terastream():
    ip4_pfx = ipaddress.ip_network('20.0.0.0/22')
    ip6_dst = ipaddress.ip_network('bbbb::/32')
    psid_len = 6
    ip6_src = ipaddress.ip_address('cccc:bbbb::')
    for i in range(ip4_pfx.num_addresses):
        if not i % 64:
            ip6_src = ip6_src + 1
        print("map add domain ip4-pfx " + str(ip4_pfx[i]) +  "/32 ip6-pfx ::/0 ip6-src " + str(ip6_src) +
              " ea-bits-len 0 psid-offset 0 psid-len", psid_len)
        for psid in range(0x1 << psid_len):
            print("map add rule index", i, "psid", psid, "ip6-dst", ip6_dst[(i * (0x1<<psid_len)) + psid])

#
# 1:1 Shared IPv4 address, shared BR, OTE
#
def oteshared11():
    ip4_pfx = ipaddress.ip_network('2.84.63.0/24')
    dst = list(ipaddress.ip_network('2a02:580:8c00::/40').subnets(new_prefix=56))
    psid_len = 6
    ip6_src = ipaddress.ip_address('2a02::')
    for i in range(ip4_pfx.num_addresses):
        if not i % 64:
            ip6_src = ip6_src + 1
        print("map add domain ip4-pfx " + str(ip4_pfx[i]) +  "/32 ip6-pfx ::/0 ip6-src " + str(ip6_src) +
              " ea-bits-len 0 psid-offset 6 psid-len", psid_len)
        for psid in range(0x1 << psid_len):
            enduserprefix = list(dst.pop(0).subnets(new_prefix=64))[255-1]
            print("map add rule index", i, "psid", psid, "ip6-dst", enduserprefix[(i * (0x1<<psid_len)) + psid])


#
# 1:1 Shared IPv4 address, shared BR, Terastream
#
def confdterastream():
    ip4_pfx = ipaddress.ip_network('20.0.0.0/22')
    ip6_dst = ipaddress.ip_network('bbbb::/32')
    psid_len = 6
    ip6_src = ipaddress.ip_address('cccc:bbbb::')
    for i in range(ip4_pfx.num_addresses):
        if not i % 64:
            ip6_src = ip6_src + 1
        print("vpp softwire softwire-instances softwire-instance", i, "br-ipv6 " + str(ip6_src) + " ipv6-prefix ::/0" + " ipv4-prefix " + str(ip4_pfx[i]) +
              "/32 ea-len 0 psid-offset 6 psid-len", psid_len)
#        print("vpp softwire softwire-instances softwire-instance", i, "ipv4-pfx " + str(ip4_pfx[i]) +  "/32 ipv6-pfx ::/0 br-ipv6 " + str(ip6_src) +
#              " ea-len 0 psid-offset 6 psid-len", psid_len)
        for psid in range(0x1 << psid_len):
            print("binding", psid, "ipv6-addr", ip6_dst[(i * (0x1<<psid_len)) + psid])

def shared11br_yang():
    ip4_pfx = ipaddress.ip_network('20.0.0.0/16')
    ip6_dst = ipaddress.ip_network('bbbb::/32')
    psid_len = 6
    for i in range(ip4_pfx.num_addresses):
        print("vpp softwire softwire-instances softwire-instance " + str(i) + " ipv4-prefix " + str(ip4_pfx[i]) + "/32 " +
                "ipv6-prefix ::/0 ea-len 0 psid-offset 6 tunnel-mtu 1234 psid-len", psid_len)
        #print("map add domain ip4-pfx " + str(ip4_pfx[i]) +  "/32 ip6-pfx ::/0 ip6-shared-src cccc:bbbb::1",
        #      "ea-bits-len 0 psid-offset 6 psid-len", psid_len)
        for psid in range(0x1 << psid_len):
            # print("map add rule index", i, "psid", psid, "ip6-dst", ip6_dst[(i * (0x1<<psid_len)) + psid])
            print("binding", psid, "ipv6-addr", ip6_dst[(i * (0x1<<psid_len)) + psid])

def shared11br_xml():
    ip4_pfx = ipaddress.ip_network('20.0.0.0/32')
    ip6_dst = ipaddress.ip_network('bbbb::/32')
    ip6_src = ipaddress.ip_address('cccc:bbbb::')
    psid_len = 6
    print('<vpp xmlns="http://www.cisco.com/yang/cisco-vpp"><softwire><softwire-instances>');
    count = 1024;
    for i in range(ip4_pfx.num_addresses):
        if not i % 64:
            ip6_src = ip6_src + 1
        if count == 0:
            break;
        count = count - 1;
        print('<softwire-instance>')
        print('  <id>'+ str(i)+ '</id>')
        print('  <ipv4-prefix>'+ str(ip4_pfx[i])+ '/32</ipv4-prefix>')
        print('  <ipv6-prefix>::/0</ipv6-prefix>')
        print('  <ea-len>0</ea-len>')
        print('  <psid-offset>0</psid-offset>')
        print('  <psid-len>'+ str(psid_len) + '</psid-len>')
        for psid in range(0x1 << psid_len):
            print('  <binding>')
            print('    <psid>', psid, '</psid>')
            print('    <ipv6-addr>'+ str(ip6_dst[(i * (0x1<<psid_len)) + psid]) + '</ipv6-addr>')
            print('  </binding>')
        print('</softwire-instance>')
    print('</softwire-instances></softwire>')
    print('</vpp>')

#
# 1:1 Shared IPv4 address, shared BR
#
def shared11br():
    ip4_pfx = ipaddress.ip_network('20.0.0.0/16')
    ip6_dst = ipaddress.ip_network('bbbb::/32')
    psid_len = 6
    for i in range(ip4_pfx.num_addresses):
        print("map add domain ip4-pfx " + str(ip4_pfx[i]) +  "/32 ip6-pfx ::/0 ip6-shared-src cccc:bbbb::1",
              "ea-bits-len 0 psid-offset 6 psid-len", psid_len)
        for psid in range(0x1 << psid_len):
            print("map add rule index", i, "psid", psid, "ip6-dst", ip6_dst[(i * (0x1<<psid_len)) + psid])

#
# 1:1 Shared IPv4 address, shared BR
#
def shared11br():
    ip4_pfx = ipaddress.ip_network('20.0.0.0/16')
    ip6_dst = ipaddress.ip_network('bbbb::/32')
    psid_len = 6
    for i in range(ip4_pfx.num_addresses):
        print("map add domain ip4-pfx " + str(ip4_pfx[i]) +  "/32 ip6-pfx ::/0 ip6-shared-src cccc:bbbb::1",
              "ea-bits-len 0 psid-offset 6 psid-len", psid_len)
        for psid in range(0x1 << psid_len):
            print("map add rule index", i, "psid", psid, "ip6-dst", ip6_dst[(i * (0x1<<psid_len)) + psid])


#
# 1:1 Shared IPv4 address
#
def shared11():
    ip4_pfx = ipaddress.ip_network('20.0.0.0/16')
    ip6_src = ipaddress.ip_network('cccc:bbbb::/64')
    ip6_dst = ipaddress.ip_network('bbbb::/32')
    psid_len = 6
    for i in range(ip4_pfx.num_addresses):
        print("map add domain ip4-pfx " + str(ip4_pfx[i]) +  "/32 ip6-pfx ::/0 ip6-src", ip6_src[i],
              "ea-bits-len 0 psid-offset 6 psid-len", psid_len)
        for psid in range(0x1 << psid_len):
            print("map add rule index", i, "psid", psid, "ip6-dst", ip6_dst[(i * (0x1<<psid_len)) + psid])

#
# 1:1 Shared IPv4 address small
#
def smallshared11():
    ip4_pfx = ipaddress.ip_network('20.0.0.0/24')
    ip6_src = ipaddress.ip_network('cccc:bbbb::/64')
    ip6_dst = ipaddress.ip_network('bbbb::/32')
    psid_len = 6
    for i in range(ip4_pfx.num_addresses):
        print("map add domain ip4-pfx " + str(ip4_pfx[i]) +  "/32 ip6-pfx ::/0 ip6-src", ip6_src[i],
              "ea-bits-len 0 psid-offset 6 psid-len", psid_len)
        for psid in range(0x1 << psid_len):
            print("map add rule index", i, "psid", psid, "ip6-dst", ip6_dst[(i * (0x1<<psid_len)) + psid])

#
# 1:1 Full IPv4 address
#
def full11():
    ip4_pfx = ipaddress.ip_network('20.0.0.0/16')
    ip6_src = ipaddress.ip_network('cccc:bbbb::/64')
    ip6_dst = ipaddress.ip_network('bbbb::/32')
    psid_len = 0
    for i in range(ip4_pfx.num_addresses):
        print("map add domain ip4-pfx " + str(ip4_pfx[i]) +  "/32 ip6-pfx " + str(ip6_dst[i]) + "/128 ip6-src", ip6_src[i],
              "ea-bits-len 0 psid-offset 0 psid-len 0")
def full11br():
    ip4_pfx = ipaddress.ip_network('20.0.0.0/16')
    ip6_dst = ipaddress.ip_network('bbbb::/32')
    psid_len = 0
    for i in range(ip4_pfx.num_addresses):
        print("map add domain ip4-pfx " + str(ip4_pfx[i]) +  "/32 ip6-pfx " + str(ip6_dst[i]) + "/128 ip6-shared-src cccc:bbbb::1",
              "ea-bits-len 0 psid-offset 0 psid-len 0")

#
# Algorithmic mapping Shared IPv4 address
#
def algo():
    print("map add domain ip4-pfx 20.0.0.0/24 ip6-pfx bbbb::/32 ip6-src cccc:bbbb::1 ea-bits-len 16 psid-offset 6 psid-len 8")
    print("map add domain ip4-pfx 20.0.1.0/24 ip6-pfx bbbb:1::/32 ip6-src cccc:bbbb::2 ea-bits-len 8 psid-offset 0 psid-len 0")

#
# IP4 forwarding
#
def ip4():
    ip4_pfx = ipaddress.ip_network('20.0.0.0/16')
    for i in range(ip4_pfx.num_addresses):
        print("ip route add " + str(ip4_pfx[i]) +  "/32 via 172.16.0.2")


globals()[args.mapmode]()


