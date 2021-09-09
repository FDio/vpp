#
# Copyright (c) 2021 Cisco and/or its affiliates.
#
# SPDX-License-Identifier: MIT
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
import datetime
from socket import inet_pton, AF_INET6, AF_INET
import socket
import ipaddress
from . import macaddress


# Copies from vl_api_address_t definition
ADDRESS_IP4 = 0
ADDRESS_IP6 = 1


def verify_enum_hint(e):
    return (e.ADDRESS_IP4.value == ADDRESS_IP4) and\
           (e.ADDRESS_IP6.value == ADDRESS_IP6)

#
# Type conversion for input arguments and return values
#


def format_vl_api_address_t(args):
    try:
        return {'un': {'ip6': inet_pton(AF_INET6, args)},
                'af': ADDRESS_IP6}
    # PY2: raises socket.error
    # PY3: raises OSError
    except (socket.error, OSError):
        return {'un': {'ip4': inet_pton(AF_INET, args)},
                'af': ADDRESS_IP4}


def format_vl_api_prefix_t(args):
    if isinstance(args, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return {'address': format_vl_api_address_t(
            str(args.network_address)),
                'len': int(args.prefixlen)}
    p, length = args.split('/')
    return {'address': format_vl_api_address_t(p),
            'len': int(length)}


def format_vl_api_address_with_prefix_t(args):
    if isinstance(args, (ipaddress.IPv4Interface, ipaddress.IPv6Interface)):
        return {'address': format_vl_api_address_t(
            str(args.network_address)),
                'len': int(args.prefixlen)}
    p, length = args.split('/')
    return {'address': format_vl_api_address_t(p),
            'len': int(length)}


def format_vl_api_ip6_prefix_t(args):
    if isinstance(args, ipaddress.IPv6Network):
        return {'address': args.network_address.packed,
                'len': int(args.prefixlen)}
    p, length = args.split('/')
    return {'address': inet_pton(AF_INET6, p),
            'len': int(length)}


def format_vl_api_ip6_address_with_prefix_t(args):
    if isinstance(args, ipaddress.IPv6Interface):
        return {'address': args.network_address.packed,
                'len': int(args.prefixlen)}
    p, length = args.split('/')
    return {'address': inet_pton(AF_INET6, p),
            'len': int(length)}


def format_vl_api_ip4_prefix_t(args):
    if isinstance(args, ipaddress.IPv4Network):
        return {'address': args.network_address.packed,
                'len': int(args.prefixlen)}
    p, length = args.split('/')
    return {'address': inet_pton(AF_INET, p),
            'len': int(length)}


def format_vl_api_ip4_address_with_prefix_t(args):
    if isinstance(args, ipaddress.IPv4Interface):
        return {'address': args.network_address.packed,
                'len': int(args.prefixlen)}
    p, length = args.split('/')
    return {'address': inet_pton(AF_INET, p),
            'len': int(length)}


conversion_table = {
    'vl_api_ip6_address_t':
    {
        'IPv6Address': lambda o: o.packed,
        'str': lambda s: inet_pton(AF_INET6, s)
    },
    'vl_api_ip4_address_t':
    {
        'IPv4Address': lambda o: o.packed,
        'str': lambda s: inet_pton(AF_INET, s)
    },
    'vl_api_ip6_prefix_t':
    {
        'IPv6Network': lambda o: {'address': o.network_address.packed,
                                  'len': o.prefixlen},
        'str': lambda s: format_vl_api_ip6_prefix_t(s)
    },
    'vl_api_ip4_prefix_t':
    {
        'IPv4Network': lambda o: {'address': o.network_address.packed,
                                  'len': o.prefixlen},
        'str': lambda s: format_vl_api_ip4_prefix_t(s)
    },
    'vl_api_address_t':
    {
        'IPv4Address': lambda o: {'af': ADDRESS_IP4, 'un': {'ip4': o.packed}},
        'IPv6Address': lambda o: {'af': ADDRESS_IP6, 'un': {'ip6': o.packed}},
        'str': lambda s: format_vl_api_address_t(s)
    },
    'vl_api_prefix_t':
    {
        'IPv4Network': lambda o: {'address':
                                  {'af': ADDRESS_IP4, 'un':
                                   {'ip4': o.network_address.packed}},
                                  'len': o.prefixlen},
        'IPv6Network': lambda o: {'address':
                                  {'af': ADDRESS_IP6, 'un':
                                   {'ip6': o.network_address.packed}},
                                  'len': o.prefixlen},
        'str': lambda s: format_vl_api_prefix_t(s)
    },
    'vl_api_address_with_prefix_t':
    {
        'IPv4Interface': lambda o: {'address':
                                    {'af': ADDRESS_IP4, 'un':
                                     {'ip4': o.packed}},
                                    'len': o.network.prefixlen},
        'IPv6Interface': lambda o: {'address':
                                    {'af': ADDRESS_IP6, 'un':
                                     {'ip6': o.packed}},
                                    'len': o.network.prefixlen},
        'str': lambda s: format_vl_api_address_with_prefix_t(s)
    },
    'vl_api_ip4_address_with_prefix_t':
    {
        'IPv4Interface': lambda o: {'address': o.packed,
                                    'len': o.network.prefixlen},
        'str': lambda s: format_vl_api_ip4_address_with_prefix_t(s)
    },
    'vl_api_ip6_address_with_prefix_t':
    {
        'IPv6Interface': lambda o: {'address': o.packed,
                                    'len': o.network.prefixlen},
        'str': lambda s: format_vl_api_ip6_address_with_prefix_t(s)
    },
    'vl_api_mac_address_t':
    {
        'MACAddress': lambda o: o.packed,
        'str': lambda s: macaddress.mac_pton(s)
    },
    'vl_api_timestamp_t':
    {
        'datetime.datetime': lambda o:
        (o - datetime.datetime(1970, 1, 1)).total_seconds()
    }
}


def unformat_api_address_t(o):
    if o.af == 1:
        return ipaddress.IPv6Address(o.un.ip6)
    if o.af == 0:
        return ipaddress.IPv4Address(o.un.ip4)
    return None


def unformat_api_prefix_t(o):
    if o.address.af == 1:
        return ipaddress.IPv6Network((o.address.un.ip6, o.len), False)
    if o.address.af == 0:
        return ipaddress.IPv4Network((o.address.un.ip4, o.len), False)
    return None

    if isinstance(o.address, ipaddress.IPv4Address):
        return ipaddress.IPv4Network((o.address, o.len), False)
    if isinstance(o.address, ipaddress.IPv6Address):
        return ipaddress.IPv6Network((o.address, o.len), False)
    raise ValueError('Unknown instance {}', format(o))


def unformat_api_address_with_prefix_t(o):
    if o.address.af == 1:
        return ipaddress.IPv6Interface((o.address.un.ip6, o.len))
    if o.address.af == 0:
        return ipaddress.IPv4Interface((o.address.un.ip4, o.len))
    return None


def unformat_api_ip4_address_with_prefix_t(o):
    return ipaddress.IPv4Interface((o.address, o.len))


def unformat_api_ip6_address_with_prefix_t(o):
    return ipaddress.IPv6Interface((o.address, o.len))


conversion_unpacker_table = {
    'vl_api_ip6_address_t': lambda o: ipaddress.IPv6Address(o),
    'vl_api_ip6_prefix_t': lambda o: ipaddress.IPv6Network((o.address, o.len)),
    'vl_api_ip4_address_t': lambda o: ipaddress.IPv4Address(o),
    'vl_api_ip4_prefix_t': lambda o: ipaddress.IPv4Network((o.address, o.len)),
    'vl_api_address_t': lambda o: unformat_api_address_t(o),
    'vl_api_prefix_t': lambda o: unformat_api_prefix_t(o),
    'vl_api_address_with_prefix_t': lambda o: unformat_api_address_with_prefix_t(o),
    'vl_api_ip4_address_with_prefix_t': lambda o: unformat_api_ip4_address_with_prefix_t(o),
    'vl_api_ip6_address_with_prefix_t': lambda o: unformat_api_ip6_address_with_prefix_t(o),
    'vl_api_mac_address_t': lambda o: macaddress.MACAddress(o),
    'vl_api_timestamp_t': lambda o: datetime.datetime.fromtimestamp(o),
    'vl_api_timedelta_t': lambda o: datetime.timedelta(seconds=o),
}
