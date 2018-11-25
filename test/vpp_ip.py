"""
  IP Types

"""
import logging

import enum
from ipaddress import ip_address
from socket import AF_INET, AF_INET6
from vpp_papi import VppEnum

_log = logging.getLogger(__name__)


class DPO_PROTO(enum.IntEnum):  # noqa
    IP4 = 0
    IP6 = 1
    MPLS = 2
    ETHERNET = 3
    BIER = 4
    NSH = 5


INVALID_INDEX = 0xffffffff


class VppIpAddressUnion(object):
    def __init__(self, addr):
        self.addr = addr
        self.ip_addr = ip_address(unicode(self.addr))

    def encode(self):
        if self.version == 6:
            return {'ip6': self.ip_addr.packed}
        else:
            return {'ip4': self.ip_addr.packed}

    @property
    def version(self):
        return self.ip_addr.version

    @property
    def address(self):
        return self.addr

    @property
    def length(self):
        return self.ip_addr.max_prefixlen

    @property
    def bytes(self):
        return self.ip_addr.packed

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.ip_addr == other.ip_addr
        elif hasattr(other, "ip4") and hasattr(other, "ip6"):
            # vl_api_address_union_t
            if 4 == self.version:
                return self.ip_addr.packed == other.ip4
            else:
                return self.ip_addr.packed == other.ip6
        else:
            _log.error("Comparing VppIpAddressUnions:%s"
                       " with incomparable type: %s",
                       self, other)
            return NotImplemented


class VppIpAddress(object):
    def __init__(self, addr):
        self.addr = VppIpAddressUnion(addr)

    def encode(self):
        if self.addr.version == 6:
            return {
                'af': VppEnum.vl_api_address_family_t.ADDRESS_IP6,
                'un': self.addr.encode()
            }
        else:
            return {
                'af': VppEnum.vl_api_address_family_t.ADDRESS_IP4,
                'un': self.addr.encode()
            }

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.addr == other.addr
        elif hasattr(other, "af") and hasattr(other, "un"):
            # a vp_api_address_t
            if 4 == self.version:
                return other.af == \
                    VppEnum.vl_api_address_family_t.ADDRESS_IP4 and \
                    other.un == self.addr
            else:
                return other.af == \
                    VppEnum.vl_api_address_family_t.ADDRESS_IP6 and \
                    other.un == self.addr
        else:
            _log.error(
                "Comparing VppIpAddress:<%s> %s with incomparable "
                "type: <%s> %s",
                self.__class__.__name__, self,
                other.__class__.__name__, other)
            return NotImplemented

    def __ne__(self, other):
        return not (self == other)

    def __str__(self):
        return self.address

    @property
    def bytes(self):
        return self.addr.bytes

    @property
    def address(self):
        return self.addr.address

    @property
    def length(self):
        return self.addr.length

    @property
    def version(self):
        return self.addr.version

    @property
    def is_ip6(self):
        return (self.version == 6)

    @property
    def af(self):
        if self.version == 6:
            return AF_INET6
        else:
            return AF_INET

    @property
    def dpo_proto(self):
        if self.version == 6:
            return DPO_PROTO.IP6
        else:
            return DPO_PROTO.IP4


class VppIpPrefix(object):
    def __init__(self, addr, len):
        self.addr = VppIpAddress(addr)
        self.len = len

    def encode(self):
        return {'address': self.addr.encode(),
                'address_length': self.len}

    @property
    def address(self):
        return self.addr.address

    @property
    def bytes(self):
        return self.addr.bytes

    @property
    def length(self):
        return self.len

    @property
    def is_ip6(self):
        return self.addr.is_ip6

    def __str__(self):
        return "%s/%d" % (self.address, self.length)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return (self.len == other.len and self.addr == other.addr)
        elif hasattr(other, "address") and hasattr(other, "address_length"):
            # vl_api_prefix_t
            return self.len == other.address_length and \
                   self.addr == other.address
        else:
            _log.error(
                "Comparing VppIpPrefix:%s with incomparable type: %s" %
                (self, other))
            return NotImplemented


class VppIpMPrefix(object):
    def __init__(self, saddr, gaddr, len):
        self.saddr = saddr
        self.gaddr = gaddr
        self.len = len
        self.ip_saddr = ip_address(unicode(self.saddr))
        self.ip_gaddr = ip_address(unicode(self.gaddr))
        if self.ip_saddr.version != self.ip_gaddr.version:
            raise ValueError('Source and group addresses must be of the '
                             'same address family.')

    def encode(self):
        if 6 == self.ip_saddr.version:
            prefix = {
                'af': VppEnum.vl_api_address_family_t.ADDRESS_IP6,
                'grp_address': {'ip6': self.ip_gaddr.packed},
                'src_address': {'ip6': self.ip_saddr.packed},
                'grp_address_length': self.len,
            }
        else:
            prefix = {
                'af': VppEnum.vl_api_address_family_t.ADDRESS_IP4,
                'grp_address': {'ip4': self.ip_gaddr.packed},
                'src_address': {'ip4': self.ip_saddr.packed},
                'grp_address_length': self.len,
            }
        return prefix
