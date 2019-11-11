"""
  IP Types

"""
import logging

from ipaddress import ip_address
from socket import AF_INET, AF_INET6
from vpp_papi import VppEnum
try:
    text_type = unicode
except NameError:
    text_type = str

_log = logging.getLogger(__name__)


class DpoProto:
    DPO_PROTO_IP4 = 0
    DPO_PROTO_IP6 = 1
    DPO_PROTO_MPLS = 2
    DPO_PROTO_ETHERNET = 3
    DPO_PROTO_BIER = 4
    DPO_PROTO_NSH = 5


INVALID_INDEX = 0xffffffff


def get_dpo_proto(addr):
    if ip_address(addr).version == 6:
        return DpoProto.DPO_PROTO_IP6
    else:
        return DpoProto.DPO_PROTO_IP4


class VppIpAddressUnion():
    def __init__(self, addr):
        self.addr = addr
        self.ip_addr = ip_address(text_type(self.addr))

    def encode(self):
        if self.version == 6:
            return {'ip6': self.ip_addr}
        else:
            return {'ip4': self.ip_addr}

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

    def __str__(self):
        return str(self.ip_addr)


class VppIpMPrefix():
    def __init__(self, saddr, gaddr, glen):
        self.saddr = saddr
        self.gaddr = gaddr
        self.glen = glen
        if ip_address(self.saddr).version != \
           ip_address(self.gaddr).version:
            raise ValueError('Source and group addresses must be of the '
                             'same address family.')

    def encode(self):
        if 6 == self.version:
            prefix = {
                'af': VppEnum.vl_api_address_family_t.ADDRESS_IP6,
                'grp_address': {
                    'ip6': self.gaddr
                },
                'src_address': {
                    'ip6': self.saddr
                },
                'grp_address_length': self.glen,
            }
        else:
            prefix = {
                'af': VppEnum.vl_api_address_family_t.ADDRESS_IP4,
                'grp_address': {
                    'ip4': self.gaddr
                },
                'src_address': {
                    'ip4':  self.saddr
                },
                'grp_address_length': self.glen,
            }
        return prefix

    @property
    def length(self):
        return self.glen

    @property
    def version(self):
        return ip_address(self.gaddr).version

    def __str__(self):
        return "(%s,%s)/%d" % (self.saddr, self.gaddr, self.glen)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return (self.glen == other.glen and
                    self.saddr == other.gaddr and
                    self.saddr == other.saddr)
        elif (hasattr(other, "grp_address_length") and
              hasattr(other, "grp_address") and
              hasattr(other, "src_address")):
            # vl_api_mprefix_t
            if 4 == self.version:
                return (self.glen == other.grp_address_length and
                        self.gaddr == str(other.grp_address.ip4) and
                        self.saddr == str(other.src_address.ip4))
            else:
                return (self.glen == other.grp_address_length and
                        self.gaddr == str(other.grp_address.ip6) and
                        self.saddr == str(other.src_address.ip6))
        else:
            raise Exception("Comparing VppIpPrefix:%s with unknown type: %s" %
                            (self, other))
        return False
