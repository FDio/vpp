"""
  IP Types

"""

from ipaddress import ip_address
from socket import AF_INET, AF_INET6
from vpp_papi import VppEnum


class DpoProto:
    DPO_PROTO_IP4 = 0
    DPO_PROTO_IP6 = 1
    DPO_PROTO_MPLS = 2
    DPO_PROTO_ETHERNET = 3
    DPO_PROTO_BIER = 4
    DPO_PROTO_NSH = 5


INVALID_INDEX = 0xffffffff


class VppIpAddressUnion():
    def __init__(self, addr):
        self.addr = addr
        self.ip_addr = ip_address(unicode(self.addr))

    def encode(self):
        if self.version is 6:
            return {
                'ip6': {
                    'address': self.ip_addr.packed
                },
            }
        else:
            return {
                'ip4': {
                    'address': self.ip_addr.packed
                },
            }

    @property
    def version(self):
        return self.ip_addr.version

    @property
    def address(self):
        return self.addr

    @property
    def length(self):
        if self.version is 6:
            return 128
        else:
            return 32

    @property
    def bytes(self):
        return self.ip_addr.packed

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.ip_addr == other.ip_addr
        elif hasattr(other, "ip4") and hasattr(other, "ip6"):
            # vl_api_address_union_t
            if 4 is self.version:
                return self.ip_addr.packed == other.ip4.address
            else:
                return self.ip_addr.packed == other.ip6.address
        else:
            raise Exception("Comparing VppIpAddresUnions:%s"
                            " with unknown type: %s" %
                            (self, other))

        return False


class VppIpAddress():
    def __init__(self, addr):
        self.addr = VppIpAddressUnion(addr)

    def encode(self):
        if self.addr.version is 6:
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
            if 4 is self.version:
                return other.af == \
                    VppEnum.vl_api_address_family_t.ADDRESS_IP4 and \
                    other.un == self.addr
            else:
                return other.af == \
                    VppEnum.vl_api_address_family_t.ADDRESS_IP6 and \
                    other.un == self.addr
        else:
            raise Exception("Comparing VppIpAddress:%s with unknown type: %s" %
                            (self, other))
        return False

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
        if self.version is 6:
            return DpoProto.DPO_PROTO_IP6
        else:
            return DpoProto.DPO_PROTO_IP4


class VppIpPrefix():
    def __init__(self, addr, len):
        self.addr = VppIpAddress(addr)
        self.len = len

    def __eq__(self, other):
        if self.addr == other.addr and self.len == other.len:
            return True
        return False

    def encode(self):
        return {'address': self.addr.encode(),
                'address_length': self.len}

    @property
    def address(self):
        return self.addr.address

    @property
    def length(self):
        return self.len

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
            raise Exception("Comparing VppIpPrefix:%s with unknown type: %s" %
                            (self, other))
        return False

class VppIp6Prefix():
    def __init__(self, prefix, prefixlen):
        self.ip_prefix = ip_address(unicode(prefix))
        self.prefixlen = prefixlen

    def encode(self):
        return {'prefix': { 'address' : self.ip_prefix.packed },
                'len': self.prefixlen}

class VppIp4Prefix(VppIp6Prefix):
    pass

class VppIpMPrefix():
    def __init__(self, saddr, gaddr, len):
        self.saddr = saddr
        self.gaddr = gaddr
        self.len = len
        self.ip_saddr = ip_address(unicode(self.saddr))
        self.ip_gaddr = ip_address(unicode(self.gaddr))

    def encode(self):

        if 6 is self.ip_saddr.version:
            prefix = {
                'af': VppEnum.vl_api_address_family_t.ADDRESS_IP6,
                'grp_address': {
                    'ip6': {
                        'address': self.ip_gaddr.packed
                    },
                },
                'src_address': {
                    'ip6': {
                        'address': self.ip_saddr.packed
                    },
                },
                'grp_address_length': self.len,
            }
        else:
            prefix = {
                'af': VppEnum.vl_api_address_family_t.ADDRESS_IP4,
                'grp_address': {
                    'ip4': {
                        'address': self.ip_gaddr.packed
                    },
                },
                'src_address': {
                    'ip4': {
                        'address': self.ip_saddr.packed
                    },
                },
                'grp_address_length': self.len,
            }
        return prefix
