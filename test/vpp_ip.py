"""
  IP Types

"""

from ipaddress import ip_address
from socket import AF_INET, AF_INET6


class IpAddressFamily:
    ADDRESS_IP4 = 0
    ADDRESS_IP6 = 1


INVALID_INDEX = 0xffffffff


def compare_ip_address_union(api_address_u, py_address):
    if 4 is py_address.version:
        if py_address.packed == api_address_u.ip4.address:
            return True
    else:
        if py_address.packed == api_address_u.ip6.address:
            return True
    return False


def compare_ip_address(api_address, vpp_address):
    if 4 is vpp_address.version:
        return (api_address.af == IpAddressFamily.ADDRESS_IP4 and
                compare_ip_address_union(api_address.un,
                                         vpp_address.addr.ip_addr))
    else:
        return (api_address.af == IpAddressFamily.ADDRESS_IP6 and
                compare_ip_address_union(api_address.un,
                                         vpp_address.addr.ip_addr))
    return False


def compare_ip_prefix(api_prefix, vpp_prefix):
    return (api_prefix.address_length == vpp_prefix.length and
            compare_ip_address(api_prefix.address,
                               vpp_prefix.addr))


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


class VppIpAddress():
    def __init__(self, addr):
        self.addr = VppIpAddressUnion(addr)

    def encode(self):
        if self.addr.version is 6:
            return {
                'af': IpAddressFamily.ADDRESS_IP6,
                'un': self.addr.encode()
            }
        else:
            return {
                'af': IpAddressFamily.ADDRESS_IP4,
                'un': self.addr.encode()
            }

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
                'af': IpAddressFamily.ADDRESS_IP6,
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
                'af': IpAddressFamily.ADDRESS_IP4,
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
