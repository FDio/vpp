"""
  IP Types

"""

from ipaddress import ip_address


class IpAddressFamily:
    ADDRESS_IP4 = 0
    ADDRESS_IP6 = 1


INVALID_INDEX = 0xffffffff


def compare_ip_address(api_address, py_address):
    if 4 is py_address.version:
        if py_address.packed == api_address.ip4.address:
            return True
    else:
        if py_address.packed == api_address.ip6.address:
            return True
    return False


class VppIpAddressUnion():
    def __init__(self, addr):
        self.addr = addr
        self.ip_addr = ip_address(unicode(self.addr))

    @property
    def version(self):
        return self.ip_addr.version

    @property
    def address(self):
        return self.addr

    def encode(self):
        if self.ip_addr.version is 6:
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
    def address(self):
        return self.addr.address


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
