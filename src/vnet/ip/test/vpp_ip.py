"""
  IP Types

"""
import logging

from ipaddress import ip_address
from socket import AF_INET, AF_INET6
from vpp_papi import VppEnum
from vpp_object import VppObject
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
                return self.ip_addr == other.ip4
            else:
                return self.ip_addr == other.ip6
        else:
            raise Exception("Comparing VppIpAddressUnions:%s"
                            " with incomparable type: %s",
                            self, other)

    def __ne__(self, other):
        return not (self == other)

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
        return {
            'af': ip_address(self.gaddr).vapi_af,
            'grp_address': {
                ip_address(self.gaddr).vapi_af_name: self.gaddr
            },
            'src_address': {
                ip_address(self.saddr).vapi_af_name: self.saddr
            },
            'grp_address_length': self.glen,
        }

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
        return NotImplemented


class VppIpPuntPolicer(VppObject):
    def __init__(self, test, policer_index, is_ip6=False):
        self._test = test
        self._policer_index = policer_index
        self._is_ip6 = is_ip6

    def add_vpp_config(self):
        self._test.vapi.ip_punt_police(policer_index=self._policer_index,
                                       is_ip6=self._is_ip6, is_add=True)

    def remove_vpp_config(self):
        self._test.vapi.ip_punt_police(policer_index=self._policer_index,
                                       is_ip6=self._is_ip6, is_add=False)

    def query_vpp_config(self):
        NotImplemented


class VppIpPuntRedirect(VppObject):
    def __init__(self, test, rx_index, tx_index, nh_addr):
        self._test = test
        self._rx_index = rx_index
        self._tx_index = tx_index
        self._nh_addr = ip_address(nh_addr)

    def encode(self):
        return {"rx_sw_if_index": self._rx_index,
                "tx_sw_if_index": self._tx_index, "nh": self._nh_addr}

    def add_vpp_config(self):
        self._test.vapi.ip_punt_redirect(punt=self.encode(), is_add=True)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.ip_punt_redirect(punt=self.encode(), is_add=False)

    def get_vpp_config(self):
        is_ipv6 = True if self._nh_addr.version == 6 else False
        return self._test.vapi.ip_punt_redirect_dump(
            sw_if_index=self._rx_index, is_ipv6=is_ipv6)

    def query_vpp_config(self):
        if self.get_vpp_config():
            return True
        return False


class VppIpPathMtu(VppObject):
    def __init__(self, test, nh, pmtu, table_id=0):
        self._test = test
        self.nh = nh
        self.pmtu = pmtu
        self.table_id = table_id

    def add_vpp_config(self):
        self._test.vapi.ip_path_mtu_update(pmtu={'nh': self.nh,
                                                 'table_id': self.table_id,
                                                 'path_mtu': self.pmtu})
        self._test.registry.register(self, self._test.logger)
        return self

    def modify(self, pmtu):
        self.pmtu = pmtu
        self._test.vapi.ip_path_mtu_update(pmtu={'nh': self.nh,
                                                 'table_id': self.table_id,
                                                 'path_mtu': self.pmtu})
        return self

    def remove_vpp_config(self):
        self._test.vapi.ip_path_mtu_update(pmtu={'nh': self.nh,
                                                 'table_id': self.table_id,
                                                 'path_mtu': 0})

    def query_vpp_config(self):
        ds = list(self._test.vapi.vpp.details_iter(
            self._test.vapi.ip_path_mtu_get))

        for d in ds:
            if self.nh == str(d.pmtu.nh) \
               and self.table_id == d.pmtu.table_id \
               and self.pmtu == d.pmtu.path_mtu:
                return True
        return False

    def object_id(self):
        return ("ip-path-mtu-%d-%s-%d" % (self.table_id,
                                          self.nh,
                                          self.pmtu))

    def __str__(self):
        return self.object_id()
