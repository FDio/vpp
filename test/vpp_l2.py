"""
  L2/BD Types

"""

import enum
from vpp_object import *
from vpp_ip import VppIpAddress
from vpp_lo_interface import VppLoInterface
from vpp_papi import MACAddress


class L2_PORT_TYPE(enum.IntEnum):  # noqa
    NORMAL = 0
    BVI = 1
    UU_FWD = 2


class L2_VTR_OP(enum.IntEnum):  # noqa
    L2_DISABLED = 0
    L2_PUSH_1 = 1
    L2_PUSH_2 = 2
    L2_POP_1 = 3
    L2_POP_2 = 4
    L2_TRANSLATE_1_1 = 5
    L2_TRANSLATE_1_2 = 6
    L2_TRANSLATE_2_1 = 7
    L2_TRANSLATE_2_2 = 8


class BRIDGE_FLAGS(enum.IntEnum):  # noqa
    NONE = 0
    LEARN = 1
    FWD = 2
    FLOOD = 4
    UU_FLOOD = 8
    ARP_TERM = 16


def find_bridge_domain(test, bd_id):
    bds = test.vapi.bridge_domain_dump(bd_id)
    return len(bds) == 1


def find_bridge_domain_port(test, bd_id, sw_if_index):
    bds = test.vapi.bridge_domain_dump(bd_id)
    for bd in bds:
        for p in bd.sw_if_details:
            if p.sw_if_index == sw_if_index:
                return True
    return False


def find_bridge_domain_arp_entry(test, bd_id, mac, ip):
    vmac = MACAddress(mac)
    vip = VppIpAddress(ip)

    if vip.version == 4:
        n = 4
    else:
        n = 16

    arps = test.vapi.bd_ip_mac_dump(bd_id)
    for arp in arps:
        # do IP addr comparison too once .api is fixed...
        if vmac.packed == arp.mac_address and \
           vip.bytes == arp.ip_address[:n]:
            return True
    return False


def find_l2_fib_entry(test, bd_id, mac, sw_if_index):
    vmac = MACAddress(mac)
    lfs = test.vapi.l2_fib_table_dump(bd_id)
    for lf in lfs:
        if vmac.packed == lf.mac and sw_if_index == lf.sw_if_index:
            return True
    return False


class VppBridgeDomain(VppObject):

    def __init__(self, test, bd_id,
                 flood=1, uu_flood=1, forward=1,
                 learn=1, arp_term=1):
        self._test = test
        self.bd_id = bd_id
        self.flood = flood
        self.uu_flood = uu_flood
        self.forward = forward
        self.learn = learn
        self.arp_term = arp_term

    def add_vpp_config(self):
        self._test.vapi.bridge_domain_add_del(
            self.bd_id,
            is_add=1,
            flood=self.flood,
            uu_flood=self.uu_flood,
            forward=self.forward,
            learn=self.learn,
            arp_term=self.arp_term)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.bridge_domain_add_del(self.bd_id, is_add=0)

    def query_vpp_config(self):
        return find_bridge_domain(self._test, self.bd_id)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "bridge-domain-%d" % (self.bd_id)


class VppBridgeDomainPort(VppObject):

    def __init__(self, test, bd, itf,
                 port_type=L2_PORT_TYPE.NORMAL):
        self._test = test
        self.bd = bd
        self.itf = itf
        self.port_type = port_type

    def add_vpp_config(self):
        self._test.vapi.sw_interface_set_l2_bridge(
            self.itf.sw_if_index,
            self.bd.bd_id,
            port_type=self.port_type,
            enable=1)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.sw_interface_set_l2_bridge(
            self.itf.sw_if_index,
            self.bd.bd_id,
            port_type=self.port_type,
            enable=0)

    def query_vpp_config(self):
        return find_bridge_domain_port(self._test,
                                       self.bd.bd_id,
                                       self.itf.sw_if_index)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "BD-Port-%s-%s" % (self.bd, self.itf)


class VppBridgeDomainArpEntry(VppObject):

    def __init__(self, test, bd, mac, ip):
        self._test = test
        self.bd = bd
        self.mac = MACAddress(mac)
        self.ip = VppIpAddress(ip)

    def add_vpp_config(self):
        self._test.vapi.bd_ip_mac_add_del(
            self.bd.bd_id,
            self.mac.packed,
            self.ip.encode(),
            is_add=1)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.bd_ip_mac_add_del(
            self.bd.bd_id,
            self.mac.packed,
            self.ip.encode(),
            is_add=0)

    def query_vpp_config(self):
        return find_bridge_domain_arp_entry(self._test,
                                            self.bd.bd_id,
                                            self.mac.packed,
                                            self.ip.address)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "BD-Arp-Entry-%s-%s-%s" % (self.bd, self.mac, self.ip.address)


class VppL2FibEntry(VppObject):

    def __init__(self, test, bd, mac, itf,
                 static_mac=0, filter_mac=0, bvi_mac=-1):
        self._test = test
        self.bd = bd
        self.mac = MACAddress(mac)
        self.itf = itf
        self.static_mac = static_mac
        self.filter_mac = filter_mac
        if bvi_mac == -1:
            self.bvi_mac = isinstance(self.itf, VppLoInterface)
        else:
            self.bvi_mac = bvi_mac

    def add_vpp_config(self):
        self._test.vapi.l2fib_add_del(
            self.mac.packed,
            self.bd.bd_id,
            self.itf.sw_if_index,
            is_add=1,
            static_mac=self.static_mac,
            filter_mac=self.filter_mac,
            bvi_mac=self.bvi_mac)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.l2fib_add_del(
            self.mac.packed,
            self.bd.bd_id,
            self.itf.sw_if_index,
            is_add=0)

    def query_vpp_config(self):
        return find_l2_fib_entry(self._test,
                                 self.bd.bd_id,
                                 self.mac.packed,
                                 self.itf.sw_if_index)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "L2-Fib-Entry-%s-%s-%s" % (self.bd, self.mac, self.itf)
