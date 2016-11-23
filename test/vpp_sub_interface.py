from scapy.layers.l2 import Ether, Dot1Q
from abc import abstractmethod, ABCMeta
from vpp_interface import VppInterface
from vpp_pg_interface import VppPGInterface


class VppSubInterface(VppPGInterface):
    __metaclass__ = ABCMeta

    @property
    def parent(self):
        """Parent interface for this sub-interface"""
        return self._parent

    @property
    def sub_id(self):
        """Sub-interface ID"""
        return self._sub_id

    def __init__(self, test, parent, sub_id):
        VppInterface.__init__(self, test)
        self._parent = parent
        self._parent.add_sub_if(self)
        self._sub_id = sub_id

    @abstractmethod
    def create_arp_req(self):
        pass

    @abstractmethod
    def create_ndp_req(self):
        pass

    def resolve_arp(self):
        super(VppSubInterface, self).resolve_arp(self.parent)

    def resolve_ndp(self):
        super(VppSubInterface, self).resolve_ndp(self.parent)

    @abstractmethod
    def add_dot1_layer(self, pkt):
        pass

    def remove_vpp_config(self):
        self.test.vapi.delete_subif(self._sw_if_index)


class VppDot1QSubint(VppSubInterface):

    @property
    def vlan(self):
        """VLAN tag"""
        return self._vlan

    def __init__(self, test, parent, sub_id, vlan=None):
        if vlan is None:
            vlan = sub_id
        self._vlan = vlan
        r = test.vapi.create_vlan_subif(parent.sw_if_index, vlan)
        self._sw_if_index = r.sw_if_index
        super(VppDot1QSubint, self).__init__(test, parent, sub_id)

    def create_arp_req(self):
        packet = VppPGInterface.create_arp_req(self)
        return self.add_dot1_layer(packet)

    def create_ndp_req(self):
        packet = VppPGInterface.create_ndp_req(self)
        return self.add_dot1_layer(packet)

    def add_dot1_layer(self, packet):
        payload = packet.payload
        packet.remove_payload()
        packet.add_payload(Dot1Q(vlan=self.sub_id) / payload)
        return packet

    def remove_dot1_layer(self, packet):
        payload = packet.payload
        self.test.instance().assertEqual(type(payload), Dot1Q)
        self.test.instance().assertEqual(payload.vlan, self.vlan)
        payload = payload.payload
        packet.remove_payload()
        packet.add_payload(payload)
        return packet


class VppDot1ADSubint(VppSubInterface):

    @property
    def outer_vlan(self):
        """Outer VLAN tag"""
        return self._outer_vlan

    @property
    def inner_vlan(self):
        """Inner VLAN tag"""
        return self._inner_vlan

    def __init__(self, test, parent, sub_id, outer_vlan, inner_vlan):
        r = test.vapi.create_subif(parent.sw_if_index, sub_id, outer_vlan,
                                   inner_vlan, dot1ad=1, two_tags=1,
                                   exact_match=1)
        self._sw_if_index = r.sw_if_index
        super(VppDot1ADSubint, self).__init__(test, parent, sub_id)
        self.DOT1AD_TYPE = 0x88A8
        self.DOT1Q_TYPE = 0x8100
        self._outer_vlan = outer_vlan
        self._inner_vlan = inner_vlan

    def create_arp_req(self):
        packet = VppPGInterface.create_arp_req(self)
        return self.add_dot1_layer(packet)

    def create_ndp_req(self):
        packet = VppPGInterface.create_ndp_req(self)
        return self.add_dot1_layer(packet)

    def add_dot1_layer(self, packet):
        payload = packet.payload
        packet.remove_payload()
        packet.add_payload(Dot1Q(vlan=self.outer_vlan) /
                           Dot1Q(vlan=self.inner_vlan) / payload)
        packet.type = self.DOT1AD_TYPE
        return packet

    def remove_dot1_layer(self, packet):
        self.test.instance().assertEqual(type(packet), Ether)
        self.test.instance().assertEqual(packet.type, self.DOT1AD_TYPE)
        packet.type = self.DOT1Q_TYPE
        packet = Ether(str(packet))
        payload = packet.payload
        self.test.instance().assertEqual(type(payload), Dot1Q)
        self.test.instance().assertEqual(payload.vlan, self.outer_vlan)
        payload = payload.payload
        self.test.instance().assertEqual(type(payload), Dot1Q)
        self.test.instance().assertEqual(payload.vlan, self.inner_vlan)
        payload = payload.payload
        packet.remove_payload()
        packet.add_payload(payload)
        return packet
