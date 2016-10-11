from scapy.layers.l2 import Dot1Q
from abc import abstractmethod, ABCMeta
from vpp_interface import VppInterface


class VppSubInterface(VppInterface):
    __metaclass__ = ABCMeta

    def __init__(self, test, parent, sub_id):
        self.test = test
        self.parent = parent
        self.parent.add_sub_if(self)
        self.sub_id = sub_id

    @abstractmethod
    def create_arp_req(self):
        pass

    def resolve_arp(self):
        super(VppSubInterface, self).resolve_arp(self.parent)

    @abstractmethod
    def add_dot1_layer(self, pkt):
        pass


class VppDot1QSubint(VppSubInterface):

    def __init__(self, test, parent, sub_id, vlan=None):
        if vlan is None:
            vlan = sub_id
        super(VppDot1QSubint, self).__init__(test, parent, sub_id)
        self.vlan = vlan
        self.pg_index = parent.pg_index
        r = self.test.vapi.create_vlan_subif(parent.sw_if_index, self.vlan)
        self._sw_if_index = r.sw_if_index
        self.post_init_setup()

    def create_arp_req(self):
        packet = VppInterface.create_arp_req(self)
        return self.add_dot1_layer(packet)

    def add_dot1_layer(self, packet):
        payload = packet.payload
        packet.remove_payload()
        packet.add_payload(Dot1Q(vlan=self.sub_id) / payload)
        return packet

    def remove_dot1_layer(self, packet):
        payload = packet.payload
        self.test.assertEqual(type(payload), Dot1Q)
        self.test.assertEqual(payload.vlan, self.vlan)
        payload = payload.payload
        packet.remove_payload()
        packet.add_payload(payload)
        return packet


class VppDot1ADSubint(VppSubInterface):

    def __init__(self, test, parent, sub_id, outer_vlan, inner_vlan):
        super(VppDot1ADSubint, self).__init__(test, parent, sub_id)
        self.outer_vlan = outer_vlan
        self.inner_vlan = inner_vlan
        self.dot1ad = 1
        self.pg_index = parent.pg_index
        r = vapi.create_subif(self.sw_if_index, self.sub_id,
                              self.outer_vlan, self.inner_vlan, self.dot1ad)
        self.sw_if_index = r.sw_if_index
        self.post_init_setup()

    def create_arp_req(self):
        packet = VppInterface.create_arp_req(self)
        return self.add_dot1_layer(packet)

    def add_dot1_layer(self, packet):
        payload = packet.payload
        packet.remove_payload()
        packet.add_payload(Dot1Q(vlan=self.outer_vlan) /
                           Dot1Q(vlan=self.inner_vlan) / payload)
        packet.type = 0x88A8
        return packet

    def remove_dot1_layer(self, packet):
        payload = packet.payload
        self.test.assertEqual(type(payload), Dot1Q)
        self.test.assertEqual(payload.vlan, self.outer_vlan)
        payload = payload.payload
        self.test.assertEqual(type(payload), Dot1Q)
        self.test.assertEqual(payload.vlan, self.inner_vlan)
        payload = payload.payload
        packet.remove_payload()
        packet.add_payload(payload)
        return packet
