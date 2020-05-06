from scapy.layers.l2 import Dot1Q
import abc
from vpp_pg_interface import VppPGInterface
from vpp_interface import VppInterface
from vpp_papi import VppEnum


class L2_VTR_OP:
    L2_DISABLED = 0
    L2_PUSH_1 = 1
    L2_PUSH_2 = 2
    L2_POP_1 = 3
    L2_POP_2 = 4
    L2_TRANSLATE_1_1 = 5
    L2_TRANSLATE_1_2 = 6
    L2_TRANSLATE_2_1 = 7
    L2_TRANSLATE_2_2 = 8


class VppSubInterface(VppPGInterface, metaclass=abc.ABCMeta):

    @property
    def parent(self):
        """Parent interface for this sub-interface"""
        return self._parent

    @property
    def sub_id(self):
        """Sub-interface ID"""
        return self._sub_id

    @property
    def tag1(self):
        return self._tag1

    @property
    def tag2(self):
        return self._tag2

    @property
    def vtr(self):
        return self._vtr

    def __init__(self, test, parent, sub_id):
        VppInterface.__init__(self, test)
        self._parent = parent
        self._parent.add_sub_if(self)
        self._sub_id = sub_id
        self.DOT1AD_TYPE = 0x88A8
        self.DOT1Q_TYPE = 0x8100

    def set_sw_if_index(self, sw_if_index):
        super(VppSubInterface, self).set_sw_if_index(sw_if_index)
        self.set_vtr(L2_VTR_OP.L2_DISABLED)

    @abc.abstractmethod
    def create_arp_req(self):
        pass

    @abc.abstractmethod
    def create_ndp_req(self):
        pass

    def resolve_arp(self):
        super(VppSubInterface, self).resolve_arp(self.parent)

    def resolve_ndp(self):
        super(VppSubInterface, self).resolve_ndp(self.parent)

    @abc.abstractmethod
    def add_dot1_layer(self, pkt):
        pass

    def remove_vpp_config(self):
        self.test.vapi.delete_subif(self.sw_if_index)

    def _add_tag(self, packet, vlan, tag_type):
        payload = packet.payload
        inner_type = packet.type
        packet.remove_payload()
        packet.add_payload(Dot1Q(vlan=vlan) / payload)
        packet.payload.type = inner_type
        packet.payload.vlan = vlan
        packet.type = tag_type
        return packet

    def _remove_tag(self, packet, vlan=None, tag_type=None):
        if tag_type:
            self.test.instance().assertEqual(packet.type, tag_type)

        payload = packet.payload
        if vlan:
            self.test.instance().assertEqual(payload.vlan, vlan)
        inner_type = payload.type
        payload = payload.payload
        packet.remove_payload()
        packet.add_payload(payload)
        packet.type = inner_type
        return packet

    def add_dot1q_layer(self, packet, vlan):
        return self._add_tag(packet, vlan, self.DOT1Q_TYPE)

    def add_dot1ad_layer(self, packet, outer, inner):
        p = self._add_tag(packet, inner, self.DOT1Q_TYPE)
        return self._add_tag(p, outer, self.DOT1AD_TYPE)

    def remove_dot1q_layer(self, packet, vlan=None):
        return self._remove_tag(packet, vlan, self.DOT1Q_TYPE)

    def remove_dot1ad_layer(self, packet, outer=None, inner=None):
        p = self._remove_tag(packet, outer, self.DOT1AD_TYPE)
        return self._remove_tag(p, inner, self.DOT1Q_TYPE)

    def set_vtr(self, vtr, push1q=0, tag=None, inner=None, outer=None):
        self._tag1 = 0
        self._tag2 = 0
        self._push1q = 0

        if (vtr == L2_VTR_OP.L2_PUSH_1 or
            vtr == L2_VTR_OP.L2_TRANSLATE_1_1 or
                vtr == L2_VTR_OP.L2_TRANSLATE_2_1):
            self._tag1 = tag
            self._push1q = push1q
        if (vtr == L2_VTR_OP.L2_PUSH_2 or
            vtr == L2_VTR_OP.L2_TRANSLATE_1_2 or
                vtr == L2_VTR_OP.L2_TRANSLATE_2_2):
            self._tag1 = outer
            self._tag2 = inner
            self._push1q = push1q

        self.test.vapi.l2_interface_vlan_tag_rewrite(
            sw_if_index=self.sw_if_index, vtr_op=vtr, push_dot1q=self._push1q,
            tag1=self._tag1, tag2=self._tag2)
        self._vtr = vtr


class VppDot1QSubint(VppSubInterface):

    @property
    def vlan(self):
        """VLAN tag"""
        return self._vlan

    def __init__(self, test, parent, sub_id, vlan=None):
        super(VppDot1QSubint, self).__init__(test, parent, sub_id)
        if vlan is None:
            vlan = sub_id
        self._vlan = vlan
        r = test.vapi.create_vlan_subif(parent.sw_if_index, vlan)
        self.set_sw_if_index(r.sw_if_index)

    def create_arp_req(self):
        packet = VppPGInterface.create_arp_req(self)
        return self.add_dot1_layer(packet)

    def create_ndp_req(self):
        packet = VppPGInterface.create_ndp_req(self)
        return self.add_dot1_layer(packet)

    # called before sending packet
    def add_dot1_layer(self, packet):
        return self.add_dot1q_layer(packet, self.vlan)

    # called on received packet to "reverse" the add call
    def remove_dot1_layer(self, packet):
        return self.remove_dot1q_layer(packet, self.vlan)


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
        super(VppDot1ADSubint, self).__init__(test, parent, sub_id)
        flags = (VppEnum.vl_api_sub_if_flags_t.SUB_IF_API_FLAG_DOT1AD |
                 VppEnum.vl_api_sub_if_flags_t.SUB_IF_API_FLAG_TWO_TAGS |
                 VppEnum.vl_api_sub_if_flags_t.SUB_IF_API_FLAG_EXACT_MATCH)
        r = test.vapi.create_subif(sw_if_index=parent.sw_if_index,
                                   sub_id=sub_id, outer_vlan_id=outer_vlan,
                                   inner_vlan_id=inner_vlan,
                                   sub_if_flags=flags)
        self.set_sw_if_index(r.sw_if_index)
        self._outer_vlan = outer_vlan
        self._inner_vlan = inner_vlan

    def create_arp_req(self):
        packet = VppPGInterface.create_arp_req(self)
        return self.add_dot1_layer(packet)

    def create_ndp_req(self):
        packet = VppPGInterface.create_ndp_req(self)
        return self.add_dot1_layer(packet)

    def add_dot1_layer(self, packet):
        return self.add_dot1ad_layer(packet, self.outer_vlan, self.inner_vlan)

    def remove_dot1_layer(self, packet):
        return self.remove_dot1ad_layer(packet, self.outer_vlan,
                                        self.inner_vlan)


class VppP2PSubint(VppSubInterface):

    def __init__(self, test, parent, sub_id, remote_mac):
        super(VppP2PSubint, self).__init__(test, parent, sub_id)
        r = test.vapi.p2p_ethernet_add(parent.sw_if_index,
                                       remote_mac, sub_id)
        self.set_sw_if_index(r.sw_if_index)
        self.parent_sw_if_index = parent.sw_if_index
        self.p2p_remote_mac = remote_mac

    def add_dot1_layer(self, packet):
        return packet

    def remove_dot1_layer(self, packet):
        return packet

    def create_arp_req(self):
        packet = VppPGInterface.create_arp_req(self)
        return packet

    def create_ndp_req(self):
        packet = VppPGInterface.create_ndp_req(self)
        return packet
