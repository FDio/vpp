from scapy.fields import BitField, XByteField, X3BytesField
from scapy.packet import Packet, bind_layers
from scapy.layers.l2 import Ether
from scapy.layers.inet import UDP


class VXLAN(Packet):
    name = "VXLAN"
    fields_desc = [BitField("flags", 0x08000000, 32),
                   X3BytesField("vni", 0),
                   XByteField("reserved", 0x00)]

    def mysummary(self):
        return self.sprintf("VXLAN (vni=%VXLAN.vni%)")

bind_layers(UDP, VXLAN, dport=4789)
bind_layers(VXLAN, Ether)
