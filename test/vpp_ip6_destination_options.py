from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField
from scapy.layers.inet6 import _OTypeField, _hbhopts


class IPv6DestOptEncapLimit(Packet):
    name = "IPv6DestOptEncapLimit"
    fields_desc = [
        _OTypeField("otype", 0x04, _hbhopts),  # Option Type for Encap Limit
        ByteField("optlen", 1),  # Length of following field
        ByteField("EncapLimit", 4),  # Tunnel Encapsulation Limit
    ]

    def alignment_delta(self, curpos):  # No alignment requirement
        return 0

    def extract_padding(self, p):
        return b"", p
