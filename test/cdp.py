""" CDP protocol implementation """

from scapy.packet import Packet
from scapy.all import ByteField, ByteEnumField, XByteField, ShortField, \
    XShortField, FieldLenField, ShortEnumField, StrField, StrLenField

from util import NumericConstant
from vpp_object import VppObject
from scapy.fields import BitField
from scapy.fields import BitEnumField


def chksum(b):

    i = 0
    sum = 0
    count = len(b)

    while count > 1:
        sum = sum + ((b[i] << 8) + b[i + 1])
        count = count - 2
        i = i + 2

    if count > 0:
        sum = sum + b[i]

    while sum >> 16:
        sum = ((sum & 0xFFFF) + (sum >> 16))

    return ~sum & 0xFFFF


class CDPVersion(NumericConstant):
    """ CDP Version """

    v1 = 1
    v2 = 2

    desc_dict = {
        v1: "Version 1",
        v2: "Version 2"
    }


class TLVType(NumericConstant):
    """ TLV Type """

    unused = 0
    device_id = 1
    address = 2
    port_id = 3
    capabilities = 4
    version = 5
    platform = 6
    ipprefix = 7
    hello = 8
    vtp_domain = 9
    native_vlan = 10
    duplex = 11
    app1_vlan = 12
    trigger = 13
    power = 14
    mtu = 15
    trust = 16
    cos = 17
    sysname = 18
    sysobject = 19
    mgmt_addr = 20
    physical_loc = 21
    mgmt_addr2 = 22
    power_requested = 23
    power_available = 24
    port_unidirectional = 25
    unknown_28 = 26
    energywise = 27
    unknown_30 = 28
    spare_poe = 29

    desc_dict = {
        unused: "Unused",
        device_id: "Device ID",
        address: "Address",
        port_id: "Port ID",
        capabilities: "Capabilities",
        version: "Version",
        platform: "Platform",
        ipprefix: "IP Prefix",
        hello: "Hello",
        vtp_domain: "VTP domain",
        native_vlan: "Native VLAN",
        duplex: "Duplex",
        app1_vlan: "APP1 VLAN",
        trigger: "Trigger",
        power: "Power",
        mtu: "MTU",
        trust: "Trust",
        cos: "COS",
        sysname: "Sysname",
        sysobject: "Sysobject",
        mgmt_addr: "Management Address",
        physical_loc: "Physical Location",
        mgmt_addr2: "Management Address 2",
        power_requested: "Power Requested",
        power_available: "Power Available",
        port_unidirectional: "Port Unidirectional",
        unknown_28: "Unknown 28",
        energywise: "Energywise",
        unknown_30: "Unknown 30",
        spare_poe: "Spare POE"
    }


class CDP(Packet):
    """ CDP protocol layer for scapy """

    fields_desc = [
        ByteEnumField("version", CDPVersion.v2, CDPVersion.desc_dict),
        ByteField("ttl", 180),
        XShortField("checksum", 0)
    ]

    def post_build(self, p, pay):
        p += pay
        if not self.checksum:
            self.checksum = chksum(bytearray(p))
        return p


class TLV(Packet):
    """ TLV protocol layer for scapy """

    fields_desc = [
        ShortEnumField("type", TLVType.unused, TLVType.desc_dict),
        FieldLenField("length", None, fmt="H", length_of="value",
                      adjust=lambda pkt, x: x + 4),
        StrLenField("value", "", length_from=lambda pkt: pkt.length - 4)
    ]


class CustomTLV(Packet):
    """ Custom TLV protocol layer for scapy """

    fields_desc = [
        ShortField("type", 0),
        ShortField("length", 4),
        StrField("value", "")

    ]
