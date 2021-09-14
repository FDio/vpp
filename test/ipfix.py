#!/usr/bin/env python3
# Copyright (c) 2021 Cisco and/or its affiliates.
#
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#
# Licensed under the Apache License 2.0 or
# GNU General Public License v2.0 or later;  you may not use this file
# except in compliance with one of these Licenses. You
# may obtain a copy of the Licenses at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#     https://www.gnu.org/licenses/old-licenses/gpl-2.0-standalone.html
#
# Note: If this file is linked with Scapy, which is GPLv2+, your use of it
# must be under GPLv2+.  If at any point in the future it is no longer linked
# with Scapy (or other GPLv2+ licensed software), you are free to choose
# Apache 2.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# IPFIX support for Scapy (RFC7011)

from scapy.all import bind_layers, FieldLenField, IntField, Packet, \
    PacketListField, ShortEnumField, ShortField, StrLenField
from scapy.layers.inet import UDP


# IPFIX Information Elements http://www.iana.org/assignments/ipfix/ipfix.xhtml
information_elements = {
    1:   "octetDeltaCount",
    2:   "packetDeltaCount",
    3:   "deltaFlowCount",
    4:   "protocolIdentifier",
    5:   "ipClassOfService",
    6:   "tcpControlBits",
    7:   "sourceTransportPort",
    8:   "sourceIPv4Address",
    9:   "sourceIPv4PrefixLength",
    10:  "ingressInterface",
    11:  "destinationTransportPort",
    12:  "destinationIPv4Address",
    13:  "destinationIPv4PrefixLength",
    14:  "egressInterface",
    15:  "ipNextHopIPv4Address",
    16:  "bgpSourceAsNumber",
    17:  "bgpDestinationAsNumber",
    18:  "bgpNextHopIPv4Address",
    19:  "postMCastPacketDeltaCount",
    20:  "postMCastOctetDeltaCount",
    21:  "flowEndSysUpTime",
    22:  "flowStartSysUpTime",
    23:  "postOctetDeltaCount",
    24:  "postPacketDeltaCount",
    25:  "minimumIpTotalLength",
    26:  "maximumIpTotalLength",
    27:  "sourceIPv6Address",
    28:  "destinationIPv6Address",
    29:  "sourceIPv6PrefixLength",
    30:  "destinationIPv6PrefixLength",
    31:  "flowLabelIPv6",
    32:  "icmpTypeCodeIPv4",
    33:  "igmpType",
    34:  "samplingInterval",
    35:  "samplingAlgorithm",
    36:  "flowActiveTimeout",
    37:  "flowIdleTimeout",
    38:  "engineType",
    39:  "engineId",
    40:  "exportedOctetTotalCount",
    41:  "exportedMessageTotalCount",
    42:  "exportedFlowRecordTotalCount",
    43:  "ipv4RouterSc",
    44:  "sourceIPv4Prefix",
    45:  "destinationIPv4Prefix",
    46:  "mplsTopLabelType",
    47:  "mplsTopLabelIPv4Address",
    48:  "samplerId",
    49:  "samplerMode",
    50:  "samplerRandomInterval",
    51:  "classId",
    52:  "minimumTTL",
    53:  "maximumTTL",
    54:  "fragmentIdentification",
    55:  "postIpClassOfService",
    56:  "sourceMacAddress",
    57:  "postDestinationMacAddress",
    58:  "vlanId",
    59:  "postVlanId",
    60:  "ipVersion",
    61:  "flowDirection",
    62:  "ipNextHopIPv6Address",
    63:  "bgpNextHopIPv6Address",
    64:  "ipv6ExtensionHeaders",
    70:  "mplsTopLabelStackSection",
    71:  "mplsLabelStackSection2",
    72:  "mplsLabelStackSection3",
    73:  "mplsLabelStackSection4",
    74:  "mplsLabelStackSection5",
    75:  "mplsLabelStackSection6",
    76:  "mplsLabelStackSection7",
    77:  "mplsLabelStackSection8",
    78:  "mplsLabelStackSection9",
    79:  "mplsLabelStackSection10",
    80:  "destinationMacAddress",
    81:  "postSourceMacAddress",
    82:  "interfaceName",
    83:  "interfaceDescription",
    84:  "samplerName",
    85:  "octetTotalCount",
    86:  "packetTotalCount",
    87:  "flagsAndSamplerId",
    88:  "fragmentOffset",
    89:  "forwardingStatus",
    90:  "mplsVpnRouteDistinguisher",
    91:  "mplsTopLabelPrefixLength",
    92:  "srcTrafficIndex",
    93:  "dstTrafficIndex",
    94:  "applicationDescription",
    95:  "applicationId",
    96:  "applicationName",
    98:  "postIpDiffServCodePoint",
    99:  "multicastReplicationFactor",
    100: "className",
    101: "classificationEngineId",
    102: "layer2packetSectionOffset",
    103: "layer2packetSectionSize",
    104: "layer2packetSectionData",
    128: "bgpNextAdjacentAsNumber",
    129: "bgpPrevAdjacentAsNumber",
    130: "exporterIPv4Address",
    131: "exporterIPv6Address",
    132: "droppedOctetDeltaCount",
    133: "droppedPacketDeltaCount",
    134: "droppedOctetTotalCount",
    135: "droppedPacketTotalCount",
    136: "flowEndReason",
    137: "commonPropertiesId",
    138: "observationPointId",
    139: "icmpTypeCodeIPv6",
    140: "mplsTopLabelIPv6Address",
    141: "lineCardId",
    142: "portId",
    143: "meteringProcessId",
    144: "exportingProcessId",
    145: "templateId",
    146: "wlanChannelId",
    147: "wlanSSID",
    148: "flowId",
    149: "observationDomainId",
    150: "flowStartSeconds",
    151: "flowEndSeconds",
    152: "flowStartMilliseconds",
    153: "flowEndMilliseconds",
    154: "flowStartMicroseconds",
    155: "flowEndMicroseconds",
    156: "flowStartNanoseconds",
    157: "flowEndNanoseconds",
    158: "flowStartDeltaMicroseconds",
    159: "flowEndDeltaMicroseconds",
    160: "systemInitTimeMilliseconds",
    161: "flowDurationMilliseconds",
    162: "flowDurationMicroseconds",
    163: "observedFlowTotalCount",
    164: "ignoredPacketTotalCount",
    165: "ignoredOctetTotalCount",
    166: "notSentFlowTotalCount",
    167: "notSentPacketTotalCount",
    168: "notSentOctetTotalCount",
    169: "destinationIPv6Prefix",
    170: "sourceIPv6Prefix",
    171: "postOctetTotalCount",
    172: "postPacketTotalCount",
    173: "flowKeyIndicator",
    174: "postMCastPacketTotalCount",
    175: "postMCastOctetTotalCount",
    176: "icmpTypeIPv4",
    177: "icmpCodeIPv4",
    178: "icmpTypeIPv6",
    179: "icmpCodeIPv6",
    180: "udpSourcePort",
    181: "udpDestinationPort",
    182: "tcpSourcePort",
    183: "tcpDestinationPort",
    184: "tcpSequenceNumber",
    185: "tcpAcknowledgementNumber",
    186: "tcpWindowSize",
    187: "tcpUrgentPointer",
    188: "tcpHeaderLength",
    189: "ipHeaderLength",
    190: "totalLengthIPv4",
    191: "payloadLengthIPv6",
    192: "ipTTL",
    193: "nextHeaderIPv6",
    194: "mplsPayloadLength",
    195: "ipDiffServCodePoint",
    196: "ipPrecedence",
    197: "fragmentFlags",
    198: "octetDeltaSumOfSquares",
    199: "octetTotalSumOfSquares",
    200: "mplsTopLabelTTL",
    201: "mplsLabelStackLength",
    202: "mplsLabelStackDepth",
    203: "mplsTopLabelExp",
    204: "ipPayloadLength",
    205: "udpMessageLength",
    206: "isMulticast",
    207: "ipv4IHL",
    208: "ipv4Options",
    209: "tcpOptions",
    210: "paddingOctets",
    211: "collectorIPv4Address",
    212: "collectorIPv6Address",
    213: "exportInterface",
    214: "exportProtocolVersion",
    215: "exportTransportProtocol",
    216: "collectorTransportPort",
    217: "exporterTransportPort",
    218: "tcpSynTotalCount",
    219: "tcpFinTotalCount",
    220: "tcpRstTotalCount",
    221: "tcpPshTotalCount",
    222: "tcpAckTotalCount",
    223: "tcpUrgTotalCount",
    224: "ipTotalLength",
    225: "postNATSourceIPv4Address",
    226: "postNATDestinationIPv4Address",
    227: "postNAPTSourceTransportPort",
    228: "postNAPTDestinationTransportPort",
    229: "natOriginatingAddressRealm",
    230: "natEvent",
    231: "initiatorOctets",
    232: "responderOctets",
    233: "firewallEvent",
    234: "ingressVRFID",
    235: "egressVRFID",
    236: "VRFname",
    237: "postMplsTopLabelExp",
    238: "tcpWindowScale",
    239: "biflowDirection",
    240: "ethernetHeaderLength",
    241: "ethernetPayloadLength",
    242: "ethernetTotalLength",
    243: "dot1qVlanId",
    244: "dot1qPriority",
    245: "dot1qCustomerVlanId",
    246: "dot1qCustomerPriority",
    247: "metroEvcId",
    248: "metroEvcType",
    249: "pseudoWireId",
    250: "pseudoWireType",
    251: "pseudoWireControlWord",
    252: "ingressPhysicalInterface",
    253: "egressPhysicalInterface",
    254: "postDot1qVlanId",
    255: "postDot1qCustomerVlanId",
    256: "ethernetType",
    257: "postIpPrecedence",
    258: "collectionTimeMilliseconds",
    259: "exportSctpStreamId",
    260: "maxExportSeconds",
    261: "maxFlowEndSeconds",
    262: "messageMD5Checksum",
    263: "messageScope",
    264: "minExportSeconds",
    265: "minFlowStartSeconds",
    266: "opaqueOctets",
    267: "sessionScope",
    268: "maxFlowEndMicroseconds",
    269: "maxFlowEndMilliseconds",
    270: "maxFlowEndNanoseconds",
    271: "minFlowStartMicroseconds",
    272: "minFlowStartMilliseconds",
    273: "minFlowStartNanoseconds",
    274: "collectorCertificate",
    275: "exporterCertificate",
    276: "dataRecordsReliability",
    277: "observationPointType",
    278: "newConnectionDeltaCount",
    279: "connectionSumDurationSeconds",
    280: "connectionTransactionId",
    281: "postNATSourceIPv6Address",
    282: "postNATDestinationIPv6Address",
    283: "natPoolId",
    284: "natPoolName",
    285: "anonymizationFlags",
    286: "anonymizationTechnique",
    287: "informationElementIndex",
    288: "p2pTechnology",
    289: "tunnelTechnology",
    290: "encryptedTechnology",
    291: "basicList",
    292: "subTemplateList",
    293: "subTemplateMultiList",
    294: "bgpValidityState",
    295: "IPSecSPI",
    296: "greKey",
    297: "natType",
    298: "initiatorPackets",
    299: "responderPackets",
    300: "observationDomainName",
    301: "selectionSequenceId",
    302: "selectorId",
    303: "informationElementId",
    304: "selectorAlgorithm",
    305: "samplingPacketInterval",
    306: "samplingPacketSpace",
    307: "samplingTimeInterval",
    308: "samplingTimeSpace",
    309: "samplingSize",
    310: "samplingPopulation",
    311: "samplingProbability",
    312: "dataLinkFrameSize",
    313: "ipHeaderPacketSection",
    314: "ipPayloadPacketSection",
    315: "dataLinkFrameSection",
    316: "mplsLabelStackSection",
    317: "mplsPayloadPacketSection",
    318: "selectorIdTotalPktsObserved",
    319: "selectorIdTotalPktsSelected",
    320: "absoluteError",
    321: "relativeError",
    322: "observationTimeSeconds",
    323: "observationTimeMilliseconds",
    324: "observationTimeMicroseconds",
    325: "observationTimeNanoseconds",
    326: "digestHashValue",
    327: "hashIPPayloadOffset",
    328: "hashIPPayloadSize",
    329: "hashOutputRangeMin",
    330: "hashOutputRangeMax",
    331: "hashSelectedRangeMin",
    332: "hashSelectedRangeMax",
    333: "hashDigestOutput",
    334: "hashInitialiserValue",
    335: "selectorName",
    336: "upperCILimit",
    337: "lowerCILimit",
    338: "confidenceLevel",
    339: "informationElementDataType",
    340: "informationElementDescription",
    341: "informationElementName",
    342: "informationElementRangeBegin",
    343: "informationElementRangeEnd",
    344: "informationElementSemantics",
    345: "informationElementUnits",
    346: "privateEnterpriseNumber",
    347: "virtualStationInterfaceId",
    348: "virtualStationInterfaceName",
    349: "virtualStationUUID",
    350: "virtualStationName",
    351: "layer2SegmentId",
    352: "layer2OctetDeltaCount",
    353: "layer2OctetTotalCount",
    354: "ingressUnicastPacketTotalCount",
    355: "ingressMulticastPacketTotalCount",
    356: "ingressBroadcastPacketTotalCount",
    357: "egressUnicastPacketTotalCount",
    358: "egressBroadcastPacketTotalCount",
    359: "monitoringIntervalStartMilliSeconds",
    360: "monitoringIntervalEndMilliSeconds",
    361: "portRangeStart",
    362: "portRangeEnd",
    363: "portRangeStepSize",
    364: "portRangeNumPorts",
    365: "staMacAddress",
    366: "staIPv4Address",
    367: "wtpMacAddress",
    368: "ingressInterfaceType",
    369: "egressInterfaceType",
    370: "rtpSequenceNumber",
    371: "userName",
    372: "applicationCategoryName",
    373: "applicationSubCategoryName",
    374: "applicationGroupName",
    375: "originalFlowsPresent",
    376: "originalFlowsInitiated",
    377: "originalFlowsCompleted",
    378: "distinctCountOfSourceIPAddress",
    379: "distinctCountOfDestinationIPAddress",
    380: "distinctCountOfSourceIPv4Address",
    381: "distinctCountOfDestinationIPv4Address",
    382: "distinctCountOfSourceIPv6Address",
    383: "distinctCountOfDestinationIPv6Address",
    384: "valueDistributionMethod",
    385: "rfc3550JitterMilliseconds",
    386: "rfc3550JitterMicroseconds",
    387: "rfc3550JitterNanoseconds",
    388: "dot1qDEI",
    389: "dot1qCustomerDEI",
    390: "flowSelectorAlgorithm",
    391: "flowSelectedOctetDeltaCount",
    392: "flowSelectedPacketDeltaCount",
    393: "flowSelectedFlowDeltaCount",
    394: "selectorIDTotalFlowsObserved",
    395: "selectorIDTotalFlowsSelected",
    396: "samplingFlowInterval",
    397: "samplingFlowSpacing",
    398: "flowSamplingTimeInterval",
    399: "flowSamplingTimeSpacing",
    400: "hashFlowDomain",
    401: "transportOctetDeltaCount",
    402: "transportPacketDeltaCount",
    403: "originalExporterIPv4Address",
    404: "originalExporterIPv6Address",
    405: "originalObservationDomainId",
    406: "intermediateProcessId",
    407: "ignoredDataRecordTotalCount",
    408: "dataLinkFrameType",
    409: "sectionOffset",
    410: "sectionExportedOctets",
    411: "dot1qServiceInstanceTag",
    412: "dot1qServiceInstanceId",
    413: "dot1qServiceInstancePriority",
    414: "dot1qCustomerSourceMacAddress",
    415: "dot1qCustomerDestinationMacAddress",
    417: "postLayer2OctetDeltaCount",
    418: "postMCastLayer2OctetDeltaCount",
    420: "postLayer2OctetTotalCount",
    421: "postMCastLayer2OctetTotalCount",
    422: "minimumLayer2TotalLength",
    423: "maximumLayer2TotalLength",
    424: "droppedLayer2OctetDeltaCount",
    425: "droppedLayer2OctetTotalCount",
    426: "ignoredLayer2OctetTotalCount",
    427: "notSentLayer2OctetTotalCount",
    428: "layer2OctetDeltaSumOfSquares",
    429: "layer2OctetTotalSumOfSquares",
    430: "layer2FrameDeltaCount",
    431: "layer2FrameTotalCount",
    432: "pseudoWireDestinationIPv4Address",
    433: "ignoredLayer2FrameTotalCount",
    434: "mibObjectValueInteger",
    435: "mibObjectValueOctetString",
    436: "mibObjectValueOID",
    437: "mibObjectValueBits",
    438: "mibObjectValueIPAddress",
    439: "mibObjectValueCounter",
    440: "mibObjectValueGauge",
    441: "mibObjectValueTimeTicks",
    442: "mibObjectValueUnsigned",
    443: "mibObjectValueTable",
    444: "mibObjectValueRow",
    445: "mibObjectIdentifier",
    446: "mibSubIdentifier",
    447: "mibIndexIndicator",
    448: "mibCaptureTimeSemantics",
    449: "mibContextEngineID",
    450: "mibContextName",
    451: "mibObjectName",
    452: "mibObjectDescription",
    453: "mibObjectSyntax",
    454: "mibModuleName",
    455: "mobileIMSI",
    456: "mobileMSISDN",
    457: "httpStatusCode",
    458: "sourceTransportPortsLimit",
    459: "httpRequestMethod",
    460: "httpRequestHost",
    461: "httpRequestTarget",
    462: "httpMessageVersion",
    466: "natQuotaExceededEvent",
    471: "maxSessionEntries",
    472: "maxBIBEntries",
    473: "maxEntriesPerUser",
    475: "maxFragmentsPendingReassembly"
}


class IPFIX(Packet):
    name = "IPFIX"
    fields_desc = [ShortField("version", 10),
                   ShortField("length", None),
                   IntField("exportTime", None),
                   IntField("sequenceNumber", 1),
                   IntField("observationDomainID", 1)]


class FieldSpecifier(Packet):
    name = "Field Specifier"
    fields_desc = [ShortEnumField(
        "informationElement", None, information_elements),
        ShortField("fieldLength", None)]

    def extract_padding(self, s):
        return "", s


class Template(Packet):
    name = "Template"
    fields_desc = [ShortField("templateID", 256),
                   FieldLenField("fieldCount", None, count_of="fields"),
                   PacketListField("templateFields", [], FieldSpecifier,
                                   count_from=lambda p: p.fieldCount)]


class Data(Packet):
    name = "Data"
    fields_desc = [
        StrLenField("data", "", length_from=lambda p: p.underlayer.length - 4)]

    def extract_padding(self, s):
        return "", s


class Set(Packet):
    name = "Set"
    fields_desc = [ShortField("setID", 256),
                   ShortField("length", None)]

    def guess_payload_class(self, payload):
        if self.setID == 2:
            return Template
        elif self.setID > 255:
            return Data
        else:
            return Packet.guess_payload_class(self, payload)


bind_layers(IPFIX, Set)
bind_layers(UDP, IPFIX, dport=4739)


class IPFIXDecoder:
    """ IPFIX data set decoder """

    def __init__(self):
        self._templates = []

    def add_template(self, template):
        """
        Add IPFIX template

        :param template: IPFIX template
        """
        templateID = template.templateID
        fields = []
        rec_len = 0
        for field in template.templateFields:
            fields.append(
                {'name': field.informationElement, 'len': field.fieldLength})
            rec_len += field.fieldLength
        self._templates.append(
            {'id': templateID, 'fields': fields, 'rec_len': rec_len})

    def decode_data_set(self, data_set):
        """
        Decode IPFIX data

        :param data_set: IPFIX data set
        :returns: List of decoded data records.
        """
        data = []
        for template in self._templates:
            if template['id'] == data_set.setID:
                offset = 0
                d = data_set[Data].data
                for i in range(len(d) // template['rec_len']):
                    record = {}
                    for field in template['fields']:
                        f = d[offset:offset + field['len']]
                        offset += field['len']
                        record.update({field['name']: f})
                    data.append(record)
                break
        return data
