package tcpharness

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"
)

const (
	pcapLinkTypeEthernet = 1
	pcapLinkTypeRaw      = 101

	pcapGlobalHeaderLen = 24
	pcapRecordHeaderLen = 16

	ethernetHeaderLen     = 14
	ethernetVlanHeaderLen = 18
	etherTypeOffset       = 12
	etherTypeVlanOffset   = 16

	etherTypeIPv4  = 0x0800
	etherTypeDot1Q = 0x8100
	etherTypeQinQ  = 0x88a8

	ipv4Version                  = 4
	ipv4MinHeaderLen             = 20
	ipv4VersionIhlOffset         = 0
	ipv4TotalLenOffset           = 2
	ipv4TTLOffset                = 8
	ipv4ProtocolOffset           = 9
	ipv4SrcAddrOffset            = 12
	ipv4DstAddrOffset            = 16
	ipv4ProtocolTCP              = 6
	ipv4HeaderLenMultiplier      = 4
	ipv4VersionShift             = 4
	ipv4HeaderLenMask       byte = 0x0f

	tcpMinHeaderLen        = 20
	tcpSrcPortOffset       = 0
	tcpDstPortOffset       = 2
	tcpSeqOffset           = 4
	tcpAckOffset           = 8
	tcpDataOffsetByte      = 12
	tcpFlagsOffset         = 13
	tcpHeaderLenShift      = 4
	tcpHeaderLenMultiplier = 4
	tcpOptionsOffset       = 20

	tcpFlagAck = 0x10
	tcpFlagSyn = 0x02
	tcpFlagFin = 0x01

	tcpOptionEnd          = 0
	tcpOptionNoop         = 1
	tcpOptionSack         = 5
	tcpOptionTimestamp    = 8
	tcpOptionHeaderLen    = 2
	tcpOptionSackBlockLen = 8
	tcpMaxSackBlocks      = 4

	// The ACK gate suppresses Linux-generated pure ACK/SACK packets on the server
	// egress path while allowing the harness's own synthetic ACK/SACK packets to
	// escape the same NFQUEUE hook. Marking synthetic packets with a distinctive
	// IPv4 TTL gives the gate an explicit way to recognize and pass them.
	tcpHarnessSyntheticAckTTL = 66
)

type TcpTestEndpointSackBlock struct {
	Left  uint32
	Right uint32
}

type PcapIPv4TCPPacket struct {
	Timestamp  time.Time
	SrcIP      net.IP
	DstIP      net.IP
	TTL        uint8
	SrcPort    uint16
	DstPort    uint16
	Seq        uint32
	Ack        uint32
	Flags      uint8
	SackBlocks int
	HasTSOpt   bool
	PayloadLen int
}

func (p PcapIPv4TCPPacket) IsAckOnly() bool {
	return p.PayloadLen == 0 && p.Flags == tcpFlagAck
}

func (p PcapIPv4TCPPacket) IsSyntheticHarnessAck() bool {
	return p.TTL == tcpHarnessSyntheticAckTTL
}

func (p PcapIPv4TCPPacket) SeqEnd() uint32 {
	end := p.Seq + uint32(p.PayloadLen)
	if p.Flags&tcpFlagSyn != 0 {
		end++
	}
	if p.Flags&tcpFlagFin != 0 {
		end++
	}
	return end
}

type Flow struct {
	ClientIP   string
	ServerIP   string
	ServerPort uint16
}

func NewFlow(clientIP string, serverIP string, serverPort uint16) Flow {
	return Flow{
		ClientIP:   clientIP,
		ServerIP:   serverIP,
		ServerPort: serverPort,
	}
}

func (f Flow) ClientToServer(packet PcapIPv4TCPPacket) bool {
	return packet.SrcIP.String() == f.ClientIP &&
		packet.DstIP.String() == f.ServerIP &&
		packet.DstPort == f.ServerPort
}

func (f Flow) ServerToClient(packet PcapIPv4TCPPacket) bool {
	return packet.SrcIP.String() == f.ServerIP &&
		packet.DstIP.String() == f.ClientIP &&
		packet.SrcPort == f.ServerPort
}

func (f Flow) ServerSackCount(packets []PcapIPv4TCPPacket) int {
	count := 0
	for _, packet := range packets {
		if f.ServerToClient(packet) && packet.SackBlocks > 0 {
			count++
		}
	}
	return count
}

func (f Flow) HasServerSackWithAtLeastBlocks(packets []PcapIPv4TCPPacket, minBlocks int) bool {
	for _, packet := range packets {
		if f.ServerToClient(packet) && packet.SackBlocks >= minBlocks {
			return true
		}
	}
	return false
}

func (f Flow) HasPartialServerSackAck(packets []PcapIPv4TCPPacket) bool {
	maxDataSeqEnd := uint32(0)
	minSackAck := uint32(0)
	sawSack := false

	for _, packet := range packets {
		if !f.ClientToServer(packet) || packet.PayloadLen == 0 {
			continue
		}

		if seqEnd := packet.SeqEnd(); seqEnd > maxDataSeqEnd {
			maxDataSeqEnd = seqEnd
		}
	}

	for _, packet := range packets {
		if !f.ServerToClient(packet) || packet.SackBlocks == 0 {
			continue
		}

		if !sawSack || packet.Ack < minSackAck {
			minSackAck = packet.Ack
			sawSack = true
		}
	}

	if !sawSack || maxDataSeqEnd == 0 {
		return false
	}

	for _, packet := range packets {
		if !f.ServerToClient(packet) || packet.SackBlocks == 0 {
			continue
		}
		if packet.Ack > minSackAck && packet.Ack < maxDataSeqEnd {
			return true
		}
	}

	return false
}

func (f Flow) HasSackDrivenClientRetransmit(packets []PcapIPv4TCPPacket,
	maxAfterSack time.Duration) bool {
	seenBeforeSack := make(map[uint32]struct{})
	lastSackAt := time.Time{}

	for _, packet := range packets {
		switch {
		case f.ClientToServer(packet) && packet.PayloadLen > 0:
			if lastSackAt.IsZero() {
				seenBeforeSack[packet.Seq] = struct{}{}
				continue
			}

			if _, ok := seenBeforeSack[packet.Seq]; ok &&
				!packet.Timestamp.Before(lastSackAt) &&
				packet.Timestamp.Sub(lastSackAt) <= maxAfterSack {
				return true
			}

		case f.ServerToClient(packet) && packet.SackBlocks > 0:
			lastSackAt = packet.Timestamp
		}
	}

	return false
}

func (f Flow) HasOldSeqAckOnlyProbe(packets []PcapIPv4TCPPacket) bool {
	maxDataSeqEnd := uint32(0)

	for _, packet := range packets {
		if !f.ClientToServer(packet) {
			continue
		}

		if packet.PayloadLen > 0 {
			if seqEnd := packet.SeqEnd(); seqEnd > maxDataSeqEnd {
				maxDataSeqEnd = seqEnd
			}
			continue
		}

		if packet.IsAckOnly() && packet.Seq < maxDataSeqEnd {
			return true
		}
	}

	return false
}

func ReadPcapIPv4TCPPackets(path string) ([]PcapIPv4TCPPacket, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < pcapGlobalHeaderLen {
		return nil, fmt.Errorf("pcap too short")
	}

	format, err := pcapByteOrder(data[:4])
	if err != nil {
		return nil, err
	}

	linkType := format.order.Uint32(data[20:24])
	offset := pcapGlobalHeaderLen
	packets := make([]PcapIPv4TCPPacket, 0)

	for offset+pcapRecordHeaderLen <= len(data) {
		tsSec := format.order.Uint32(data[offset : offset+4])
		tsFrac := format.order.Uint32(data[offset+4 : offset+8])
		inclLen := int(format.order.Uint32(data[offset+8 : offset+12]))
		offset += pcapRecordHeaderLen
		if inclLen < 0 || offset+inclLen > len(data) {
			return nil, fmt.Errorf("invalid pcap record length")
		}

		pkt := data[offset : offset+inclLen]
		offset += inclLen

		packet, ok := parsePcapIPv4TCPPacket(linkType, pkt)
		if ok {
			packet.Timestamp = format.timestamp(tsSec, tsFrac)
			packets = append(packets, packet)
		}
	}

	return packets, nil
}

type pcapFormat struct {
	order binary.ByteOrder
	nano  bool
}

func (f pcapFormat) timestamp(sec uint32, frac uint32) time.Time {
	if f.nano {
		return time.Unix(int64(sec), int64(frac))
	}
	return time.Unix(int64(sec), int64(frac)*1000)
}

func pcapByteOrder(magic []byte) (pcapFormat, error) {
	switch binary.BigEndian.Uint32(magic) {
	case 0xa1b2c3d4:
		return pcapFormat{order: binary.BigEndian}, nil
	case 0xa1b23c4d:
		return pcapFormat{order: binary.BigEndian, nano: true}, nil
	case 0xd4c3b2a1:
		return pcapFormat{order: binary.LittleEndian}, nil
	case 0x4d3cb2a1:
		return pcapFormat{order: binary.LittleEndian, nano: true}, nil
	default:
		return pcapFormat{}, fmt.Errorf("unknown pcap magic")
	}
}

func pcapPayloadOffset(linkType uint32, pkt []byte) (int, bool) {
	switch linkType {
	case pcapLinkTypeEthernet:
		if len(pkt) < ethernetHeaderLen {
			return 0, false
		}

		ethType := binary.BigEndian.Uint16(pkt[etherTypeOffset : etherTypeOffset+2])
		offset := ethernetHeaderLen
		if ethType == etherTypeDot1Q || ethType == etherTypeQinQ {
			if len(pkt) < ethernetVlanHeaderLen {
				return 0, false
			}
			ethType = binary.BigEndian.Uint16(pkt[etherTypeVlanOffset : etherTypeVlanOffset+2])
			offset = ethernetVlanHeaderLen
		}
		if ethType != etherTypeIPv4 {
			return 0, false
		}
		return offset, true
	case pcapLinkTypeRaw:
		return 0, true
	default:
		return 0, false
	}
}

func parsePcapIPv4TCPPacket(linkType uint32, pkt []byte) (PcapIPv4TCPPacket, bool) {
	l3off, ok := pcapPayloadOffset(linkType, pkt)
	if !ok || len(pkt) < l3off+ipv4MinHeaderLen {
		return PcapIPv4TCPPacket{}, false
	}
	if pkt[l3off+ipv4VersionIhlOffset]>>ipv4VersionShift != ipv4Version {
		return PcapIPv4TCPPacket{}, false
	}

	ipHdrLen := int(pkt[l3off+ipv4VersionIhlOffset]&ipv4HeaderLenMask) *
		ipv4HeaderLenMultiplier
	if len(pkt) < l3off+ipHdrLen+tcpMinHeaderLen ||
		pkt[l3off+ipv4ProtocolOffset] != ipv4ProtocolTCP {
		return PcapIPv4TCPPacket{}, false
	}

	totalLen := int(binary.BigEndian.Uint16(pkt[l3off+ipv4TotalLenOffset : l3off+ipv4TotalLenOffset+2]))
	if totalLen < ipHdrLen+tcpMinHeaderLen || len(pkt) < l3off+totalLen {
		return PcapIPv4TCPPacket{}, false
	}

	tcpOff := l3off + ipHdrLen
	tcpHdrLen := int(pkt[tcpOff+tcpDataOffsetByte]>>tcpHeaderLenShift) *
		tcpHeaderLenMultiplier
	if tcpHdrLen < tcpMinHeaderLen || totalLen < ipHdrLen+tcpHdrLen {
		return PcapIPv4TCPPacket{}, false
	}

	sackBlocks := 0
	hasTSOpt := false
	for optOff := tcpOptionsOffset; optOff < tcpHdrLen; {
		kind := pkt[tcpOff+optOff]

		switch kind {
		case tcpOptionEnd:
			optOff = tcpHdrLen
		case tcpOptionNoop:
			optOff++
		default:
			if optOff+tcpOptionHeaderLen > tcpHdrLen {
				optOff = tcpHdrLen
				break
			}

			optLen := int(pkt[tcpOff+optOff+1])
			if optLen < tcpOptionHeaderLen || optOff+optLen > tcpHdrLen {
				optOff = tcpHdrLen
				break
			}

			if kind == tcpOptionSack && optLen >= tcpOptionHeaderLen+tcpOptionSackBlockLen {
				sackBlocks = (optLen - tcpOptionHeaderLen) / tcpOptionSackBlockLen
			}
			if kind == tcpOptionTimestamp {
				hasTSOpt = true
			}
			optOff += optLen
		}
	}

	return PcapIPv4TCPPacket{
		SrcIP: net.IPv4(pkt[l3off+ipv4SrcAddrOffset], pkt[l3off+ipv4SrcAddrOffset+1],
			pkt[l3off+ipv4SrcAddrOffset+2], pkt[l3off+ipv4SrcAddrOffset+3]),
		DstIP: net.IPv4(pkt[l3off+ipv4DstAddrOffset], pkt[l3off+ipv4DstAddrOffset+1],
			pkt[l3off+ipv4DstAddrOffset+2], pkt[l3off+ipv4DstAddrOffset+3]),
		TTL:        pkt[l3off+ipv4TTLOffset],
		SrcPort:    binary.BigEndian.Uint16(pkt[tcpOff+tcpSrcPortOffset : tcpOff+tcpSrcPortOffset+2]),
		DstPort:    binary.BigEndian.Uint16(pkt[tcpOff+tcpDstPortOffset : tcpOff+tcpDstPortOffset+2]),
		Seq:        binary.BigEndian.Uint32(pkt[tcpOff+tcpSeqOffset : tcpOff+tcpSeqOffset+4]),
		Ack:        binary.BigEndian.Uint32(pkt[tcpOff+tcpAckOffset : tcpOff+tcpAckOffset+4]),
		Flags:      pkt[tcpOff+tcpFlagsOffset],
		SackBlocks: sackBlocks,
		HasTSOpt:   hasTSOpt,
		PayloadLen: totalLen - ipHdrLen - tcpHdrLen,
	}, true
}

func tcpHarnessChecksumReduce(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func tcpHarnessChecksum(data []byte) uint16 {
	var sum uint32

	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}

	return tcpHarnessChecksumReduce(sum)
}

func tcpHarnessTCPChecksum(srcIP, dstIP net.IP, tcp []byte) uint16 {
	src := srcIP.To4()
	dst := dstIP.To4()
	if src == nil || dst == nil {
		return 0
	}

	var sum uint32

	sum += uint32(binary.BigEndian.Uint16(src[0:2]))
	sum += uint32(binary.BigEndian.Uint16(src[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dst[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dst[2:4]))
	sum += uint32(ipv4ProtocolTCP)
	sum += uint32(len(tcp))

	for i := 0; i+1 < len(tcp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcp[i : i+2]))
	}
	if len(tcp)%2 != 0 {
		sum += uint32(tcp[len(tcp)-1]) << 8
	}

	return tcpHarnessChecksumReduce(sum)
}
