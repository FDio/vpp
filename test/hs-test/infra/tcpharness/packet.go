/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

package tcpharness

import (
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

const (
	tcpFlagAck = 0x10
	tcpFlagSyn = 0x02
	tcpFlagFin = 0x01
	tcpFlagRst = 0x04
	tcpFlagPsh = 0x08
	tcpFlagUrg = 0x20
	tcpFlagEce = 0x40
	tcpFlagCwr = 0x80

	tcpOptionSackBlockLen = 8
	tcpMaxSackBlocks      = 4

	// The ACK gate suppresses Linux-generated pure ACK/SACK packets on the server
	// egress path while allowing the harness's own synthetic ACK/SACK packets to
	// escape the same NFQUEUE hook. Marking synthetic packets with a distinctive
	// IPv4 TTL gives the gate an explicit way to recognize and pass them.
	syntheticAckTTL = 66
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

func (p PcapIPv4TCPPacket) IsSyntheticAck() bool {
	return p.TTL == syntheticAckTTL
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
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader, err := pcapgo.NewReader(file)
	if err != nil {
		return nil, err
	}

	packets := make([]PcapIPv4TCPPacket, 0)

	for {
		data, captureInfo, err := reader.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}

		packet, ok := parseLinkIPv4TCPPacket(reader.LinkType(), data)
		if ok {
			packet.Timestamp = captureInfo.Timestamp
			packets = append(packets, packet)
		}
	}

	return packets, nil
}

func parseRawIPv4TCPPacket(data []byte) (PcapIPv4TCPPacket, bool) {
	return parseLinkIPv4TCPPacket(layers.LinkTypeRaw, data)
}

func parseLinkIPv4TCPPacket(linkType layers.LinkType, data []byte) (PcapIPv4TCPPacket, bool) {
	packet := gopacket.NewPacket(data, linkType, gopacket.NoCopy)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if ipLayer == nil || tcpLayer == nil {
		return PcapIPv4TCPPacket{}, false
	}

	ipv4, ok := ipLayer.(*layers.IPv4)
	if !ok {
		return PcapIPv4TCPPacket{}, false
	}
	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return PcapIPv4TCPPacket{}, false
	}

	srcIP := ipv4.SrcIP.To4()
	dstIP := ipv4.DstIP.To4()
	if srcIP == nil || dstIP == nil {
		return PcapIPv4TCPPacket{}, false
	}
	srcIP = append(net.IP(nil), srcIP...)
	dstIP = append(net.IP(nil), dstIP...)

	sackBlocks := 0
	hasTSOpt := false
	for _, option := range tcp.Options {
		switch option.OptionType {
		case layers.TCPOptionKindSACK:
			if len(option.OptionData) >= tcpOptionSackBlockLen {
				sackBlocks = len(option.OptionData) / tcpOptionSackBlockLen
			}
		case layers.TCPOptionKindTimestamps:
			hasTSOpt = true
		}
	}

	return PcapIPv4TCPPacket{
		SrcIP:      srcIP,
		DstIP:      dstIP,
		TTL:        uint8(ipv4.TTL),
		SrcPort:    uint16(tcp.SrcPort),
		DstPort:    uint16(tcp.DstPort),
		Seq:        tcp.Seq,
		Ack:        tcp.Ack,
		Flags:      tcpFlags(tcp),
		SackBlocks: sackBlocks,
		HasTSOpt:   hasTSOpt,
		PayloadLen: len(tcp.Payload),
	}, true
}

func tcpFlags(tcp *layers.TCP) uint8 {
	var flags uint8
	if tcp.FIN {
		flags |= tcpFlagFin
	}
	if tcp.SYN {
		flags |= tcpFlagSyn
	}
	if tcp.RST {
		flags |= tcpFlagRst
	}
	if tcp.PSH {
		flags |= tcpFlagPsh
	}
	if tcp.ACK {
		flags |= tcpFlagAck
	}
	if tcp.URG {
		flags |= tcpFlagUrg
	}
	if tcp.ECE {
		flags |= tcpFlagEce
	}
	if tcp.CWR {
		flags |= tcpFlagCwr
	}
	return flags
}
