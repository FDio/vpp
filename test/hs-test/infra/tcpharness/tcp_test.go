/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

package tcpharness

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var testSynOptions = []layers.TCPOption{
	{
		OptionType: layers.TCPOptionKindMSS,
		OptionData: []byte{0x05, 0xb4},
	},
	{
		OptionType: layers.TCPOptionKindSACKPermitted,
	},
	{
		OptionType: layers.TCPOptionKindNop,
	},
	{
		OptionType: layers.TCPOptionKindNop,
	},
	{
		OptionType: layers.TCPOptionKindTimestamps,
		OptionData: []byte{0, 0, 0, 11, 0, 0, 0, 22},
	},
	{
		OptionType: layers.TCPOptionKindWindowScale,
		OptionData: []byte{7},
	},
}

func buildTestIPv4TCPPacket(t *testing.T, flags uint8,
	options []layers.TCPOption) []byte {
	t.Helper()

	ipv4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Id:       12345,
		Flags:    layers.IPv4DontFragment,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP("10.0.0.1").To4(),
		DstIP:    net.ParseIP("10.0.0.2").To4(),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(40000),
		DstPort: layers.TCPPort(1234),
		Seq:     1000,
		Ack:     2000,
		FIN:     flags&tcpFlagFin != 0,
		SYN:     flags&tcpFlagSyn != 0,
		RST:     flags&tcpFlagRst != 0,
		PSH:     flags&tcpFlagPsh != 0,
		ACK:     flags&tcpFlagAck != 0,
		URG:     flags&tcpFlagUrg != 0,
		ECE:     flags&tcpFlagEce != 0,
		CWR:     flags&tcpFlagCwr != 0,
		Window:  65535,
		Options: options,
	}
	if err := tcp.SetNetworkLayerForChecksum(ipv4); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum failed: %v", err)
	}

	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, ipv4, tcp); err != nil {
		t.Fatalf("SerializeLayers failed: %v", err)
	}
	return buffer.Bytes()
}

func decodedTestIPv4TCP(t *testing.T, raw []byte) (*layers.IPv4, *layers.TCP) {
	t.Helper()

	packet := gopacket.NewPacket(raw, layers.LinkTypeRaw, gopacket.Default)
	if errLayer := packet.ErrorLayer(); errLayer != nil {
		t.Fatalf("packet decode failed: %v", errLayer.Error())
	}
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if ipLayer == nil || tcpLayer == nil {
		t.Fatalf("expected IPv4/TCP packet")
	}
	return ipLayer.(*layers.IPv4), tcpLayer.(*layers.TCP)
}

func testTCPOption(tcp *layers.TCP,
	kind layers.TCPOptionKind) (layers.TCPOption, bool) {
	for _, option := range tcp.Options {
		if option.OptionType == kind {
			return option, true
		}
	}
	return layers.TCPOption{}, false
}

func assertTestTCPOption(t *testing.T, tcp *layers.TCP, kind layers.TCPOptionKind,
	data []byte) {
	t.Helper()
	option, ok := testTCPOption(tcp, kind)
	if !ok {
		t.Fatalf("missing TCP option %s in %v", kind, tcp.Options)
	}
	if data != nil && !bytes.Equal(data, option.OptionData) {
		t.Fatalf("option %s data = %v, want %v", kind, option.OptionData, data)
	}
}

func testPacket(src, dst string, srcPort, dstPort uint16, seq, ack uint32,
	payloadLen int, flags uint8, sackBlocks int, timestamp time.Time) PcapIPv4TCPPacket {
	return PcapIPv4TCPPacket{
		Timestamp:  timestamp,
		SrcIP:      net.ParseIP(src),
		DstIP:      net.ParseIP(dst),
		SrcPort:    srcPort,
		DstPort:    dstPort,
		Seq:        seq,
		Ack:        ack,
		Flags:      flags,
		PayloadLen: payloadLen,
		SackBlocks: sackBlocks,
	}
}

func TestTcpHarnessNFQueueDropIndicesUseFirstSeenDataSeq(t *testing.T) {
	h := &NFQueueHelper{
		cfg: NFQueueConfig{
			DropRetransmitCount: 1,
		},
		dropDataPacketIndices: map[uint32]struct{}{2: {}},
		retransmitTargets:     make(map[uint32]uint32),
		seenDataSeqs:          make(map[uint32]struct{}),
		originalDroppedSeqs:   make(map[uint32]struct{}),
	}

	first := PcapIPv4TCPPacket{Seq: 1000, PayloadLen: 100}
	drop, originalDrop := h.dataPacketDropDecisionLocked(first)
	if drop || originalDrop || h.dataSeen != 1 {
		t.Fatalf("first segment: drop=%v original=%v dataSeen=%d", drop, originalDrop, h.dataSeen)
	}

	drop, originalDrop = h.dataPacketDropDecisionLocked(first)
	if drop || originalDrop || h.dataSeen != 1 {
		t.Fatalf("duplicate segment changed index: drop=%v original=%v dataSeen=%d",
			drop, originalDrop, h.dataSeen)
	}

	second := PcapIPv4TCPPacket{Seq: 1100, PayloadLen: 100}
	drop, originalDrop = h.dataPacketDropDecisionLocked(second)
	if !drop || !originalDrop || h.dataSeen != 2 {
		t.Fatalf("second first-seen segment: drop=%v original=%v dataSeen=%d",
			drop, originalDrop, h.dataSeen)
	}

	drop, originalDrop = h.dataPacketDropDecisionLocked(second)
	if !drop || originalDrop || h.dataSeen != 2 || h.retransmitCount != 1 {
		t.Fatalf("first retransmit of dropped segment: drop=%v original=%v dataSeen=%d retransmits=%d",
			drop, originalDrop, h.dataSeen, h.retransmitCount)
	}

	third := PcapIPv4TCPPacket{Seq: 1200, PayloadLen: 100}
	drop, originalDrop = h.dataPacketDropDecisionLocked(third)
	if drop || originalDrop || h.dataSeen != 3 {
		t.Fatalf("third first-seen segment: drop=%v original=%v dataSeen=%d",
			drop, originalDrop, h.dataSeen)
	}

	h.StopDrops()
	drop, originalDrop = h.dataPacketDropDecisionLocked(second)
	if drop || originalDrop || h.dataSeen != 3 || h.retransmitCount != 2 {
		t.Fatalf("accepted retransmit of dropped segment: drop=%v original=%v dataSeen=%d retransmits=%d",
			drop, originalDrop, h.dataSeen, h.retransmitCount)
	}
}

func TestTcpHarnessNFQueueDropRetransmitCount(t *testing.T) {
	h := &NFQueueHelper{
		cfg: NFQueueConfig{
			DropRetransmitCount: 3,
		},
		dropDataPacketIndices: map[uint32]struct{}{1: {}},
		retransmitTargets:     make(map[uint32]uint32),
		seenDataSeqs:          make(map[uint32]struct{}),
		originalDroppedSeqs:   make(map[uint32]struct{}),
	}

	seg := PcapIPv4TCPPacket{Seq: 1000, PayloadLen: 100}

	// Original transmission is dropped and arms the retransmit counter.
	drop, originalDrop := h.dataPacketDropDecisionLocked(seg)
	if !drop || !originalDrop {
		t.Fatalf("original segment: drop=%v original=%v", drop, originalDrop)
	}

	// The next 3 retransmits of the same segment are dropped too.
	for i := 1; i <= 3; i++ {
		drop, originalDrop = h.dataPacketDropDecisionLocked(seg)
		if !drop || originalDrop {
			t.Fatalf("retransmit %d: drop=%v original=%v", i, drop, originalDrop)
		}
	}

	// The 4th retransmit is allowed through (counter exhausted).
	drop, originalDrop = h.dataPacketDropDecisionLocked(seg)
	if drop || originalDrop {
		t.Fatalf("retransmit past count should pass: drop=%v original=%v", drop, originalDrop)
	}
	if h.retransmitCount != 4 {
		t.Fatalf("expected 4 recorded retransmits, got %d", h.retransmitCount)
	}
}

func TestTcpHarnessBuildIPv4AckPacket(t *testing.T) {
	raw, err := buildIPv4AckPacket(net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.1"),
		1234, 40000, 5000, 1100, 2048,
		[]TcpTestEndpointSackBlock{
			{Left: 1200, Right: 1300},
			{Left: 1400, Right: 1500},
		})
	if err != nil {
		t.Fatalf("buildIPv4AckPacket failed: %v", err)
	}

	packet, ok := parseRawIPv4TCPPacket(raw)
	if !ok {
		t.Fatalf("failed to parse built packet")
	}
	if packet.SrcIP.String() != "10.0.0.2" ||
		packet.DstIP.String() != "10.0.0.1" ||
		packet.SrcPort != 1234 ||
		packet.DstPort != 40000 ||
		packet.Seq != 5000 ||
		packet.Ack != 1100 ||
		packet.Flags != tcpFlagAck ||
		packet.PayloadLen != 0 ||
		packet.SackBlocks != 2 ||
		!packet.IsSyntheticAck() {
		t.Fatalf("unexpected built packet: %+v", packet)
	}
}

func TestTcpHarnessRewriteIPv4TCPSynOptionsStripSackAndTimestamps(t *testing.T) {
	raw := buildTestIPv4TCPPacket(t, tcpFlagSyn, testSynOptions)
	rewritten, changed, err := rewriteIPv4TCPSynOptions(raw, SynOptionRewriteConfig{
		StripSackPermitted: true,
		StripTimestamps:    true,
	})
	if err != nil {
		t.Fatalf("rewrite failed: %v", err)
	}
	if !changed {
		t.Fatalf("expected SYN rewrite")
	}

	ipv4, tcp := decodedTestIPv4TCP(t, rewritten)
	if int(ipv4.Length) != len(rewritten) {
		t.Fatalf("IPv4 length = %d, want %d", ipv4.Length, len(rewritten))
	}
	if !tcp.SYN || tcp.ACK || len(tcp.Payload) != 0 {
		t.Fatalf("unexpected rewritten TCP flags/payload: %+v payload=%d",
			tcp, len(tcp.Payload))
	}
	if _, ok := testTCPOption(tcp, layers.TCPOptionKindSACKPermitted); ok {
		t.Fatalf("SACK-permitted option still present: %v", tcp.Options)
	}
	if _, ok := testTCPOption(tcp, layers.TCPOptionKindTimestamps); ok {
		t.Fatalf("timestamp option still present: %v", tcp.Options)
	}
	assertTestTCPOption(t, tcp, layers.TCPOptionKindMSS, []byte{0x05, 0xb4})
	assertTestTCPOption(t, tcp, layers.TCPOptionKindWindowScale, []byte{7})

	packet, ok := parseRawIPv4TCPPacket(rewritten)
	if !ok {
		t.Fatalf("rewritten packet did not parse")
	}
	if packet.Flags != tcpFlagSyn || packet.HasTSOpt || packet.SackBlocks != 0 {
		t.Fatalf("unexpected rewritten parsed packet: %+v", packet)
	}
}

func TestTcpHarnessRewriteIPv4TCPSynOptionsStripSackOnly(t *testing.T) {
	raw := buildTestIPv4TCPPacket(t, tcpFlagSyn, testSynOptions)
	rewritten, changed, err := rewriteIPv4TCPSynOptions(raw, SynOptionRewriteConfig{
		StripSackPermitted: true,
	})
	if err != nil {
		t.Fatalf("rewrite failed: %v", err)
	}
	if !changed {
		t.Fatalf("expected SYN rewrite")
	}

	_, tcp := decodedTestIPv4TCP(t, rewritten)
	if _, ok := testTCPOption(tcp, layers.TCPOptionKindSACKPermitted); ok {
		t.Fatalf("SACK-permitted option still present: %v", tcp.Options)
	}
	ts, ok := testTCPOption(tcp, layers.TCPOptionKindTimestamps)
	if !ok {
		t.Fatalf("timestamp option missing: %v", tcp.Options)
	}
	if got := binary.BigEndian.Uint32(ts.OptionData[:4]); got != 11 {
		t.Fatalf("timestamp tsval = %d, want 11", got)
	}
	assertTestTCPOption(t, tcp, layers.TCPOptionKindMSS, []byte{0x05, 0xb4})
	assertTestTCPOption(t, tcp, layers.TCPOptionKindWindowScale, []byte{7})
}

func TestTcpHarnessRewriteIPv4TCPSynOptionsStripTimestampsOnly(t *testing.T) {
	raw := buildTestIPv4TCPPacket(t, tcpFlagSyn, testSynOptions)
	rewritten, changed, err := rewriteIPv4TCPSynOptions(raw, SynOptionRewriteConfig{
		StripTimestamps: true,
	})
	if err != nil {
		t.Fatalf("rewrite failed: %v", err)
	}
	if !changed {
		t.Fatalf("expected SYN rewrite")
	}

	_, tcp := decodedTestIPv4TCP(t, rewritten)
	if _, ok := testTCPOption(tcp, layers.TCPOptionKindTimestamps); ok {
		t.Fatalf("timestamp option still present: %v", tcp.Options)
	}
	assertTestTCPOption(t, tcp, layers.TCPOptionKindSACKPermitted, nil)
	assertTestTCPOption(t, tcp, layers.TCPOptionKindMSS, []byte{0x05, 0xb4})
	assertTestTCPOption(t, tcp, layers.TCPOptionKindWindowScale, []byte{7})
}

func TestTcpHarnessRewriteIPv4TCPSynOptionsNoopCases(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		cfg  SynOptionRewriteConfig
	}{
		{
			name: "rewrite disabled",
			raw:  buildTestIPv4TCPPacket(t, tcpFlagSyn, testSynOptions),
			cfg:  SynOptionRewriteConfig{},
		},
		{
			name: "non syn",
			raw:  buildTestIPv4TCPPacket(t, tcpFlagAck, testSynOptions),
			cfg:  SynOptionRewriteConfig{StripSackPermitted: true, StripTimestamps: true},
		},
		{
			name: "syn ack",
			raw:  buildTestIPv4TCPPacket(t, tcpFlagSyn|tcpFlagAck, testSynOptions),
			cfg:  SynOptionRewriteConfig{StripSackPermitted: true, StripTimestamps: true},
		},
		{
			name: "option free syn",
			raw:  buildTestIPv4TCPPacket(t, tcpFlagSyn, nil),
			cfg:  SynOptionRewriteConfig{StripSackPermitted: true, StripTimestamps: true},
		},
		{
			name: "malformed",
			raw:  []byte{0x45, 0x00},
			cfg:  SynOptionRewriteConfig{StripSackPermitted: true, StripTimestamps: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rewritten, changed, err := rewriteIPv4TCPSynOptions(tt.raw, tt.cfg)
			if err != nil {
				t.Fatalf("rewrite failed: %v", err)
			}
			if changed {
				t.Fatalf("unexpected rewrite")
			}
			if !bytes.Equal(rewritten, tt.raw) {
				t.Fatalf("packet changed: got %v want %v", rewritten, tt.raw)
			}
		})
	}
}

func TestTcpHarnessFlowPacketAssertions(t *testing.T) {
	flow := NewFlow("10.0.0.1", "10.0.0.2", 1234)
	ts := time.Unix(0, 0)
	packets := []PcapIPv4TCPPacket{
		testPacket("10.0.0.1", "10.0.0.2", 40000, 1234,
			1000, 0, 100, tcpFlagAck, 0, ts),
		testPacket("10.0.0.2", "10.0.0.1", 1234, 40000,
			5000, 1000, 0, tcpFlagAck, 1, ts.Add(10*time.Millisecond)),
		testPacket("10.0.0.1", "10.0.0.2", 40000, 1234,
			1000, 0, 100, tcpFlagAck, 0, ts.Add(20*time.Millisecond)),
		testPacket("10.0.0.2", "10.0.0.1", 1234, 40000,
			5000, 1050, 0, tcpFlagAck, 2, ts.Add(30*time.Millisecond)),
		testPacket("10.0.0.1", "10.0.0.2", 40000, 1234,
			900, 0, 0, tcpFlagAck, 0, ts.Add(40*time.Millisecond)),
	}

	if got := flow.ServerSackCount(packets); got != 2 {
		t.Fatalf("ServerSackCount=%d, want 2", got)
	}
	if !flow.HasServerSackWithAtLeastBlocks(packets, 2) {
		t.Fatal("expected server SACK with at least 2 blocks")
	}
	if !flow.HasPartialServerSackAck(packets) {
		t.Fatal("expected partial server SACK ACK")
	}
	if !flow.HasSackDrivenClientRetransmit(packets, 25*time.Millisecond) {
		t.Fatal("expected SACK-driven client retransmit")
	}
	if !flow.HasOldSeqAckOnlyProbe(packets) {
		t.Fatal("expected old-seq ACK-only probe")
	}
}

func TestTcpHarnessFlowTimestampAssertions(t *testing.T) {
	flow := NewFlow("10.0.0.1", "10.0.0.2", 1234)
	packets := []PcapIPv4TCPPacket{
		{
			SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"),
			SrcPort: 40000, DstPort: 1234, Flags: tcpFlagSyn, HasTSOpt: true,
		},
		{
			SrcIP: net.ParseIP("10.0.0.2"), DstIP: net.ParseIP("10.0.0.1"),
			SrcPort: 1234, DstPort: 40000, Flags: tcpFlagSyn | tcpFlagAck,
		},
		{
			SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"),
			SrcPort: 40000, DstPort: 1234, Flags: tcpFlagAck, PayloadLen: 100,
		},
		{
			SrcIP: net.ParseIP("10.0.0.2"), DstIP: net.ParseIP("10.0.0.1"),
			SrcPort: 1234, DstPort: 40000, Flags: tcpFlagAck, HasTSOpt: true,
		},
		{
			SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"),
			SrcPort: 40000, DstPort: 1234, Flags: tcpFlagAck, HasTSOpt: true,
		},
	}

	if got := flow.ServerTimestampCount(packets); got != 1 {
		t.Fatalf("ServerTimestampCount=%d, want 1", got)
	}
	if got := flow.ClientEstablishedTimestampCount(packets); got != 1 {
		t.Fatalf("ClientEstablishedTimestampCount=%d, want 1", got)
	}
}

func TestTcpHarnessScriptStepConstructors(t *testing.T) {
	initial := InitialHolesSackStep(3, 4,
		WaitForDataSegments(6),
		DiscardQueuedAcks(),
		AdvanceScriptToDone())
	if initial.trigger != nfQueueScriptTriggerInitialHolesReady ||
		initial.holeCount != 3 ||
		initial.injectCount != 4 ||
		initial.minDataSegments != 6 ||
		!initial.stopIngressDrops ||
		initial.ackQueueDisposition != nfQueueAckQueueDispositionDiscardQueued ||
		!initial.advanceToDone {
		t.Fatalf("unexpected initial holes step: %+v", initial)
	}

	partial := RetransmitPartialAckStep(2, KeepQueuedAcks())
	if partial.trigger != nfQueueScriptTriggerRetransmitOfDroppedSeqObserved ||
		partial.holeCount != 0 ||
		partial.injectCount != 2 ||
		partial.minDataSegments != 0 ||
		partial.stopIngressDrops ||
		partial.ackQueueDisposition != nfQueueAckQueueDispositionKeepQueued ||
		partial.advanceToDone {
		t.Fatalf("unexpected partial ACK step: %+v", partial)
	}
}

func TestTcpHarnessScriptInitialHolesWaitsForDataSegments(t *testing.T) {
	state := newNFQueueScriptState(NFQueueScript([]uint32{2, 4},
		InitialHolesSackStep(2, 3,
			WaitForDataSegments(6),
			KeepQueuedAcks())))

	state.ApplyEvent(nfQueueScriptEvent{
		Role: nfQueueRoleEgress,
		Packet: testPacket("10.0.0.2", "10.0.0.1", 1234, 40000,
			5000, 1000, 0, tcpFlagAck, 0, time.Time{}),
	})

	events := []nfQueueScriptEvent{
		{Packet: PcapIPv4TCPPacket{Seq: 1000, PayloadLen: 100}},
		{Packet: PcapIPv4TCPPacket{Seq: 1100, PayloadLen: 100}, OriginalDrop: true},
		{Packet: PcapIPv4TCPPacket{Seq: 1200, PayloadLen: 100}},
		{Packet: PcapIPv4TCPPacket{Seq: 1300, PayloadLen: 100}, OriginalDrop: true},
		{Packet: PcapIPv4TCPPacket{Seq: 1400, PayloadLen: 100}},
	}
	for _, event := range events {
		action := state.ApplyEvent(event)
		if len(action.Injections) != 0 || action.StopIngressDrops {
			t.Fatalf("script fired before minimum data segments: action=%+v", action)
		}
	}

	action := state.ApplyEvent(nfQueueScriptEvent{
		Packet: PcapIPv4TCPPacket{Seq: 1500, PayloadLen: 100},
	})
	if !action.StopIngressDrops {
		t.Fatal("expected script to stop ingress drops after minimum data segments")
	}
	if len(action.Injections) != 1 {
		t.Fatalf("injection count=%d, want 1", len(action.Injections))
	}

	injection := action.Injections[0]
	if injection.Ack != 1100 || injection.Count != 3 {
		t.Fatalf("unexpected injection ack/count: %+v", injection)
	}
	if len(injection.SackBlocks) != 2 ||
		injection.SackBlocks[0].Left != 1200 ||
		injection.SackBlocks[0].Right != 1300 ||
		injection.SackBlocks[1].Left != 1400 ||
		injection.SackBlocks[1].Right != 1600 {
		t.Fatalf("unexpected SACK blocks: %+v", injection.SackBlocks)
	}
}

func TestTcpHarnessScriptInitialHolesAction(t *testing.T) {
	state := newNFQueueScriptState(NFQueueScript([]uint32{2, 4},
		InitialHolesSackStep(2, 3, KeepQueuedAcks())))

	state.ApplyEvent(nfQueueScriptEvent{
		Role: nfQueueRoleEgress,
		Packet: testPacket("10.0.0.2", "10.0.0.1", 1234, 40000,
			5000, 1000, 0, tcpFlagAck, 0, time.Time{}),
	})

	for _, event := range []nfQueueScriptEvent{
		{Packet: PcapIPv4TCPPacket{Seq: 1000, PayloadLen: 100}},
		{Packet: PcapIPv4TCPPacket{Seq: 1100, PayloadLen: 100}, OriginalDrop: true},
		{Packet: PcapIPv4TCPPacket{Seq: 1200, PayloadLen: 100}},
	} {
		state.ApplyEvent(event)
	}

	action := state.ApplyEvent(nfQueueScriptEvent{
		Packet:       PcapIPv4TCPPacket{Seq: 1300, PayloadLen: 100},
		OriginalDrop: true,
	})

	if !action.StopIngressDrops {
		t.Fatal("expected script to stop ingress drops")
	}
	if action.QueueDisposition != nfQueueAckQueueDispositionKeepQueued {
		t.Fatalf("QueueDisposition=%d, want keep queued", action.QueueDisposition)
	}
	if len(action.Injections) != 1 {
		t.Fatalf("injection count=%d, want 1", len(action.Injections))
	}

	injection := action.Injections[0]
	if injection.Ack != 1100 || injection.Count != 3 {
		t.Fatalf("unexpected injection ack/count: %+v", injection)
	}
	if len(injection.SackBlocks) != 1 ||
		injection.SackBlocks[0].Left != 1200 ||
		injection.SackBlocks[0].Right != 1300 {
		t.Fatalf("unexpected SACK blocks: %+v", injection.SackBlocks)
	}

	stats := state.Stats()
	if stats.Stage != NFQueueScriptStageDone ||
		stats.OriginalDropCount != 2 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}
