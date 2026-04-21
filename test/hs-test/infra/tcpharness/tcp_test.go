/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

package tcpharness

import (
	"net"
	"testing"
	"time"
)

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
			DropFirstRetransmitOfDrop: true,
		},
		dropDataPacketIndices: map[uint32]struct{}{2: {}},
		retransmitTargets:     make(map[uint32]struct{}),
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

func TestTcpHarnessScriptStepConstructors(t *testing.T) {
	initial := InitialHolesSackStep(3, 4,
		DiscardQueuedAcks(),
		AdvanceScriptToDone())
	if initial.trigger != nfQueueScriptTriggerInitialHolesReady ||
		initial.holeCount != 3 ||
		initial.injectCount != 4 ||
		!initial.stopIngressDrops ||
		initial.ackQueueDisposition != nfQueueAckQueueDispositionDiscardQueued ||
		!initial.advanceToDone {
		t.Fatalf("unexpected initial holes step: %+v", initial)
	}

	partial := RetransmitPartialAckStep(2, KeepQueuedAcks())
	if partial.trigger != nfQueueScriptTriggerRetransmitOfDroppedSeqObserved ||
		partial.holeCount != 0 ||
		partial.injectCount != 2 ||
		partial.stopIngressDrops ||
		partial.ackQueueDisposition != nfQueueAckQueueDispositionKeepQueued ||
		partial.advanceToDone {
		t.Fatalf("unexpected partial ACK step: %+v", partial)
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
