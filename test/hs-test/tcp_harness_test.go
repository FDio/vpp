package main

import (
	"sort"
	"strconv"
	"strings"
	"time"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterTcpHarnessTests(
		TcpWindowProbeLinuxTest,
		TcpFastRecoverySackSingleLossTest,
		TcpFastRecoveryLostRetransmitThenRtoTest,
		TcpTailLossTimerRecoveryTest,
		TcpFastRecoveryTwoHolesPartialAckTest,
		TcpSackScoreboardRobustnessTest,
	)
}

func hasOldSeqAckOnlyProbe(s *TcpHarnessSuite, vppName string,
	srcIP string, dstIP string, dstPort uint16) (bool, error) {
	packets, err := ReadPcapIPv4TCPPackets(s.GetPcapTracePath(vppName))
	if err != nil {
		return false, err
	}

	maxDataSeqEnd := uint32(0)

	for _, packet := range packets {
		if packet.SrcIP.String() != srcIP || packet.DstIP.String() != dstIP || packet.DstPort != dstPort {
			continue
		}

		if packet.PayloadLen > 0 {
			seqEnd := packet.Seq + uint32(packet.PayloadLen)
			if seqEnd > maxDataSeqEnd {
				maxDataSeqEnd = seqEnd
			}
			continue
		}

		if packet.IsAckOnly() && packet.Seq < maxDataSeqEnd {
			return true, nil
		}
	}

	return false, nil
}

func tcpHarnessPort(s *TcpHarnessSuite) uint16 {
	port, err := strconv.ParseUint(s.Ports.Port1, 10, 16)
	AssertNil(err)
	return uint16(port)
}

func countSackPacketsToPort(packets []PcapIPv4TCPPacket,
	srcIP string, dstIP string, srcPort uint16) int {
	count := 0

	for _, packet := range packets {
		if packet.SrcIP.String() != srcIP || packet.DstIP.String() != dstIP || packet.SrcPort != srcPort {
			continue
		}
		if packet.SackBlocks > 0 {
			count++
		}
	}

	return count
}

func hasSackWithAtLeastBlocksToPort(packets []PcapIPv4TCPPacket,
	srcIP string, dstIP string, srcPort uint16, minBlocks int) bool {
	for _, packet := range packets {
		if packet.SrcIP.String() != srcIP || packet.DstIP.String() != dstIP || packet.SrcPort != srcPort {
			continue
		}
		if packet.SackBlocks >= minBlocks {
			return true
		}
	}

	return false
}

type tcpHarnessDataSegment struct {
	Seq uint32
	End uint32
}

func clientDataSegmentsToPort(packets []PcapIPv4TCPPacket,
	clientIP string, serverIP string, serverPort uint16) []tcpHarnessDataSegment {
	seqEndByStart := make(map[uint32]uint32)

	for _, packet := range packets {
		if packet.SrcIP.String() != clientIP || packet.DstIP.String() != serverIP || packet.DstPort != serverPort {
			continue
		}
		if packet.PayloadLen == 0 {
			continue
		}

		end := packet.Seq + uint32(packet.PayloadLen)
		if prevEnd, ok := seqEndByStart[packet.Seq]; !ok || end > prevEnd {
			seqEndByStart[packet.Seq] = end
		}
	}

	segments := make([]tcpHarnessDataSegment, 0, len(seqEndByStart))
	for seq, end := range seqEndByStart {
		segments = append(segments, tcpHarnessDataSegment{
			Seq: seq,
			End: end,
		})
	}

	sort.Slice(segments, func(i, j int) bool {
		return segments[i].Seq < segments[j].Seq
	})

	return segments
}

func serverAckSeqToPort(packets []PcapIPv4TCPPacket,
	serverIP string, clientIP string, serverPort uint16) (uint32, bool) {
	var maxSeqEnd uint32
	var found bool

	for _, packet := range packets {
		if packet.SrcIP.String() != serverIP || packet.DstIP.String() != clientIP || packet.SrcPort != serverPort {
			continue
		}
		if packet.Flags&0x10 == 0 {
			continue
		}

		seqEnd := packet.SeqEnd()
		if !found || seqEnd > maxSeqEnd {
			maxSeqEnd = seqEnd
			found = true
		}
	}

	return maxSeqEnd, found
}

func serverAckNumberToPort(packets []PcapIPv4TCPPacket,
	serverIP string, clientIP string, serverPort uint16) (uint32, bool) {
	var maxAck uint32
	var found bool

	for _, packet := range packets {
		if packet.SrcIP.String() != serverIP || packet.DstIP.String() != clientIP || packet.SrcPort != serverPort {
			continue
		}
		if packet.Flags&0x10 == 0 {
			continue
		}
		if !found || packet.Ack > maxAck {
			maxAck = packet.Ack
			found = true
		}
	}

	return maxAck, found
}

func holeIndexesFromDropDataPacketIndices(segmentCount int, dropDataPacketIndices []uint32, maxHoles int) []int {
	holes := make([]int, 0, maxHoles)

	for _, packetIndex := range dropDataPacketIndices {
		if len(holes) >= maxHoles {
			break
		}

		idx := int(packetIndex) - 1
		if idx < 0 || idx >= segmentCount {
			continue
		}
		holes = append(holes, idx)
	}

	return holes
}

func buildDropDataPacketIndexSackPlan(segments []tcpHarnessDataSegment,
	dropDataPacketIndices []uint32, maxHoles int) (uint32, []TcpTestEndpointSackBlock, []int, bool) {
	holes := holeIndexesFromDropDataPacketIndices(len(segments), dropDataPacketIndices, maxHoles)
	if len(holes) == 0 {
		return 0, nil, nil, false
	}

	ack := segments[holes[0]].Seq
	sackBlocks := make([]TcpTestEndpointSackBlock, 0, len(holes))
	start := holes[0] + 1

	for i := 1; i < len(holes); i++ {
		if start < holes[i] {
			sackBlocks = append(sackBlocks, TcpTestEndpointSackBlock{
				Left:  segments[start].Seq,
				Right: segments[holes[i]].Seq,
			})
		}
		start = holes[i] + 1
	}

	if start < len(segments) {
		sackBlocks = append(sackBlocks, TcpTestEndpointSackBlock{
			Left:  segments[start].Seq,
			Right: segments[len(segments)-1].End,
		})
	}

	if len(sackBlocks) == 0 {
		return 0, nil, nil, false
	}

	return ack, sackBlocks, holes, true
}

func buildPartialAckPlan(segments []tcpHarnessDataSegment,
	holes []int) (uint32, []TcpTestEndpointSackBlock, bool) {
	if len(holes) < 2 {
		return 0, nil, false
	}

	secondHole := holes[1]
	if secondHole+1 >= len(segments) {
		return 0, nil, false
	}

	return segments[secondHole].Seq, []TcpTestEndpointSackBlock{{
		Left:  segments[secondHole+1].Seq,
		Right: segments[len(segments)-1].End,
	}}, true
}

func hasPartialSackAck(packets []PcapIPv4TCPPacket,
	clientIP string, serverIP string, serverPort uint16) bool {
	maxDataSeqEnd := uint32(0)
	minSackAck := uint32(0)
	sawSack := false

	for _, packet := range packets {
		if packet.SrcIP.String() != clientIP || packet.DstIP.String() != serverIP || packet.DstPort != serverPort {
			continue
		}
		if packet.PayloadLen == 0 {
			continue
		}

		seqEnd := packet.Seq + uint32(packet.PayloadLen)
		if seqEnd > maxDataSeqEnd {
			maxDataSeqEnd = seqEnd
		}
	}

	for _, packet := range packets {
		if packet.SrcIP.String() != serverIP || packet.DstIP.String() != clientIP || packet.SrcPort != serverPort {
			continue
		}
		if packet.SackBlocks == 0 {
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
		if packet.SrcIP.String() != serverIP || packet.DstIP.String() != clientIP || packet.SrcPort != serverPort {
			continue
		}
		if packet.SackBlocks == 0 {
			continue
		}
		if packet.Ack > minSackAck && packet.Ack < maxDataSeqEnd {
			return true
		}
	}

	return false
}

func hasSackDrivenRetransmit(packets []PcapIPv4TCPPacket,
	clientIP string, serverIP string, serverPort uint16, maxAfterSack time.Duration) bool {
	seenBeforeSack := make(map[uint32]struct{})
	lastSackAt := time.Time{}

	for _, packet := range packets {
		switch {
		case packet.SrcIP.String() == clientIP &&
			packet.DstIP.String() == serverIP &&
			packet.DstPort == serverPort &&
			packet.PayloadLen > 0:
			if lastSackAt.IsZero() {
				seenBeforeSack[packet.Seq] = struct{}{}
				continue
			}

			if _, ok := seenBeforeSack[packet.Seq]; ok &&
				!packet.Timestamp.Before(lastSackAt) &&
				packet.Timestamp.Sub(lastSackAt) <= maxAfterSack {
				return true
			}

		case packet.SrcIP.String() == serverIP &&
			packet.DstIP.String() == clientIP &&
			packet.SrcPort == serverPort &&
			packet.SackBlocks > 0:
			lastSackAt = packet.Timestamp
		}
	}

	return false
}

func assertTcpTestEndpointCommandOK(result TcpTestEndpointCommandResult) {
	AssertNil(result.Err, result.Out)
	AssertEqual("ok", strings.TrimSpace(result.Out))
}

func assertTcpTestEndpointCommandOKOrPipeClosed(result TcpTestEndpointCommandResult) {
	if result.Err == nil {
		AssertEqual("ok", strings.TrimSpace(result.Out))
		return
	}

	Log("tcp_test_endpoint client send control exited: %v", result.Err)
	AssertEqual(true, strings.Contains(result.Err.Error(), "exit status 141"),
		"expected tcp_test_endpoint control to either succeed or exit with SIGPIPE")
}

func TcpWindowProbeLinuxTest(s *TcpHarnessSuite) {
	const sendBytes = 256 << 10

	serverAddr := s.Interfaces.Server.Host.Ip4AddressString()
	var (
		serverStats      TcpTestEndpointStats
		finalServerStats TcpTestEndpointStats
		persistStats     TcpHarnessClientSessionStats
		sendHandle       TcpHarnessSendHandle
		sendResult       TcpTestEndpointCommandResult
	)

	defer s.StopTcpTestEndpoints()

	state := RunTcpHarnessScenario(s,
		StartClientPcap(),
		StartTcpTestEndpointServer(TcpTestEndpointServerConfig{
			Port:        s.Ports.Port1,
			ReceiveBuf:  4096,
			WindowClamp: 1024,
			PauseRead:   true,
		}),
		StartTcpTestEndpointClient(TcpTestEndpointClientConfig{}),
		WaitServerStats(5*time.Second, IsAccepted, &serverStats),
		StartClientSend(sendBytes, &sendHandle),
		WaitClientSessionStats(10*time.Second, HasRtoBackoffAtLeast(1), &persistStats),
		WaitServerStats(2*time.Second, BytesReadExactly(0), &serverStats),
		ServerCtl(TcpTestEndpointCtlResumeRead),
		WaitClientSend(&sendHandle, 20*time.Second, &sendResult),
		CloseTcpTestEndpointClient(),
		WaitServerStats(5*time.Second, PeerClosedAndBytesReadExactly(sendBytes), &finalServerStats),
		StopClientPcap(),
	)
	defer state.Close()

	AssertEqual(uint64(0), serverStats.BytesRead, "server should still be paused with no app reads")
	AssertGreaterEqual(persistStats.RtoBackoffCount, uint64(1))
	assertTcpTestEndpointCommandOKOrPipeClosed(sendResult)
	AssertEqual(uint64(sendBytes), finalServerStats.BytesRead)

	s.LogTcpTestEndpointLogs()

	probeSeen, err := hasOldSeqAckOnlyProbe(
		s,
		s.Containers.ClientVpp.Name,
		s.Interfaces.Client.Ip4AddressString(),
		serverAddr,
		tcpHarnessPort(s))
	AssertNil(err)
	AssertEqual(true, probeSeen, "expected an old-seq ACK-only window probe in client VPP pcap")
}

func TcpFastRecoverySackSingleLossTest(s *TcpHarnessSuite) {
	const sendBytes = 64 << 10
	dropDataPacketIndices := []uint32{6}

	clientAddr := s.Interfaces.Client.Ip4AddressString()
	serverAddr := s.Interfaces.Server.Host.Ip4AddressString()
	var (
		serverStats TcpTestEndpointStats
		clientStats TcpTestEndpointStats
		peerClosed  TcpTestEndpointStats
		sendHandle  TcpHarnessSendHandle
		sendResult  TcpTestEndpointCommandResult
		packets     []PcapIPv4TCPPacket
	)

	defer s.StopTcpTestEndpoints()
	state := RunTcpHarnessScenario(s,
		StartClientPcap(),
		StartTcpTestEndpointServer(TcpTestEndpointServerConfig{Port: s.Ports.Port1}),
		StartTcpTestEndpointClient(TcpTestEndpointClientConfig{}),
		WaitServerStats(5*time.Second, IsAccepted, &serverStats),
		EnableServerNFQueue(TcpHarnessNFQueueConfig{DropDataPacketIndices: dropDataPacketIndices}),
		StartClientSend(sendBytes, &sendHandle),
		WaitServerNFQueueDrops(10*time.Second, uint32(len(dropDataPacketIndices))),
		DisableServerNFQueue(),
		WaitServerStats(10*time.Second, BytesReadExactly(sendBytes), &serverStats),
		WaitClientSend(&sendHandle, 10*time.Second, &sendResult),
		WaitClientStats(5*time.Second, BytesSentExactly(sendBytes), &clientStats),
		CloseTcpTestEndpointClient(),
		WaitServerStats(5*time.Second, IsPeerClosed, &peerClosed),
		StopClientPcap(),
		ReadClientPcap(&packets),
	)
	defer state.Close()
	AssertEqual(uint64(sendBytes), serverStats.BytesRead)
	AssertEqual(true, peerClosed.PeerClosed)

	assertTcpTestEndpointCommandOKOrPipeClosed(sendResult)
	AssertEqual(uint64(sendBytes), clientStats.BytesSent)

	s.LogTcpTestEndpointLogs()

	sackCount := countSackPacketsToPort(packets, serverAddr, clientAddr, tcpHarnessPort(s))
	AssertGreaterEqual(sackCount, 1, "expected Linux receiver to send at least one SACK")
	AssertEqual(true, hasSackDrivenRetransmit(packets, clientAddr, serverAddr, tcpHarnessPort(s), 100*time.Millisecond),
		"expected VPP sender to retransmit previously-sent data promptly after a SACK")
}

func TcpFastRecoveryLostRetransmitThenRtoTest(s *TcpHarnessSuite) {
	dropDataPacketIndices := []uint32{2}

	clientAddr := s.Interfaces.Client.Ip4AddressString()
	serverAddr := s.Interfaces.Server.Host.Ip4AddressString()
	var (
		mssStats           TcpHarnessClientSessionStats
		serverStats        TcpTestEndpointStats
		clientStats        TcpTestEndpointStats
		peerClosed         TcpTestEndpointStats
		sessionStats       TcpHarnessClientSessionStats
		finalSessionOutput string
		sendHandle         TcpHarnessSendHandle
		sendResult         TcpTestEndpointCommandResult
		packets            []PcapIPv4TCPPacket
	)

	defer s.StopTcpTestEndpoints()

	state := RunTcpHarnessScenario(s,
		StartClientPcap(),
		StartTcpTestEndpointServer(TcpTestEndpointServerConfig{Port: s.Ports.Port1}),
		StartTcpTestEndpointClient(TcpTestEndpointClientConfig{}),
		WaitServerStats(5*time.Second, IsAccepted, &serverStats),
		WaitClientSessionStats(5*time.Second, HasSndMss, &mssStats),
	)

	sendBytes := 5 * mssStats.SndMss

	RunTcpHarnessScenarioOnState(s, state,
		EnableServerNFQueue(TcpHarnessNFQueueConfig{
			DropDataPacketIndices:     dropDataPacketIndices,
			DropFirstRetransmitOfDrop: true,
		}),
		StartClientSend(sendBytes, &sendHandle),
		WaitServerNFQueueDrops(20*time.Second, 2),
		DisableServerNFQueue(),
		WaitClientSessionStats(20*time.Second, HasFastAndTimerRecovery(2), &sessionStats),
		WaitServerStats(20*time.Second, BytesReadExactly(sendBytes), &serverStats),
		WaitClientSend(&sendHandle, 20*time.Second, &sendResult),
		WaitClientStats(5*time.Second, BytesSentExactly(sendBytes), &clientStats),
	)

	RunTcpHarnessScenarioOnState(s, state,
		CloseTcpTestEndpointClient(),
		WaitServerStats(5*time.Second, IsPeerClosed, &peerClosed),
		StopClientPcap(),
		ReadClientPcap(&packets),
	)
	defer state.Close()

	finalSessionOutput = s.ShowClientVppSessions(2)

	AssertEqual(uint64(sendBytes), serverStats.BytesRead)
	assertTcpTestEndpointCommandOKOrPipeClosed(sendResult)
	AssertEqual(uint64(sendBytes), clientStats.BytesSent)
	AssertEqual(true, peerClosed.PeerClosed)
	Log(sessionStats.Output)
	Log("final client show session verbose 2:\n%s", finalSessionOutput)

	s.LogTcpTestEndpointLogs()

	sackCount := countSackPacketsToPort(packets, serverAddr, clientAddr, tcpHarnessPort(s))
	AssertGreaterEqual(sackCount, 1, "expected Linux receiver to send at least one SACK")
	AssertEqual(true, hasSackDrivenRetransmit(packets, clientAddr, serverAddr,
		tcpHarnessPort(s), 200*time.Millisecond),
		"expected VPP sender to retransmit previously-sent data promptly after a SACK")
	AssertGreaterEqual(sessionStats.FastRecoveryCount, uint64(1),
		"expected client VPP session stats to record fast recovery")
	AssertGreaterEqual(sessionStats.TimerRecoveryCount, uint64(1),
		"expected client VPP session stats to record timer recovery")
	AssertGreaterEqual(sessionStats.RetransmitSegsCount, uint64(2),
		"expected client VPP session stats to record both fast and timer retransmissions")
}

func TcpTailLossTimerRecoveryTest(s *TcpHarnessSuite) {
	dropDataPacketIndices := []uint32{1}
	clientAddr := s.Interfaces.Client.Ip4AddressString()
	serverAddr := s.Interfaces.Server.Host.Ip4AddressString()
	var (
		mssStats      TcpHarnessClientSessionStats
		serverStats   TcpTestEndpointStats
		clientStats   TcpTestEndpointStats
		peerClosed    TcpTestEndpointStats
		sessionStats  TcpHarnessClientSessionStats
		initialSend   TcpHarnessSendHandle
		sendHandle    TcpHarnessSendHandle
		initialResult TcpTestEndpointCommandResult
		sendResult    TcpTestEndpointCommandResult
		packets       []PcapIPv4TCPPacket
	)

	defer s.StopTcpTestEndpoints()

	state := RunTcpHarnessScenario(s,
		StartClientPcap(),
		StartTcpTestEndpointServer(TcpTestEndpointServerConfig{Port: s.Ports.Port1}),
		StartTcpTestEndpointClient(TcpTestEndpointClientConfig{}),
		WaitServerStats(5*time.Second, IsAccepted, &serverStats),
		WaitClientSessionStats(5*time.Second, HasSndMss, &mssStats),
	)
	defer state.Close()

	mss := mssStats.SndMss
	initialBytes := 9 * mss
	sendBytes := 10 * mss

	RunTcpHarnessScenarioOnState(s, state,
		StartClientSend(initialBytes, &initialSend),
		WaitServerStats(10*time.Second, BytesReadExactly(initialBytes), &serverStats),
		WaitClientSend(&initialSend, 10*time.Second, &initialResult),
		EnableServerNFQueue(TcpHarnessNFQueueConfig{DropDataPacketIndices: dropDataPacketIndices}),
		StartClientSend(mss, &sendHandle),
		WaitServerNFQueueDrops(10*time.Second, uint32(len(dropDataPacketIndices))),
		DisableServerNFQueue(),
		WaitClientSessionStats(20*time.Second, HasTimerRecoveryOnly(1), &sessionStats),
		WaitServerStats(20*time.Second, BytesReadExactly(sendBytes), &serverStats),
		WaitClientSend(&sendHandle, 20*time.Second, &sendResult),
		WaitClientStats(5*time.Second, BytesSentExactly(sendBytes), &clientStats),
		CloseTcpTestEndpointClient(),
		WaitServerStats(5*time.Second, IsPeerClosed, &peerClosed),
		StopClientPcap(),
		ReadClientPcap(&packets),
	)

	AssertEqual(sendBytes, serverStats.BytesRead)
	assertTcpTestEndpointCommandOKOrPipeClosed(initialResult)
	assertTcpTestEndpointCommandOKOrPipeClosed(sendResult)
	AssertEqual(sendBytes, clientStats.BytesSent)
	AssertEqual(true, peerClosed.PeerClosed)
	Log(sessionStats.Output)

	s.LogTcpTestEndpointLogs()

	sackCount := countSackPacketsToPort(packets, serverAddr, clientAddr, tcpHarnessPort(s))
	AssertEqual(0, sackCount, "expected no SACKs for pure tail-loss timer recovery")
	AssertEqual(uint64(0), sessionStats.FastRecoveryCount,
		"expected client VPP session stats to avoid fast recovery")
	AssertGreaterEqual(sessionStats.TimerRecoveryCount, uint64(1),
		"expected client VPP session stats to record timer recovery")
	AssertGreaterEqual(sessionStats.RetransmitSegsCount, uint64(1),
		"expected client VPP session stats to record retransmissions")
}

func TcpFastRecoveryTwoHolesPartialAckTest(s *TcpHarnessSuite) {
	dropDataPacketIndices := []uint32{3, 6}
	clientAddr := s.Interfaces.Client.Ip4AddressString()
	serverAddr := s.Interfaces.Server.Host.Ip4AddressString()
	var (
		mssStats     TcpHarnessClientSessionStats
		serverStats  TcpTestEndpointStats
		clientStats  TcpTestEndpointStats
		peerClosed   TcpTestEndpointStats
		fastRtxStats TcpHarnessClientSessionStats
		sessionStats TcpHarnessClientSessionStats
		sendHandle   TcpHarnessSendHandle
		sendResult   TcpTestEndpointCommandResult
		livePackets  []PcapIPv4TCPPacket
		packets      []PcapIPv4TCPPacket
		serverSeq    uint32
		partialAck   uint32
		initialSack  []TcpTestEndpointSackBlock
		partialSack  []TcpTestEndpointSackBlock
		currentAck   uint32
		ok           bool
	)

	defer s.StopTcpTestEndpoints()

	state := RunTcpHarnessScenario(s,
		StartClientPcap(),
		StartTcpTestEndpointServer(TcpTestEndpointServerConfig{Port: s.Ports.Port1}),
		StartTcpTestEndpointClient(TcpTestEndpointClientConfig{}),
		WaitServerStats(5*time.Second, IsAccepted, &serverStats),
		WaitClientSessionStats(5*time.Second, HasSndMss, &mssStats),
	)
	defer state.Close()

	sendBytes := 8 * mssStats.SndMss

	RunTcpHarnessScenarioOnState(s, state,
		EnableServerNFQueue(TcpHarnessNFQueueConfig{DropDataPacketIndices: dropDataPacketIndices}),
		StartClientSend(sendBytes, &sendHandle),
		WaitServerNFQueueDrops(10*time.Second, uint32(len(dropDataPacketIndices))),
		DisableServerNFQueue(),
		StopClientPcap(),
		ReadClientPcap(&livePackets),
	)

	segments := clientDataSegmentsToPort(livePackets, clientAddr, serverAddr, tcpHarnessPort(s))
	AssertGreaterEqual(len(segments), 8, "expected at least 8 unique client data segments in initial pcap")
	serverSeq, ok = serverAckSeqToPort(livePackets, serverAddr, clientAddr, tcpHarnessPort(s))
	AssertEqual(true, ok, "expected a server ACK sequence in the live client VPP pcap")
	currentAck, ok = serverAckNumberToPort(livePackets, serverAddr, clientAddr, tcpHarnessPort(s))
	AssertEqual(true, ok, "expected a server ACK number in the live client VPP pcap")

	_, initialSack, holes, ok := buildDropDataPacketIndexSackPlan(segments, dropDataPacketIndices, 2)
	AssertEqual(true, ok, "expected to derive a two-hole SACK plan from the first 8 data segments")
	partialAck, partialSack, ok = buildPartialAckPlan(segments, holes)
	AssertEqual(true, ok, "expected to derive a partial-ACK plan from the first 8 data segments")

	RunTcpHarnessScenarioOnState(s, state,
		StartClientPcap(),
	)

	AssertEqual("ok", s.WaitForTcpTestEndpointServerCtl(
		TcpTestEndpointCtlInjectAck(serverSeq, currentAck, 65535, initialSack...), 2*time.Second))

	RunTcpHarnessScenarioOnState(s, state,
		WaitClientSessionStats(10*time.Second, func(stats TcpHarnessClientSessionStats) bool {
			return stats.FastRecoveryCount > 0 && stats.RetransmitSegsCount >= 1
		}, &fastRtxStats),
	)

	AssertEqual("ok", s.WaitForTcpTestEndpointServerCtl(
		TcpTestEndpointCtlInjectAck(serverSeq, partialAck, 65535, partialSack...), 2*time.Second))

	RunTcpHarnessScenarioOnState(s, state,
		WaitClientSessionStats(20*time.Second, HasFastRecoveryOnly(2), &sessionStats),
		WaitServerStats(20*time.Second, BytesReadExactly(sendBytes), &serverStats),
		WaitClientSend(&sendHandle, 20*time.Second, &sendResult),
		WaitClientStats(5*time.Second, BytesSentExactly(sendBytes), &clientStats),
		CloseTcpTestEndpointClient(),
		WaitServerStats(5*time.Second, IsPeerClosed, &peerClosed),
		StopClientPcap(),
		ReadClientPcap(&packets),
	)

	AssertEqual(sendBytes, serverStats.BytesRead)
	assertTcpTestEndpointCommandOKOrPipeClosed(sendResult)
	AssertEqual(sendBytes, clientStats.BytesSent)
	AssertEqual(true, peerClosed.PeerClosed)
	Log(sessionStats.Output)

	s.LogTcpTestEndpointLogs()

	sackCount := countSackPacketsToPort(packets, serverAddr, clientAddr, tcpHarnessPort(s))
	allPackets := append(append([]PcapIPv4TCPPacket(nil), livePackets...), packets...)
	AssertGreaterEqual(sackCount, 2, "expected crafted or Linux receiver SACKs across the two holes")
	AssertEqual(true, hasPartialSackAck(allPackets, clientAddr, serverAddr, tcpHarnessPort(s)),
		"expected a partial ACK while another SACKed hole remained")
	AssertGreaterEqual(sessionStats.FastRecoveryCount, uint64(1),
		"expected client VPP session stats to use fast recovery")
	AssertEqual(uint64(0), sessionStats.TimerRecoveryCount,
		"expected client VPP session stats to avoid timer recovery")
	AssertGreaterEqual(sessionStats.RetransmitSegsCount, uint64(2),
		"expected client VPP session stats to retransmit at least two segments")
}

func TcpSackScoreboardRobustnessTest(s *TcpHarnessSuite) {
	const sendBytes = 64 << 10
	dropDataPacketIndices := []uint32{4, 8, 12, 16}

	clientAddr := s.Interfaces.Client.Ip4AddressString()
	serverAddr := s.Interfaces.Server.Host.Ip4AddressString()
	var (
		serverStats  TcpTestEndpointStats
		clientStats  TcpTestEndpointStats
		peerClosed   TcpTestEndpointStats
		sessionStats TcpHarnessClientSessionStats
		sendHandle   TcpHarnessSendHandle
		sendResult   TcpTestEndpointCommandResult
		livePackets  []PcapIPv4TCPPacket
		packets      []PcapIPv4TCPPacket
		serverSeq    uint32
		currentAck   uint32
		initialSack  []TcpTestEndpointSackBlock
		ok           bool
	)

	defer s.StopTcpTestEndpoints()

	state := RunTcpHarnessScenario(s,
		StartClientPcap(),
		StartTcpTestEndpointServer(TcpTestEndpointServerConfig{Port: s.Ports.Port1}),
		StartTcpTestEndpointClient(TcpTestEndpointClientConfig{}),
		WaitServerStats(5*time.Second, IsAccepted, &serverStats),
		EnableServerNFQueue(TcpHarnessNFQueueConfig{DropDataPacketIndices: dropDataPacketIndices}),
		StartClientSend(sendBytes, &sendHandle),
		WaitServerNFQueueDrops(10*time.Second, uint32(len(dropDataPacketIndices))),
		DisableServerNFQueue(),
		StopClientPcap(),
		ReadClientPcap(&livePackets),
	)

	segments := clientDataSegmentsToPort(livePackets, clientAddr, serverAddr, tcpHarnessPort(s))
	AssertGreaterEqual(len(segments), 12,
		"expected at least 12 unique client data segments in initial pcap")
	serverSeq, ok = serverAckSeqToPort(livePackets, serverAddr, clientAddr, tcpHarnessPort(s))
	AssertEqual(true, ok, "expected a server ACK sequence in the live client VPP pcap")
	currentAck, ok = serverAckNumberToPort(livePackets, serverAddr, clientAddr, tcpHarnessPort(s))
	AssertEqual(true, ok, "expected a server ACK number in the live client VPP pcap")
	_, initialSack, _, ok = buildDropDataPacketIndexSackPlan(segments, dropDataPacketIndices, 4)
	AssertEqual(true, ok, "expected to derive a multi-hole scoreboard SACK plan from the live data segments")

	RunTcpHarnessScenarioOnState(s, state,
		StartClientPcap(),
	)

	AssertEqual("ok", s.WaitForTcpTestEndpointServerCtl(
		TcpTestEndpointCtlInjectAck(serverSeq, currentAck, 65535, initialSack...), 2*time.Second))

	RunTcpHarnessScenarioOnState(s, state,
		WaitClientSessionStats(10*time.Second, func(stats TcpHarnessClientSessionStats) bool {
			return stats.FastRecoveryCount > 0 && stats.RetransmitSegsCount >= 1
		}, &sessionStats),
		WaitServerStats(20*time.Second, BytesReadExactly(sendBytes), &serverStats),
		WaitClientSend(&sendHandle, 20*time.Second, &sendResult),
		WaitClientStats(5*time.Second, BytesSentExactly(sendBytes), &clientStats),
	)

	RunTcpHarnessScenarioOnState(s, state,
		CloseTcpTestEndpointClient(),
		WaitServerStats(5*time.Second, IsPeerClosed, &peerClosed),
		StopClientPcap(),
		ReadClientPcap(&packets),
	)
	defer state.Close()

	AssertEqual(uint64(sendBytes), serverStats.BytesRead)
	assertTcpTestEndpointCommandOK(sendResult)
	AssertEqual(uint64(sendBytes), clientStats.BytesSent)
	AssertEqual(true, peerClosed.PeerClosed)
	Log(sessionStats.Output)

	s.LogTcpTestEndpointLogs()

	combinedPackets := append(append([]PcapIPv4TCPPacket{}, livePackets...), packets...)
	sackCount := countSackPacketsToPort(combinedPackets, serverAddr, clientAddr, tcpHarnessPort(s))
	AssertGreaterEqual(sackCount, 2, "expected crafted or Linux receiver SACKs for scoreboard stress")
	AssertEqual(true, hasSackWithAtLeastBlocksToPort(combinedPackets, serverAddr, clientAddr,
		tcpHarnessPort(s), len(initialSack)),
		"expected to observe the crafted multi-block SACK on the wire")
	AssertEqual(true, hasSackDrivenRetransmit(combinedPackets, clientAddr, serverAddr,
		tcpHarnessPort(s), 200*time.Millisecond),
		"expected VPP sender to retransmit previously-sent data after the scoreboard-driving SACK")
	AssertGreaterEqual(sessionStats.FastRecoveryCount, uint64(1),
		"expected client VPP session stats to record fast recovery")
	AssertGreaterEqual(sessionStats.RetransmitSegsCount, uint64(1),
		"expected client VPP session stats to record retransmissions")
	AssertEqual(false, sessionStats.IsReneging,
		"expected client VPP session stats to avoid SACK reneging")
}
