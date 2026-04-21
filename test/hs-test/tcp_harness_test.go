package main

import (
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

func requiredSegmentCountForDropDataPacketIndices(dropDataPacketIndices []uint32) int {
	maxIndex := uint32(0)

	for _, packetIndex := range dropDataPacketIndices {
		if packetIndex > maxIndex {
			maxIndex = packetIndex
		}
	}
	if maxIndex == 0 {
		return 0
	}

	return int(maxIndex + 1)
}

func buildDropDataPacketIndexSackPlan(segments []TcpHarnessDataSegment,
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

func buildPartialAckPlan(segments []TcpHarnessDataSegment,
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

func injectServerAckRepeated(s *TcpHarnessSuite, count int, ack uint32, window uint16,
	sackBlocks ...TcpTestEndpointSackBlock) {
	for i := 0; i < count; i++ {
		s.InjectServerAck(ack, window, sackBlocks...)
		time.Sleep(10 * time.Millisecond)
	}
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
	dropDataPacketIndices := []uint32{2, 4}
	clientAddr := s.Interfaces.Client.Ip4AddressString()
	serverAddr := s.Interfaces.Server.Host.Ip4AddressString()
	var (
		mssStats     TcpHarnessClientSessionStats
		serverStats  TcpTestEndpointStats
		clientStats  TcpTestEndpointStats
		peerClosed   TcpTestEndpointStats
		fastRtxStats TcpHarnessClientSessionStats
		sessionStats TcpHarnessClientSessionStats
		warmupHandle TcpHarnessSendHandle
		sendHandle   TcpHarnessSendHandle
		warmupResult TcpTestEndpointCommandResult
		sendResult   TcpTestEndpointCommandResult
		packets      []PcapIPv4TCPPacket
		initialAck   uint32
		initialSack  []TcpTestEndpointSackBlock
		partialAck   uint32
		partialSack  []TcpTestEndpointSackBlock
	)

	defer s.StopTcpTestEndpoints()

	state := RunTcpHarnessScenario(s,
		StartTcpTestEndpointServer(TcpTestEndpointServerConfig{Port: s.Ports.Port1}),
		StartTcpTestEndpointClient(TcpTestEndpointClientConfig{}),
		StartClientPcap(),
		WaitServerStats(5*time.Second, IsAccepted, &serverStats),
		WaitClientSessionStats(5*time.Second, HasSndMss, &mssStats),
	)
	defer state.Close()

	warmupBytes := 2 * mssStats.SndMss
	controlledBytes := 6 * mssStats.SndMss
	sendBytes := warmupBytes + controlledBytes

	RunTcpHarnessScenarioOnState(s, state,
		StartClientSend(warmupBytes, &warmupHandle),
		WaitServerStats(10*time.Second, BytesReadExactly(warmupBytes), &serverStats),
		WaitClientSend(&warmupHandle, 10*time.Second, &warmupResult),
		EnableServerAckGate(),
		EnableServerNFQueue(TcpHarnessNFQueueConfig{DropDataPacketIndices: dropDataPacketIndices}),
		StartClientSend(controlledBytes, &sendHandle),
		WaitServerNFQueueDrops(10*time.Second, uint32(len(dropDataPacketIndices))),
		WaitServerAckGateDrops(10*time.Second, 1),
	)

	segments := s.ServerNFQueueSegments()
	AssertGreaterEqual(len(segments), requiredSegmentCountForDropDataPacketIndices(dropDataPacketIndices),
		"expected enough client data segments in NFQUEUE state to cover the two-hole plan")

	stateAck := s.ServerAckGateState()
	AssertEqual(true, stateAck.Valid, "expected server ACK-gate state to track blocked Linux ACKs")
	initialAck = stateAck.Ack
	_, initialSack, holes, ok := buildDropDataPacketIndexSackPlan(segments, dropDataPacketIndices, 2)
	AssertEqual(true, ok, "expected to derive a two-hole SACK plan from NFQUEUE segments")
	partialAck, partialSack, ok = buildPartialAckPlan(segments, holes)
	AssertEqual(true, ok, "expected to derive a partial-ACK plan from NFQUEUE segments")

	s.DisableServerNFQueue()
	injectServerAckRepeated(s, 3, initialAck, 65535, initialSack...)

	RunTcpHarnessScenarioOnState(s, state,
		WaitClientSessionStats(10*time.Second, func(stats TcpHarnessClientSessionStats) bool {
			return stats.FastRecoveryCount > 0 && stats.RetransmitSegsCount >= 1
		}, &fastRtxStats),
	)

	injectServerAckRepeated(s, 2, partialAck, 65535, partialSack...)
	s.DisableServerAckGate()

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
	assertTcpTestEndpointCommandOKOrPipeClosed(warmupResult)
	assertTcpTestEndpointCommandOKOrPipeClosed(sendResult)
	AssertEqual(sendBytes, clientStats.BytesSent)
	AssertEqual(true, peerClosed.PeerClosed)
	Log(sessionStats.Output)

	s.LogTcpTestEndpointLogs()

	sackCount := countSackPacketsToPort(packets, serverAddr, clientAddr, tcpHarnessPort(s))
	AssertGreaterEqual(sackCount, 2, "expected crafted or Linux receiver SACKs across the two holes")
	AssertEqual(true, hasPartialSackAck(packets, clientAddr, serverAddr, tcpHarnessPort(s)),
		"expected a partial ACK while another SACKed hole remained")
	AssertGreaterEqual(sessionStats.FastRecoveryCount, uint64(1),
		"expected client VPP session stats to use fast recovery")
	AssertEqual(uint64(0), sessionStats.TimerRecoveryCount,
		"expected client VPP session stats to avoid timer recovery")
	AssertGreaterEqual(sessionStats.RetransmitSegsCount, uint64(2),
		"expected client VPP session stats to retransmit at least two segments")
}

func TcpSackScoreboardRobustnessTest(s *TcpHarnessSuite) {
	dropDataPacketIndices := []uint32{2, 4, 6}

	clientAddr := s.Interfaces.Client.Ip4AddressString()
	serverAddr := s.Interfaces.Server.Host.Ip4AddressString()
	var (
		mssStats     TcpHarnessClientSessionStats
		serverStats  TcpTestEndpointStats
		clientStats  TcpTestEndpointStats
		peerClosed   TcpTestEndpointStats
		sessionStats TcpHarnessClientSessionStats
		warmupHandle TcpHarnessSendHandle
		sendHandle   TcpHarnessSendHandle
		warmupResult TcpTestEndpointCommandResult
		sendResult   TcpTestEndpointCommandResult
		packets      []PcapIPv4TCPPacket
		initialAck   uint32
		initialSack  []TcpTestEndpointSackBlock
	)

	defer s.StopTcpTestEndpoints()

	state := RunTcpHarnessScenario(s,
		StartTcpTestEndpointServer(TcpTestEndpointServerConfig{Port: s.Ports.Port1}),
		StartTcpTestEndpointClient(TcpTestEndpointClientConfig{}),
		StartClientPcap(),
		WaitServerStats(5*time.Second, IsAccepted, &serverStats),
		WaitClientSessionStats(5*time.Second, HasSndMss, &mssStats),
	)
	defer state.Close()

	warmupBytes := 4 * mssStats.SndMss
	controlledBytes := 8 * mssStats.SndMss
	sendBytes := warmupBytes + controlledBytes

	RunTcpHarnessScenarioOnState(s, state,
		StartClientSend(warmupBytes, &warmupHandle),
		WaitServerStats(10*time.Second, BytesReadExactly(warmupBytes), &serverStats),
		WaitClientSend(&warmupHandle, 10*time.Second, &warmupResult),
		EnableServerAckGate(),
		EnableServerNFQueue(TcpHarnessNFQueueConfig{DropDataPacketIndices: dropDataPacketIndices}),
		StartClientSend(controlledBytes, &sendHandle),
		WaitServerNFQueueDrops(10*time.Second, uint32(len(dropDataPacketIndices))),
		WaitServerAckGateDrops(10*time.Second, 1),
	)

	segments := s.ServerNFQueueSegments()
	AssertGreaterEqual(len(segments), requiredSegmentCountForDropDataPacketIndices(dropDataPacketIndices),
		"expected enough client data segments in NFQUEUE state to cover the scoreboard plan")
	stateAck := s.ServerAckGateState()
	AssertEqual(true, stateAck.Valid, "expected server ACK-gate state to track blocked Linux ACKs")
	initialAck = stateAck.Ack
	_, initialSack, _, ok := buildDropDataPacketIndexSackPlan(segments, dropDataPacketIndices,
		len(dropDataPacketIndices))
	AssertEqual(true, ok, "expected to derive a multi-hole scoreboard SACK plan from NFQUEUE segments")

	s.DisableServerNFQueue()
	injectServerAckRepeated(s, 3, initialAck, 65535, initialSack...)
	s.DisableServerAckGate()

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

	AssertEqual(sendBytes, serverStats.BytesRead)
	assertTcpTestEndpointCommandOKOrPipeClosed(warmupResult)
	assertTcpTestEndpointCommandOKOrPipeClosed(sendResult)
	AssertEqual(sendBytes, clientStats.BytesSent)
	AssertEqual(true, peerClosed.PeerClosed)
	Log(sessionStats.Output)

	s.LogTcpTestEndpointLogs()

	sackCount := countSackPacketsToPort(packets, serverAddr, clientAddr, tcpHarnessPort(s))
	AssertGreaterEqual(sackCount, 2, "expected crafted or Linux receiver SACKs for scoreboard stress")
	AssertEqual(true, hasSackWithAtLeastBlocksToPort(packets, serverAddr, clientAddr,
		tcpHarnessPort(s), len(initialSack)),
		"expected to observe the crafted multi-block SACK on the wire")
	AssertEqual(true, hasSackDrivenRetransmit(packets, clientAddr, serverAddr,
		tcpHarnessPort(s), 200*time.Millisecond),
		"expected VPP sender to retransmit previously-sent data after the scoreboard-driving SACK")
	AssertGreaterEqual(sessionStats.FastRecoveryCount, uint64(1),
		"expected client VPP session stats to record fast recovery")
	AssertGreaterEqual(sessionStats.RetransmitSegsCount, uint64(1),
		"expected client VPP session stats to record retransmissions")
	AssertEqual(false, sessionStats.IsReneging,
		"expected client VPP session stats to avoid SACK reneging")
}
