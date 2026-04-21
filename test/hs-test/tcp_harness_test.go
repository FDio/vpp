/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

package main

import (
	"strings"
	"time"

	. "fd.io/hs-test/infra"
	tcpharness "fd.io/hs-test/infra/tcpharness"
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
	AssertContains(result.Err.Error(), "exit status 141",
		"expected tcp_test_endpoint control to either succeed or exit with SIGPIPE")
}

func TcpWindowProbeLinuxTest(s *TcpHarnessSuite) {
	const (
		sendBytes              = 256 << 10
		acceptTimeout          = 10 * time.Second
		persistTimeout         = 20 * time.Second
		pausedStatsTimeout     = 5 * time.Second
		finalServerReadTimeout = 20 * time.Second
	)

	var (
		serverStats      TcpTestEndpointStats
		finalServerStats TcpTestEndpointStats
		persistStats     TcpHarnessClientSessionStats
		sendHandle       TcpHarnessSendHandle
		sendResult       TcpTestEndpointCommandResult
		packets          []tcpharness.PcapIPv4TCPPacket
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
		WaitServerStats(acceptTimeout, IsAccepted, &serverStats),
		StartClientSend(sendBytes, &sendHandle),
		WaitClientSessionStats(persistTimeout, HasRtoBackoffAtLeast(1), &persistStats),
		WaitServerStats(pausedStatsTimeout, BytesReadExactly(0), &serverStats),
		ServerCtl(TcpTestEndpointCtlResumeRead),
		WaitClientSend(&sendHandle, 20*time.Second, &sendResult),
		CloseTcpTestEndpointClient(),
		WaitServerStats(finalServerReadTimeout,
			PeerClosedAndBytesReadExactly(sendBytes), &finalServerStats),
		StopClientPcap(),
		ReadClientPcap(&packets),
	)
	defer state.Close()

	AssertEqual(uint64(0), serverStats.BytesRead, "server should still be paused with no app reads")
	AssertGreaterEqual(persistStats.RtoBackoffCount, uint64(1))
	assertTcpTestEndpointCommandOKOrPipeClosed(sendResult)
	AssertEqual(uint64(sendBytes), finalServerStats.BytesRead)

	s.LogTcpTestEndpointLogs()

	AssertEqual(true, s.ClientServerFlow().HasOldSeqAckOnlyProbe(packets),
		"expected an old-seq ACK-only window probe in client VPP pcap")
}

func TcpFastRecoverySackSingleLossTest(s *TcpHarnessSuite) {
	const sendBytes = 64 << 10
	dropDataPacketIndices := []uint32{6}

	var (
		serverStats  TcpTestEndpointStats
		clientStats  TcpTestEndpointStats
		peerClosed   TcpTestEndpointStats
		nfQueueStats tcpharness.NFQueueStats
		sendHandle   TcpHarnessSendHandle
		sendResult   TcpTestEndpointCommandResult
		packets      []tcpharness.PcapIPv4TCPPacket
	)

	defer s.StopTcpTestEndpoints()
	state := RunTcpHarnessScenario(s,
		StartClientPcap(),
		StartTcpTestEndpointServer(TcpTestEndpointServerConfig{Port: s.Ports.Port1}),
		StartTcpTestEndpointClient(TcpTestEndpointClientConfig{}),
		WaitServerStats(5*time.Second, IsAccepted, &serverStats),
		EnableServerNFQueue(tcpharness.NFQueueConfig{DropDataPacketIndices: dropDataPacketIndices}),
		StartClientSend(sendBytes, &sendHandle),
		WaitServerNFQueueDrops(10*time.Second, uint32(len(dropDataPacketIndices))),
		StopServerNFQueueDrops(),
		WaitServerNFQueueRetransmits(10*time.Second, uint32(len(dropDataPacketIndices)),
			&nfQueueStats),
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

	flow := s.ClientServerFlow()
	sackCount := flow.ServerSackCount(packets)
	AssertGreaterEqual(sackCount, 1, "expected Linux receiver to send at least one SACK")
	AssertGreaterEqual(nfQueueStats.RetransmitCount, uint32(len(dropDataPacketIndices)),
		"expected NFQUEUE monitor to observe retransmission of dropped data")
}

func TcpFastRecoveryLostRetransmitThenRtoTest(s *TcpHarnessSuite) {
	dropDataPacketIndices := []uint32{2}

	var (
		mssStats           TcpHarnessClientSessionStats
		serverStats        TcpTestEndpointStats
		clientStats        TcpTestEndpointStats
		peerClosed         TcpTestEndpointStats
		sessionStats       TcpHarnessClientSessionStats
		nfQueueStats       tcpharness.NFQueueStats
		finalSessionOutput string
		sendHandle         TcpHarnessSendHandle
		sendResult         TcpTestEndpointCommandResult
		packets            []tcpharness.PcapIPv4TCPPacket
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
		EnableServerNFQueue(tcpharness.NFQueueConfig{
			DropDataPacketIndices:     dropDataPacketIndices,
			DropFirstRetransmitOfDrop: true,
		}),
		StartClientSend(sendBytes, &sendHandle),
		WaitServerNFQueueDrops(20*time.Second, 2),
		StopServerNFQueueDrops(),
		WaitServerNFQueueRetransmits(20*time.Second, 2, &nfQueueStats),
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

	flow := s.ClientServerFlow()
	sackCount := flow.ServerSackCount(packets)
	AssertGreaterEqual(sackCount, 1, "expected Linux receiver to send at least one SACK")
	AssertGreaterEqual(nfQueueStats.RetransmitCount, uint32(2),
		"expected NFQUEUE monitor to observe fast and timer retransmissions")
	AssertGreaterEqual(sessionStats.FastRecoveryCount, uint64(1),
		"expected client VPP session stats to record fast recovery")
	AssertGreaterEqual(sessionStats.TimerRecoveryCount, uint64(1),
		"expected client VPP session stats to record timer recovery")
	AssertGreaterEqual(sessionStats.RetransmitSegsCount, uint64(2),
		"expected client VPP session stats to record both fast and timer retransmissions")
}

func TcpTailLossTimerRecoveryTest(s *TcpHarnessSuite) {
	dropDataPacketIndices := []uint32{1}
	var (
		mssStats      TcpHarnessClientSessionStats
		serverStats   TcpTestEndpointStats
		clientStats   TcpTestEndpointStats
		peerClosed    TcpTestEndpointStats
		sessionStats  TcpHarnessClientSessionStats
		nfQueueStats  tcpharness.NFQueueStats
		initialSend   TcpHarnessSendHandle
		sendHandle    TcpHarnessSendHandle
		initialResult TcpTestEndpointCommandResult
		sendResult    TcpTestEndpointCommandResult
		packets       []tcpharness.PcapIPv4TCPPacket
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
		EnableServerNFQueue(tcpharness.NFQueueConfig{DropDataPacketIndices: dropDataPacketIndices}),
		StartClientSend(mss, &sendHandle),
		WaitServerNFQueueDrops(10*time.Second, uint32(len(dropDataPacketIndices))),
		StopServerNFQueueDrops(),
		WaitServerNFQueueRetransmits(20*time.Second, uint32(len(dropDataPacketIndices)),
			&nfQueueStats),
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

	sackCount := s.ClientServerFlow().ServerSackCount(packets)
	AssertEqual(0, sackCount, "expected no SACKs for pure tail-loss timer recovery")
	AssertGreaterEqual(nfQueueStats.RetransmitCount, uint32(len(dropDataPacketIndices)),
		"expected NFQUEUE monitor to observe retransmission of dropped tail data")
	AssertEqual(uint64(0), sessionStats.FastRecoveryCount,
		"expected client VPP session stats to avoid fast recovery")
	AssertGreaterEqual(sessionStats.TimerRecoveryCount, uint64(1),
		"expected client VPP session stats to record timer recovery")
	AssertGreaterEqual(sessionStats.RetransmitSegsCount, uint64(1),
		"expected client VPP session stats to record retransmissions")
}

func TcpFastRecoveryTwoHolesPartialAckTest(s *TcpHarnessSuite) {
	dropDataPacketIndices := []uint32{2, 4}
	scriptCfg := tcpharness.NFQueueScript(dropDataPacketIndices,
		tcpharness.InitialHolesSackStep(len(dropDataPacketIndices), 3, tcpharness.KeepQueuedAcks()),
		tcpharness.RetransmitPartialAckStep(2,
			tcpharness.DiscardQueuedAcks(),
			tcpharness.AdvanceScriptToDone()))
	var (
		mssStats     TcpHarnessClientSessionStats
		serverStats  TcpTestEndpointStats
		clientStats  TcpTestEndpointStats
		peerClosed   TcpTestEndpointStats
		sessionStats TcpHarnessClientSessionStats
		scriptStats  tcpharness.NFQueueScriptStats
		scriptTrace  []tcpharness.NFQueueScriptTraceEntry
		warmupHandle TcpHarnessSendHandle
		sendHandle   TcpHarnessSendHandle
		warmupResult TcpTestEndpointCommandResult
		sendResult   TcpTestEndpointCommandResult
		packets      []tcpharness.PcapIPv4TCPPacket
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
		EnableServerNFQueueScript(scriptCfg),
		StartClientSend(controlledBytes, &sendHandle),
		WaitServerNFQueueScriptDone(10*time.Second, &scriptStats, &scriptTrace),
		DisableServerNFQueueScript(),
	)

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
	AssertEqual(tcpharness.NFQueueScriptStageDone, scriptStats.Stage,
		"expected scripted NFQUEUE controller to reach Done")
	AssertEqual(uint64(len(dropDataPacketIndices)), scriptStats.OriginalDropCount,
		"expected scripted NFQUEUE controller to record each planned original drop")
	AssertEqual(uint64(5), scriptStats.SyntheticAckInjectedCount,
		"expected scripted NFQUEUE controller to inject the initial and partial ACK/SACK sequence")
	AssertGreaterEqual(scriptStats.NaturalAckQueuedCount, uint64(1),
		"expected scripted NFQUEUE controller to queue at least one natural Linux ACK")
	AssertGreaterEqual(scriptStats.RetransmitTriggerCount, uint64(1),
		"expected scripted NFQUEUE controller to observe a retransmit trigger for the partial ACK step")
	AssertEmpty(scriptStats.LastErrorText,
		"expected scripted NFQUEUE controller to avoid internal errors")
	Log(sessionStats.Output)
	s.LogServerNFQueueScriptSnapshot(scriptStats, scriptTrace)

	s.LogTcpTestEndpointLogs()

	flow := s.ClientServerFlow()
	sackCount := flow.ServerSackCount(packets)
	AssertGreaterEqual(sackCount, 2, "expected crafted or Linux receiver SACKs across the two holes")
	AssertEqual(true, flow.HasPartialServerSackAck(packets),
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

	scriptCfg := tcpharness.NFQueueScript(dropDataPacketIndices,
		tcpharness.InitialHolesSackStep(len(dropDataPacketIndices), 3,
			tcpharness.DiscardQueuedAcks(),
			tcpharness.AdvanceScriptToDone()))
	var (
		mssStats     TcpHarnessClientSessionStats
		serverStats  TcpTestEndpointStats
		clientStats  TcpTestEndpointStats
		peerClosed   TcpTestEndpointStats
		sessionStats TcpHarnessClientSessionStats
		scriptStats  tcpharness.NFQueueScriptStats
		scriptTrace  []tcpharness.NFQueueScriptTraceEntry
		warmupHandle TcpHarnessSendHandle
		sendHandle   TcpHarnessSendHandle
		warmupResult TcpTestEndpointCommandResult
		sendResult   TcpTestEndpointCommandResult
		packets      []tcpharness.PcapIPv4TCPPacket
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
		EnableServerNFQueueScript(scriptCfg),
		StartClientSend(controlledBytes, &sendHandle),
		WaitServerNFQueueScriptDone(10*time.Second, &scriptStats, &scriptTrace),
		DisableServerNFQueueScript(),
	)

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
	AssertEqual(tcpharness.NFQueueScriptStageDone, scriptStats.Stage,
		"expected scripted NFQUEUE controller to reach Done")
	AssertEqual(uint64(len(dropDataPacketIndices)), scriptStats.OriginalDropCount,
		"expected scripted NFQUEUE controller to record each planned original drop")
	AssertEqual(uint64(3), scriptStats.SyntheticAckInjectedCount,
		"expected scripted NFQUEUE controller to inject the scoreboard-driving ACK/SACK sequence")
	AssertGreaterEqual(scriptStats.NaturalAckQueuedCount, uint64(1),
		"expected scripted NFQUEUE controller to queue at least one natural Linux ACK")
	AssertEmpty(scriptStats.LastErrorText,
		"expected scripted NFQUEUE controller to avoid internal errors")
	Log(sessionStats.Output)
	s.LogServerNFQueueScriptSnapshot(scriptStats, scriptTrace)

	s.LogTcpTestEndpointLogs()

	flow := s.ClientServerFlow()
	sackCount := flow.ServerSackCount(packets)
	AssertGreaterEqual(sackCount, 2, "expected crafted or Linux receiver SACKs for scoreboard stress")
	AssertEqual(true, flow.HasServerSackWithAtLeastBlocks(packets, len(dropDataPacketIndices)),
		"expected to observe the crafted multi-block SACK on the wire")
	AssertGreaterEqual(scriptStats.RetransmitTriggerCount, uint64(1),
		"expected scripted NFQUEUE controller to observe retransmission after the scoreboard-driving SACK")
	AssertGreaterEqual(sessionStats.FastRecoveryCount, uint64(1),
		"expected client VPP session stats to record fast recovery")
	AssertGreaterEqual(sessionStats.RetransmitSegsCount, uint64(1),
		"expected client VPP session stats to record retransmissions")
	AssertEqual(false, sessionStats.IsReneging,
		"expected client VPP session stats to avoid SACK reneging")
}
