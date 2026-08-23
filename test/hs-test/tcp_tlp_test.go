/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

package main

import (
	"time"

	. "fd.io/hs-test/infra"
	tcpharness "fd.io/hs-test/infra/tcpharness"
)

func init() {
	RegisterTcpHarnessTests(TcpFirstFlightTailLossProbeRecoveryTest)
}

func TcpFirstFlightTailLossProbeRecoveryTest(s *TcpHarnessSuite) {
	dropDataPacketIndices := []uint32{1}
	var (
		mssStats     TcpHarnessClientSessionStats
		serverStats  TcpTestEndpointStats
		clientStats  TcpTestEndpointStats
		peerClosed   TcpTestEndpointStats
		sessionStats TcpHarnessClientSessionStats
		nfQueueStats tcpharness.NFQueueStats
		sendHandle   TcpHarnessSendHandle
		sendResult   TcpTestEndpointCommandResult
	)

	defer s.StopTcpTestEndpoints()

	state := RunTcpHarnessScenario(s,
		EnableClientRack(),
		StartTcpTestEndpointServer(TcpTestEndpointServerConfig{Port: s.Ports.Port1}),
		StartTcpTestEndpointClient(TcpTestEndpointClientConfig{}),
		WaitServerStats(5*time.Second, IsAccepted, &serverStats),
		WaitClientSessionStats(5*time.Second, HasSndMss, &mssStats),
	)
	defer state.Close()

	mss := mssStats.SndMss
	sendBytes := mss

	RunTcpHarnessScenarioOnState(s, state,
		EnableServerNFQueue(tcpharness.NFQueueConfig{DropDataPacketIndices: dropDataPacketIndices}),
		StartClientSend(mss, &sendHandle),
		WaitServerNFQueueDrops(10*time.Second, uint32(len(dropDataPacketIndices))),
		StopServerNFQueueDrops(),
		WaitServerNFQueueRetransmits(20*time.Second, uint32(len(dropDataPacketIndices)),
			&nfQueueStats),
		DisableServerNFQueue(),
		WaitServerStats(20*time.Second, BytesReadExactly(sendBytes), &serverStats),
		WaitClientSend(&sendHandle, 20*time.Second, &sendResult),
		WaitClientStats(5*time.Second, BytesSentExactly(sendBytes), &clientStats),
	)

	sessionStats = s.ClientVppSessionStatsGet()

	RunTcpHarnessScenarioOnState(s, state,
		CloseTcpTestEndpointClient(),
		WaitServerStats(5*time.Second, IsPeerClosed, &peerClosed),
	)

	AssertEqual(sendBytes, serverStats.BytesRead)
	assertTcpTestEndpointCommandOKOrPipeClosed(sendResult)
	AssertEqual(sendBytes, clientStats.BytesSent)
	AssertEqual(true, peerClosed.PeerClosed)
	Log(sessionStats.Output)

	s.LogTcpTestEndpointLogs()

	AssertGreaterEqual(nfQueueStats.RetransmitCount, uint32(len(dropDataPacketIndices)),
		"expected NFQUEUE monitor to observe retransmission of dropped tail data")
	AssertGreaterEqual(mssStats.MrttMs, 0.001, "expected the handshake to establish an RTT sample")
	AssertEqualWithinThreshold(sessionStats.MrttMs, mssStats.MrttMs, 0.001,
		"ambiguous TLP retransmission ACK must not update the ACK-timing RTT sample")
	AssertEqual(uint64(0), sessionStats.TimerRecoveryCount,
		"expected TLP to repair the tail loss without RTO recovery")
	AssertGreaterEqual(sessionStats.RetransmitSegsCount, uint64(1),
		"expected client VPP session stats to record the loss probe retransmission")
	AssertEqual(uint64(0), sessionStats.FlightSize,
		"expected the acknowledged probe retransmission to leave no bytes in flight")
}
