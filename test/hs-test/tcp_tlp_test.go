/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

// Validation test for the Tail Loss Probe (RFC 8985) implementation. NOT for
// merge -- this exercises a VPP-specific behavior (TLP repairing a pure tail
// loss without an RTO/timer recovery) to prove the fix works.
//
// TcpTailLossTimerRecoveryTest (committed) shows the pre-TLP behavior: a single
// dropped tail segment, with nothing sent after it, recovers only via the
// retransmit timer (TimerRecoveryCount >= 1, no fast recovery). With TLP
// enabled on the sender, the same drop should be repaired by a tail loss probe:
// no timer recovery, and the send completes quickly (~PTO, not ~RTO).

package main

import (
	"time"

	. "fd.io/hs-test/infra"
	tcpharness "fd.io/hs-test/infra/tcpharness"
)

func init() {
	RegisterTcpHarnessTests(
		TcpTailLossProbeRecoveryTest,
	)
}

// EnableClientTlp turns on RACK/TLP loss detection on the sender (client) VPP.
func EnableClientTlp() TcpHarnessAction {
	return TcpHarnessActionFunc(func(s *TcpHarnessSuite, st *TcpHarnessScenarioState) {
		Log(s.Containers.ClientVpp.VppInstance.Vppctl("set tcp rack"))
	})
}

func TcpTailLossProbeRecoveryTest(s *TcpHarnessSuite) {
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
		EnableClientTlp(),
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
		WaitServerStats(20*time.Second, BytesReadExactly(sendBytes), &serverStats),
		WaitClientSend(&sendHandle, 20*time.Second, &sendResult),
		WaitClientStats(5*time.Second, BytesSentExactly(sendBytes), &clientStats),
	)

	// Snapshot the session stats once the tail has been delivered.
	sessionStats = s.ClientVppSessionStatsGet()

	RunTcpHarnessScenarioOnState(s, state,
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

	AssertGreaterEqual(nfQueueStats.RetransmitCount, uint32(len(dropDataPacketIndices)),
		"expected NFQUEUE monitor to observe retransmission of dropped tail data")
	// The whole point of TLP: a pure tail loss is repaired by the probe, not by
	// the retransmit-timer (RTO) recovery path.
	AssertEqual(uint64(0), sessionStats.TimerRecoveryCount,
		"expected TLP to repair the tail loss without timer (RTO) recovery")
	AssertGreaterEqual(sessionStats.RetransmitSegsCount, uint64(1),
		"expected client VPP session stats to record the probe retransmission")
}
