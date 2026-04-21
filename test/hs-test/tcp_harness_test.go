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

func countSackPackets(packets []PcapIPv4TCPPacket, srcIP string, dstIP string) int {
	count := 0

	for _, packet := range packets {
		if packet.SrcIP.String() != srcIP || packet.DstIP.String() != dstIP {
			continue
		}
		if packet.SackBlocks > 0 {
			count++
		}
	}

	return count
}

func TcpWindowProbeLinuxTest(s *TcpHarnessSuite) {
	const sendBytes = 256 << 10

	clientVpp := s.Containers.ClientVpp.VppInstance
	serverAddr := s.Interfaces.Server.Host.Ip4AddressString()

	pcapTrace := s.StartPcapTrace(clientVpp)
	defer pcapTrace.Close()
	defer s.StopTcpTestEndpoints()

	s.StartTcpTestEndpointServer(TcpTestEndpointServerConfig{
		Port:        s.Ports.Port1,
		ReceiveBuf:  4096,
		WindowClamp: 1024,
		PauseRead:   true,
	})
	s.StartTcpTestEndpointClient(TcpTestEndpointClientConfig{})

	clientDone := s.StartTcpTestEndpointClientSend(sendBytes)

	s.WaitForTcpTestEndpointServerStats(5*time.Second,
		func(stats TcpTestEndpointStats) bool { return stats.Accepted })

	time.Sleep(1500 * time.Millisecond)

	stats := s.TcpTestEndpointServerStatsGet()
	AssertEqual(uint64(0), stats.BytesRead, "server should still be paused with no app reads")

	s.TcpTestEndpointServerCtl(TcpTestEndpointCtlResumeRead)

	var result TcpTestEndpointCommandResult
	select {
	case result = <-clientDone:
	case <-time.After(20 * time.Second):
		AssertEmpty("timed out waiting for tcp_test_endpoint client send")
	}

	Log(result.Out)
	AssertNil(result.Err, result.Out)
	AssertEqual("ok", strings.TrimSpace(result.Out))

	s.CloseTcpTestEndpointClient()

	stats = s.WaitForTcpTestEndpointServerStats(5*time.Second,
		func(stats TcpTestEndpointStats) bool { return stats.BytesRead >= sendBytes && stats.PeerClosed })
	AssertGreaterEqual(stats.BytesRead, uint64(sendBytes))

	pcapTrace.Collect()
	s.LogTcpTestEndpointLogs()

	wantPort, err := strconv.ParseUint(s.Ports.Port1, 10, 16)
	AssertNil(err)

	probeSeen, err := hasOldSeqAckOnlyProbe(
		s,
		s.Containers.ClientVpp.Name,
		s.Interfaces.Client.Ip4AddressString(),
		serverAddr,
		uint16(wantPort))
	AssertNil(err)
	AssertEqual(true, probeSeen, "expected an old-seq ACK-only window probe in client VPP pcap")
}

func TcpFastRecoverySackSingleLossTest(s *TcpHarnessSuite) {
	const sendBytes = 64 << 10

	clientVpp := s.Containers.ClientVpp.VppInstance
	clientAddr := s.Interfaces.Client.Ip4AddressString()
	serverAddr := s.Interfaces.Server.Host.Ip4AddressString()

	pcapTrace := s.StartPcapTrace(clientVpp)
	defer pcapTrace.Close()
	defer s.StopTcpTestEndpoints()

	s.StartTcpTestEndpointServer(TcpTestEndpointServerConfig{
		Port: s.Ports.Port1,
	})
	s.StartTcpTestEndpointClient(TcpTestEndpointClientConfig{})

	s.WaitForTcpTestEndpointServerStats(5*time.Second,
		func(stats TcpTestEndpointStats) bool { return stats.Accepted })

	s.EnableClientNsim(TcpHarnessNsimConfig{
		PacketsPerDrop: 6,
	})

	clientDone := s.StartTcpTestEndpointClientSend(sendBytes)

	stats := s.WaitForTcpTestEndpointServerStats(10*time.Second,
		func(stats TcpTestEndpointStats) bool { return stats.BytesRead >= sendBytes })
	AssertGreaterEqual(stats.BytesRead, uint64(sendBytes))

	s.DisableClientNsim()

	var result TcpTestEndpointCommandResult
	select {
	case result = <-clientDone:
	case <-time.After(10 * time.Second):
		AssertEmpty("timed out waiting for tcp_test_endpoint client send")
	}

	Log(result.Out)
	if result.Err != nil {
		Log("tcp_test_endpoint client send control exited: %v", result.Err)
	} else {
		AssertEqual("ok", strings.TrimSpace(result.Out))
	}

	s.WaitForTcpTestEndpointClientStats(5*time.Second,
		func(stats TcpTestEndpointStats) bool { return stats.BytesSent >= sendBytes })

	sessionStats := s.WaitForClientVppSessionStats(5*time.Second,
		func(stats TcpHarnessClientSessionStats) bool {
			return stats.FastRecoveryCount > 0 && stats.RetransmitSegsCount > 0
		})
	Log(sessionStats.Output)

	s.CloseTcpTestEndpointClient()
	s.WaitForTcpTestEndpointServerStats(5*time.Second,
		func(stats TcpTestEndpointStats) bool { return stats.PeerClosed })

	pcapTrace.Collect()
	s.LogTcpTestEndpointLogs()

	packets, err := ReadPcapIPv4TCPPackets(s.GetPcapTracePath(s.Containers.ClientVpp.Name))
	AssertNil(err)

	sackCount := countSackPackets(packets, serverAddr, clientAddr)
	AssertGreaterEqual(sackCount, 1, "expected Linux receiver to send at least one SACK")
	AssertGreaterEqual(sessionStats.FastRecoveryCount, uint64(1),
		"expected client VPP session stats to record fast recovery")
	AssertGreaterEqual(sessionStats.RetransmitSegsCount, uint64(1),
		"expected client VPP session stats to record retransmissions")
}

func TcpFastRecoveryLostRetransmitThenRtoTest(s *TcpHarnessSuite) {
	const sendBytes = 64 << 10

	clientVpp := s.Containers.ClientVpp.VppInstance
	clientAddr := s.Interfaces.Client.Ip4AddressString()
	serverAddr := s.Interfaces.Server.Host.Ip4AddressString()

	pcapTrace := s.StartPcapTrace(clientVpp)
	defer pcapTrace.Close()
	defer s.StopTcpTestEndpoints()

	s.StartTcpTestEndpointServer(TcpTestEndpointServerConfig{
		Port: s.Ports.Port1,
	})
	s.StartTcpTestEndpointClient(TcpTestEndpointClientConfig{})

	s.WaitForTcpTestEndpointServerStats(5*time.Second,
		func(stats TcpTestEndpointStats) bool { return stats.Accepted })

	s.EnableClientNsim(TcpHarnessNsimConfig{
		PacketsPerDrop: 4,
	})

	clientDone := s.StartTcpTestEndpointClientSend(sendBytes)

	sessionStats := s.WaitForClientVppSessionStats(20*time.Second,
		func(stats TcpHarnessClientSessionStats) bool {
			return stats.FastRecoveryCount > 0 &&
				stats.TimerRecoveryCount > 0 &&
				stats.RetransmitSegsCount > 0
		})
	Log(sessionStats.Output)

	s.DisableClientNsim()

	stats := s.WaitForTcpTestEndpointServerStats(20*time.Second,
		func(stats TcpTestEndpointStats) bool { return stats.BytesRead >= sendBytes })
	AssertGreaterEqual(stats.BytesRead, uint64(sendBytes))

	var result TcpTestEndpointCommandResult
	select {
	case result = <-clientDone:
	case <-time.After(20 * time.Second):
		AssertEmpty("timed out waiting for tcp_test_endpoint client send")
	}

	Log(result.Out)
	if result.Err != nil {
		Log("tcp_test_endpoint client send control exited: %v", result.Err)
	} else {
		AssertEqual("ok", strings.TrimSpace(result.Out))
	}

	s.WaitForTcpTestEndpointClientStats(5*time.Second,
		func(stats TcpTestEndpointStats) bool { return stats.BytesSent >= sendBytes })

	s.CloseTcpTestEndpointClient()
	s.WaitForTcpTestEndpointServerStats(5*time.Second,
		func(stats TcpTestEndpointStats) bool { return stats.PeerClosed })

	pcapTrace.Collect()
	s.LogTcpTestEndpointLogs()

	packets, err := ReadPcapIPv4TCPPackets(s.GetPcapTracePath(s.Containers.ClientVpp.Name))
	AssertNil(err)

	sackCount := countSackPackets(packets, serverAddr, clientAddr)
	AssertGreaterEqual(sackCount, 1, "expected Linux receiver to send at least one SACK")
	AssertGreaterEqual(sessionStats.FastRecoveryCount, uint64(1),
		"expected client VPP session stats to record fast recovery")
	AssertGreaterEqual(sessionStats.TimerRecoveryCount, uint64(1),
		"expected client VPP session stats to record timer recovery")
	AssertGreaterEqual(sessionStats.RetransmitSegsCount, uint64(1),
		"expected client VPP session stats to record retransmissions")
}

func TcpTailLossTimerRecoveryTest(s *TcpHarnessSuite) {
	clientVpp := s.Containers.ClientVpp.VppInstance
	clientAddr := s.Interfaces.Client.Ip4AddressString()
	serverAddr := s.Interfaces.Server.Host.Ip4AddressString()

	pcapTrace := s.StartPcapTrace(clientVpp)
	defer pcapTrace.Close()
	defer s.StopTcpTestEndpoints()

	s.StartTcpTestEndpointServer(TcpTestEndpointServerConfig{
		Port: s.Ports.Port1,
	})
	s.StartTcpTestEndpointClient(TcpTestEndpointClientConfig{})

	s.WaitForTcpTestEndpointServerStats(5*time.Second,
		func(stats TcpTestEndpointStats) bool { return stats.Accepted })

	mss := s.WaitForClientVppSessionStats(5*time.Second,
		func(stats TcpHarnessClientSessionStats) bool { return stats.SndMss > 0 }).SndMss
	initialBytes := 9 * mss
	sendBytes := 10 * mss

	initialSendDone := s.StartTcpTestEndpointClientSend(initialBytes)

	stats := s.WaitForTcpTestEndpointServerStats(10*time.Second,
		func(stats TcpTestEndpointStats) bool { return stats.BytesRead >= initialBytes })
	AssertGreaterEqual(stats.BytesRead, initialBytes)

	var initialResult TcpTestEndpointCommandResult
	select {
	case initialResult = <-initialSendDone:
	case <-time.After(10 * time.Second):
		AssertEmpty("timed out waiting for tcp_test_endpoint client initial send")
	}

	Log(initialResult.Out)
	if initialResult.Err != nil {
		Log("tcp_test_endpoint client initial send control exited: %v", initialResult.Err)
	} else {
		AssertEqual("ok", strings.TrimSpace(initialResult.Out))
	}

	s.EnableClientNsim(TcpHarnessNsimConfig{
		PacketsPerDrop: 1,
	})

	clientDone := s.StartTcpTestEndpointClientSend(mss)

	time.Sleep(500 * time.Millisecond)

	s.DisableClientNsim()

	sessionStats := s.WaitForClientVppSessionStats(20*time.Second,
		func(stats TcpHarnessClientSessionStats) bool {
			return stats.FastRecoveryCount == 0 &&
				stats.TimerRecoveryCount > 0 &&
				stats.RetransmitSegsCount > 0
		})
	Log(sessionStats.Output)

	stats = s.WaitForTcpTestEndpointServerStats(20*time.Second,
		func(stats TcpTestEndpointStats) bool { return stats.BytesRead >= sendBytes })
	AssertGreaterEqual(stats.BytesRead, sendBytes)

	var result TcpTestEndpointCommandResult
	select {
	case result = <-clientDone:
	case <-time.After(20 * time.Second):
		AssertEmpty("timed out waiting for tcp_test_endpoint client send")
	}

	Log(result.Out)
	if result.Err != nil {
		Log("tcp_test_endpoint client send control exited: %v", result.Err)
	} else {
		AssertEqual("ok", strings.TrimSpace(result.Out))
	}

	s.WaitForTcpTestEndpointClientStats(5*time.Second,
		func(stats TcpTestEndpointStats) bool { return stats.BytesSent >= sendBytes })

	s.CloseTcpTestEndpointClient()
	s.WaitForTcpTestEndpointServerStats(5*time.Second,
		func(stats TcpTestEndpointStats) bool { return stats.PeerClosed })

	pcapTrace.Collect()
	s.LogTcpTestEndpointLogs()

	packets, err := ReadPcapIPv4TCPPackets(s.GetPcapTracePath(s.Containers.ClientVpp.Name))
	AssertNil(err)

	sackCount := countSackPackets(packets, serverAddr, clientAddr)
	AssertEqual(0, sackCount, "expected no SACKs for pure tail-loss timer recovery")
	AssertEqual(uint64(0), sessionStats.FastRecoveryCount,
		"expected client VPP session stats to avoid fast recovery")
	AssertGreaterEqual(sessionStats.TimerRecoveryCount, uint64(1),
		"expected client VPP session stats to record timer recovery")
	AssertGreaterEqual(sessionStats.RetransmitSegsCount, uint64(1),
		"expected client VPP session stats to record retransmissions")
}

func TcpFastRecoveryTwoHolesPartialAckTest(s *TcpHarnessSuite) {
	clientVpp := s.Containers.ClientVpp.VppInstance
	clientAddr := s.Interfaces.Client.Ip4AddressString()
	serverAddr := s.Interfaces.Server.Host.Ip4AddressString()

	pcapTrace := s.StartPcapTrace(clientVpp)
	defer pcapTrace.Close()
	defer s.StopTcpTestEndpoints()

	s.StartTcpTestEndpointServer(TcpTestEndpointServerConfig{
		Port: s.Ports.Port1,
	})
	s.StartTcpTestEndpointClient(TcpTestEndpointClientConfig{})

	s.WaitForTcpTestEndpointServerStats(5*time.Second,
		func(stats TcpTestEndpointStats) bool { return stats.Accepted })

	sendBytes := 8 * s.WaitForClientVppSessionStats(5*time.Second,
		func(stats TcpHarnessClientSessionStats) bool { return stats.SndMss > 0 }).SndMss

	s.EnableClientNsim(TcpHarnessNsimConfig{
		PacketsPerDrop: 3,
	})
	sendDone := s.StartTcpTestEndpointClientSend(sendBytes)

	time.Sleep(500 * time.Millisecond)
	s.DisableClientNsim()

	sessionStats := s.WaitForClientVppSessionStats(20*time.Second,
		func(stats TcpHarnessClientSessionStats) bool {
			return stats.FastRecoveryCount > 0 &&
				stats.TimerRecoveryCount == 0 &&
				stats.RetransmitSegsCount >= 2
		})
	Log(sessionStats.Output)

	stats := s.WaitForTcpTestEndpointServerStats(20*time.Second,
		func(stats TcpTestEndpointStats) bool { return stats.BytesRead >= sendBytes })
	AssertGreaterEqual(stats.BytesRead, sendBytes)

	var result TcpTestEndpointCommandResult
	select {
	case result = <-sendDone:
	case <-time.After(20 * time.Second):
		AssertEmpty("timed out waiting for tcp_test_endpoint client send")
	}
	Log(result.Out)
	if result.Err != nil {
		Log("tcp_test_endpoint client send control exited: %v", result.Err)
	} else {
		AssertEqual("ok", strings.TrimSpace(result.Out))
	}

	s.WaitForTcpTestEndpointClientStats(5*time.Second,
		func(stats TcpTestEndpointStats) bool { return stats.BytesSent >= sendBytes })

	s.CloseTcpTestEndpointClient()
	s.WaitForTcpTestEndpointServerStats(5*time.Second,
		func(stats TcpTestEndpointStats) bool { return stats.PeerClosed })

	pcapTrace.Collect()
	s.LogTcpTestEndpointLogs()

	packets, err := ReadPcapIPv4TCPPackets(s.GetPcapTracePath(s.Containers.ClientVpp.Name))
	AssertNil(err)

	sackCount := countSackPackets(packets, serverAddr, clientAddr)
	AssertGreaterEqual(sackCount, 2, "expected Linux receiver to send multiple SACKs across the two holes")
	AssertGreaterEqual(sessionStats.FastRecoveryCount, uint64(1),
		"expected client VPP session stats to use fast recovery")
	AssertEqual(uint64(0), sessionStats.TimerRecoveryCount,
		"expected client VPP session stats to avoid timer recovery")
	AssertGreaterEqual(sessionStats.RetransmitSegsCount, uint64(2),
		"expected client VPP session stats to retransmit at least two segments")
}

func TcpSackScoreboardRobustnessTest(s *TcpHarnessSuite) {
	const sendBytes = 64 << 10

	clientVpp := s.Containers.ClientVpp.VppInstance
	clientAddr := s.Interfaces.Client.Ip4AddressString()
	serverAddr := s.Interfaces.Server.Host.Ip4AddressString()

	pcapTrace := s.StartPcapTrace(clientVpp)
	defer pcapTrace.Close()
	defer s.StopTcpTestEndpoints()

	s.StartTcpTestEndpointServer(TcpTestEndpointServerConfig{
		Port: s.Ports.Port1,
	})
	s.StartTcpTestEndpointClient(TcpTestEndpointClientConfig{})

	s.WaitForTcpTestEndpointServerStats(5*time.Second,
		func(stats TcpTestEndpointStats) bool { return stats.Accepted })

	s.EnableClientNsim(TcpHarnessNsimConfig{
		PacketsPerDrop: 4,
	})
	sendDone := s.StartTcpTestEndpointClientSend(sendBytes)

	sessionStats := s.WaitForClientVppSessionStats(20*time.Second,
		func(stats TcpHarnessClientSessionStats) bool {
			return stats.FastRecoveryCount > 0 &&
				stats.RetransmitSegsCount > 0 &&
				stats.SackedBytes > 0 &&
				!stats.IsReneging
		})
	Log(sessionStats.Output)

	s.DisableClientNsim()

	stats := s.WaitForTcpTestEndpointServerStats(20*time.Second,
		func(stats TcpTestEndpointStats) bool { return stats.BytesRead >= sendBytes })
	AssertGreaterEqual(stats.BytesRead, uint64(sendBytes))

	var result TcpTestEndpointCommandResult
	select {
	case result = <-sendDone:
	case <-time.After(20 * time.Second):
		AssertEmpty("timed out waiting for tcp_test_endpoint client send")
	}
	Log(result.Out)
	if result.Err != nil {
		Log("tcp_test_endpoint client send control exited: %v", result.Err)
	} else {
		AssertEqual("ok", strings.TrimSpace(result.Out))
	}

	s.WaitForTcpTestEndpointClientStats(5*time.Second,
		func(stats TcpTestEndpointStats) bool { return stats.BytesSent >= sendBytes })

	s.CloseTcpTestEndpointClient()
	s.WaitForTcpTestEndpointServerStats(5*time.Second,
		func(stats TcpTestEndpointStats) bool { return stats.PeerClosed })

	pcapTrace.Collect()
	s.LogTcpTestEndpointLogs()

	packets, err := ReadPcapIPv4TCPPackets(s.GetPcapTracePath(s.Containers.ClientVpp.Name))
	AssertNil(err)

	sackCount := countSackPackets(packets, serverAddr, clientAddr)
	AssertGreaterEqual(sackCount, 2, "expected Linux receiver to send multiple SACKs for scoreboard stress")
	AssertGreaterEqual(sessionStats.FastRecoveryCount, uint64(1),
		"expected client VPP session stats to record fast recovery")
	AssertGreaterEqual(sessionStats.RetransmitSegsCount, uint64(1),
		"expected client VPP session stats to record retransmissions")
	AssertGreaterEqual(sessionStats.SackedBytes, uint64(1),
		"expected client VPP session stats to record SACKed bytes")
	AssertEqual(false, sessionStats.IsReneging,
		"expected client VPP session stats to avoid SACK reneging")
}
