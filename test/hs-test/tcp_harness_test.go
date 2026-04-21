package main

import (
	"regexp"
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

func clientSessionMss(s *TcpHarnessSuite) uint64 {
	mssRE := regexp.MustCompile(`\bsnd_mss (\d+)\b`)
	sessionOutput := s.WaitForClientVppSessions(5*time.Second,
		func(output string) bool { return mssRE.MatchString(output) })
	matches := mssRE.FindStringSubmatch(sessionOutput)
	AssertEqual(2, len(matches), "expected snd_mss in client VPP session output")

	mss, err := strconv.ParseUint(matches[1], 10, 64)
	AssertNil(err)
	return mss
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
	fastRecoveryStatsRE := regexp.MustCompile(`(?s)\bfr [1-9]\d*\b.*\brxt segs [1-9]\d*\b`)

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

	sessionOutput := s.WaitForClientVppSessions(5*time.Second,
		func(output string) bool { return fastRecoveryStatsRE.MatchString(output) })
	Log(sessionOutput)

	s.CloseTcpTestEndpointClient()
	s.WaitForTcpTestEndpointServerStats(5*time.Second,
		func(stats TcpTestEndpointStats) bool { return stats.PeerClosed })

	pcapTrace.Collect()
	s.LogTcpTestEndpointLogs()

	packets, err := ReadPcapIPv4TCPPackets(s.GetPcapTracePath(s.Containers.ClientVpp.Name))
	AssertNil(err)

	sackCount := countSackPackets(packets, serverAddr, clientAddr)
	AssertGreaterEqual(sackCount, 1, "expected Linux receiver to send at least one SACK")
	AssertEqual(true, fastRecoveryStatsRE.MatchString(sessionOutput),
		"expected client VPP session stats to record fast recovery and retransmission")
}

func TcpFastRecoveryLostRetransmitThenRtoTest(s *TcpHarnessSuite) {
	const sendBytes = 64 << 10

	clientVpp := s.Containers.ClientVpp.VppInstance
	clientAddr := s.Interfaces.Client.Ip4AddressString()
	serverAddr := s.Interfaces.Server.Host.Ip4AddressString()
	fastRecoveryThenTimerStatsRE := regexp.MustCompile(
		`(?s)\bfr [1-9]\d*\b.*\btr [1-9]\d*\b.*\brxt segs [1-9]\d*\b`)

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

	sessionOutput := s.WaitForClientVppSessions(20*time.Second,
		func(output string) bool { return fastRecoveryThenTimerStatsRE.MatchString(output) })
	Log(sessionOutput)

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
	AssertEqual(true, fastRecoveryThenTimerStatsRE.MatchString(sessionOutput),
		"expected client VPP session stats to record both fast recovery and timer recovery")
}

func TcpTailLossTimerRecoveryTest(s *TcpHarnessSuite) {
	clientVpp := s.Containers.ClientVpp.VppInstance
	clientAddr := s.Interfaces.Client.Ip4AddressString()
	serverAddr := s.Interfaces.Server.Host.Ip4AddressString()
	timerRecoveryOnlyStatsRE := regexp.MustCompile(
		`(?s)\bfr 0\b.*\btr [1-9]\d*\b.*\brxt segs [1-9]\d*\b`)

	pcapTrace := s.StartPcapTrace(clientVpp)
	defer pcapTrace.Close()
	defer s.StopTcpTestEndpoints()

	s.StartTcpTestEndpointServer(TcpTestEndpointServerConfig{
		Port: s.Ports.Port1,
	})
	s.StartTcpTestEndpointClient(TcpTestEndpointClientConfig{})

	s.WaitForTcpTestEndpointServerStats(5*time.Second,
		func(stats TcpTestEndpointStats) bool { return stats.Accepted })

	mss := clientSessionMss(s)
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

	sessionOutput := s.WaitForClientVppSessions(20*time.Second,
		func(output string) bool { return timerRecoveryOnlyStatsRE.MatchString(output) })
	Log(sessionOutput)

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
	AssertEqual(true, timerRecoveryOnlyStatsRE.MatchString(sessionOutput),
		"expected client VPP session stats to record timer recovery without fast recovery")
}

func TcpFastRecoveryTwoHolesPartialAckTest(s *TcpHarnessSuite) {
	clientVpp := s.Containers.ClientVpp.VppInstance
	clientAddr := s.Interfaces.Client.Ip4AddressString()
	serverAddr := s.Interfaces.Server.Host.Ip4AddressString()
	twoHoleFastRecoveryStatsRE := regexp.MustCompile(
		`(?s)\bfr [1-9]\d*\b.*\btr 0\b.*\brxt segs (?:[2-9]|[1-9]\d+)\b`)

	pcapTrace := s.StartPcapTrace(clientVpp)
	defer pcapTrace.Close()
	defer s.StopTcpTestEndpoints()

	s.StartTcpTestEndpointServer(TcpTestEndpointServerConfig{
		Port: s.Ports.Port1,
	})
	s.StartTcpTestEndpointClient(TcpTestEndpointClientConfig{})

	s.WaitForTcpTestEndpointServerStats(5*time.Second,
		func(stats TcpTestEndpointStats) bool { return stats.Accepted })

	sendBytes := 8 * clientSessionMss(s)

	s.EnableClientNsim(TcpHarnessNsimConfig{
		PacketsPerDrop: 3,
	})
	sendDone := s.StartTcpTestEndpointClientSend(sendBytes)

	time.Sleep(500 * time.Millisecond)
	s.DisableClientNsim()

	sessionOutput := s.WaitForClientVppSessions(20*time.Second,
		func(output string) bool { return twoHoleFastRecoveryStatsRE.MatchString(output) })
	Log(sessionOutput)

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
	AssertEqual(true, twoHoleFastRecoveryStatsRE.MatchString(sessionOutput),
		"expected client VPP session stats to repair both holes in fast recovery without timer recovery")
}
