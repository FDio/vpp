package main

import (
	"strconv"
	"strings"
	"time"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterTcpHarnessTests(TcpWindowProbeLinuxTest)
}

func hasOldSeqAckOnlyProbe(s *TcpHarnessSuite, vppName string,
	srcIP string, dstIP string, dstPort uint16) (bool, error) {
	packets, err := ReadPcapIPv4TCPPackets(s.GetPcapTracePath(vppName))
	if err != nil {
		return false, err
	}

	probeSeqs := make([]uint32, 0)
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

		if packet.IsAckOnly() {
			probeSeqs = append(probeSeqs, packet.Seq)
		}
	}

	for _, seq := range probeSeqs {
		if seq < maxDataSeqEnd {
			return true, nil
		}
	}

	return false, nil
}

func TcpWindowProbeLinuxTest(s *TcpHarnessSuite) {
	const sendBytes = 256 << 10

	clientVpp := s.Containers.ClientVpp.VppInstance
	serverAddr := s.Interfaces.Server.Host.Ip4AddressString()

	pcapTrace := s.StartPcapTrace(clientVpp)
	defer pcapTrace.Close()
	defer s.StopTcpTestPeers()

	s.StartTcpTestPeerServer(TcpTestPeerServerConfig{
		Port:        s.Ports.Port1,
		ReceiveBuf:  4096,
		WindowClamp: 1024,
		PauseRead:   true,
	})
	s.StartTcpTestPeerClient(TcpTestPeerClientConfig{})

	clientDone := s.StartTcpTestPeerClientSend(sendBytes)

	s.WaitForTcpTestPeerServerStats(5*time.Second,
		func(stats TcpTestPeerStats) bool { return stats.Accepted })

	time.Sleep(1500 * time.Millisecond)

	stats := s.TcpTestPeerServerStatsGet()
	AssertEqual(uint64(0), stats.BytesRead, "server should still be paused with no app reads")

	s.TcpTestPeerServerCtl("resume-read")

	var result TcpTestPeerCommandResult
	select {
	case result = <-clientDone:
	case <-time.After(20 * time.Second):
		AssertEmpty("timed out waiting for tcp_test_peer client send")
	}

	Log(result.Out)
	AssertNil(result.Err, result.Out)
	AssertEqual("ok", strings.TrimSpace(result.Out))

	s.CloseTcpTestPeerClient()

	stats = s.WaitForTcpTestPeerServerStats(5*time.Second,
		func(stats TcpTestPeerStats) bool { return stats.BytesRead >= sendBytes && stats.PeerClosed })
	AssertGreaterEqual(stats.BytesRead, uint64(sendBytes))

	pcapTrace.Collect()
	s.LogTcpTestPeerLogs()

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
