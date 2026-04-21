package main

import (
	"fmt"
	"strconv"
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
	serverApp := s.Containers.ServerApp
	clientApp := s.Containers.ClientApp
	serverAddr := s.Interfaces.Server.Host.Ip4AddressString()

	s.StartTcpTestPeerServer(serverApp, TcpTestPeerServerConfig{
		ListenAddr:  serverAddr,
		Port:        s.Ports.Port1,
		ReceiveBuf:  4096,
		WindowClamp: 1024,
		PauseRead:   true,
	})

	s.WaitForTcpTestPeerStats(serverApp, s.TcpTestPeer.ControlSock, 5*time.Second,
		func(stats TcpTestPeerStats) bool { return !stats.Accepted && stats.Paused })

	pcapTrace := s.StartPcapTrace(clientVpp)
	defer pcapTrace.Close()
	defer func() {
		s.TcpTestPeerCtl(serverApp, s.TcpTestPeer.ControlSock, "shutdown")
	}()

	socketName := clientApp.GetContainerWorkDir() + "/var/run/app_ns_sockets/default"
	clientCmd := fmt.Sprintf(
		"vpp_echo client TX=%d RX=0 sclose=Y use-app-socket-api socket-name %s uri tcp://%s/%s",
		sendBytes, socketName, serverAddr, s.Ports.Port1)

	type clientResult struct {
		out string
		err error
	}
	clientDone := make(chan clientResult, 1)
	go func() {
		o, err := clientApp.Exec(false, WrapCmdWithLineBuffering(clientCmd))
		clientDone <- clientResult{out: o, err: err}
	}()

	s.WaitForTcpTestPeerStats(serverApp, s.TcpTestPeer.ControlSock, 5*time.Second,
		func(stats TcpTestPeerStats) bool { return stats.Accepted })

	time.Sleep(1500 * time.Millisecond)

	stats := s.TcpTestPeerStatsGet(serverApp, s.TcpTestPeer.ControlSock)
	AssertEqual(uint64(0), stats.BytesRead, "server should still be paused with no app reads")

	s.TcpTestPeerCtl(serverApp, s.TcpTestPeer.ControlSock, "resume-read")

	var result clientResult
	select {
	case result = <-clientDone:
	case <-time.After(20 * time.Second):
		AssertEmpty("timed out waiting for vpp_echo client")
	}

	Log(result.out)
	AssertNil(result.err, result.out)

	stats = s.WaitForTcpTestPeerStats(serverApp, s.TcpTestPeer.ControlSock, 5*time.Second,
		func(stats TcpTestPeerStats) bool { return stats.BytesRead >= sendBytes && stats.PeerClosed })
	AssertGreaterEqual(stats.BytesRead, uint64(sendBytes))

	pcapTrace.Collect()
	s.LogTcpTestPeerLog(serverApp)

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
