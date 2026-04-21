package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterTcpHarnessTests(TcpWindowProbeLinuxTest)
}

type tcpHarnessStats struct {
	Accepted   bool
	Paused     bool
	PeerClosed bool
	BytesRead  uint64
}

func tcpHarnessCtl(c *Container, controlSock string, command string) string {
	o, err := c.Exec(false, "tcp_test_peer ctl --control %s %s", controlSock, command)
	AssertNil(err, o)
	return strings.TrimSpace(o)
}

func tcpHarnessParseStats(out string) tcpHarnessStats {
	stats := tcpHarnessStats{}

	for _, field := range strings.Fields(out) {
		parts := strings.SplitN(field, "=", 2)
		if len(parts) != 2 {
			continue
		}
		switch parts[0] {
		case "accepted":
			stats.Accepted = parts[1] == "1"
		case "paused":
			stats.Paused = parts[1] == "1"
		case "peer_closed":
			stats.PeerClosed = parts[1] == "1"
		case "bytes_read":
			v, err := strconv.ParseUint(parts[1], 10, 64)
			AssertNil(err)
			stats.BytesRead = v
		}
	}

	return stats
}

func tcpHarnessStatsTryGet(c *Container, controlSock string) (tcpHarnessStats, bool) {
	out, err := c.Exec(false, "tcp_test_peer ctl --control %s stats", controlSock)
	if err != nil {
		return tcpHarnessStats{}, false
	}
	return tcpHarnessParseStats(strings.TrimSpace(out)), true
}

func tcpHarnessStatsGet(c *Container, controlSock string) tcpHarnessStats {
	stats, ok := tcpHarnessStatsTryGet(c, controlSock)
	AssertEqual(true, ok, "failed to query tcp_test_peer stats")
	return stats
}

func tcpHarnessWaitForStats(c *Container, controlSock string, timeout time.Duration,
	check func(stats tcpHarnessStats) bool) tcpHarnessStats {
	deadline := time.Now().Add(timeout)
	var stats tcpHarnessStats

	for time.Now().Before(deadline) {
		if next, ok := tcpHarnessStatsTryGet(c, controlSock); ok {
			stats = next
			if check(stats) {
				return stats
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	AssertEmpty("timed out waiting for tcp_test_peer stats condition")
	return stats
}

func TcpWindowProbeLinuxTest(s *TcpHarnessSuite) {
	const sendBytes = 256 << 10

	clientVpp := s.Containers.ClientVpp.VppInstance
	serverApp := s.Containers.ServerApp
	clientApp := s.Containers.ClientApp
	serverAddr := s.Interfaces.Server.Host.Ip4AddressString()
	controlSock := serverApp.GetContainerWorkDir() + "/tcp_test_peer.sock"
	serverLog := serverApp.GetContainerWorkDir() + "/tcp_test_peer.log"

	serverCmd := fmt.Sprintf(
		"tcp_test_peer server --listen %s --port %s --control %s --rcvbuf 4096 --window-clamp 1024 --pause-read > %s 2>&1",
		serverAddr, s.Ports.Port1, controlSock, serverLog)
	serverApp.ExecServer(false, WrapCmdWithLineBuffering(serverCmd))

	tcpHarnessWaitForStats(serverApp, controlSock, 5*time.Second,
		func(stats tcpHarnessStats) bool { return !stats.Accepted && stats.Paused })

	clientVpp.EnablePcapTrace()
	pcapCollected := false
	defer func() {
		if !pcapCollected {
			clientVpp.CollectPcapTrace()
		}
	}()
	defer func() {
		_, _ = serverApp.Exec(false, "cat %s", serverLog)
		_, _ = serverApp.Exec(false, "tcp_test_peer ctl --control %s shutdown", controlSock)
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

	tcpHarnessWaitForStats(serverApp, controlSock, 5*time.Second,
		func(stats tcpHarnessStats) bool { return stats.Accepted })

	time.Sleep(1500 * time.Millisecond)

	stats := tcpHarnessStatsGet(serverApp, controlSock)
	AssertEqual(uint64(0), stats.BytesRead, "server should still be paused with no app reads")

	tcpHarnessCtl(serverApp, controlSock, "resume-read")

	var result clientResult
	select {
	case result = <-clientDone:
	case <-time.After(20 * time.Second):
		AssertEmpty("timed out waiting for vpp_echo client")
	}

	Log(result.out)
	AssertNil(result.err, result.out)

	stats = tcpHarnessWaitForStats(serverApp, controlSock, 5*time.Second,
		func(stats tcpHarnessStats) bool { return stats.BytesRead >= sendBytes && stats.PeerClosed })
	AssertGreaterEqual(stats.BytesRead, uint64(sendBytes))

	clientVpp.CollectPcapTrace()
	pcapCollected = true

	wantPort, err := strconv.ParseUint(s.Ports.Port1, 10, 16)
	AssertNil(err)

	probeSeen, err := s.HasOldSeqAckOnlyProbe(
		s.Containers.ClientVpp.Name,
		s.Interfaces.Client.Ip4AddressString(),
		serverAddr,
		uint16(wantPort))
	AssertNil(err)
	AssertEqual(true, probeSeen, "expected an old-seq ACK-only window probe in client VPP pcap")
}
