package main

import (
	"fmt"
	"os/exec"
	"time"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterSfdpTests(
		SfdpUdpSessionCreatedTest,
		SfdpTcpSessionCreatedTest,
	)
}

func SfdpUdpSessionCreatedTest(s *SfdpSuite) {
	serverAddr := s.ServerAddr()
	port := 9999

	// Start iperf3 server in server netns
	serverCmd := exec.Command("ip", "netns", "exec", s.NetNamespaces.Server,
		"iperf3", "-s", "-B", serverAddr, "-p", fmt.Sprintf("%d", port), "--one-off")
	AssertNil(serverCmd.Start())
	defer serverCmd.Process.Kill()
	time.Sleep(100 * time.Millisecond)

	// Start iperf3 client in client netns
	clientCmd := exec.Command("ip", "netns", "exec", s.NetNamespaces.Client,
		"iperf3", "-c", serverAddr, "-p", fmt.Sprintf("%d", port), "-u", "-t", "5", "-b", "1M")
	AssertNil(clientCmd.Start())
	defer clientCmd.Process.Kill()

	// Verify that SFDP UDP session exists
	stats := s.GetSfdpSessionStats()
	Log("Parsed session stats: %+v", stats)
	found := false
	for _, st := range stats {
		if st.Proto == 17 && st.PacketsFwd > 0 {
			found = true
			break
		}
	}
	AssertEqual(true, found, "expected SFDP session stats with proto 17 and Pkts(fwd) > 0")

	// iperf3 UDP server sends back small ACK packets for jitter/loss measurement,
	// so SFDP sees reverse-direction traffic and promotes the session to established.
	sessions := s.GetSfdpSessions()
	Log("Parsed sessions: %+v", sessions)
	found = false
	for _, sess := range sessions {
		Log("session: Proto=%q State=%q", sess.Proto, sess.State)
		if sess.Proto == "UDP" && sess.State == "established" {
			found = true
			break
		}
	}
	AssertEqual(true, found, "expected SFDP UDP session in established state")
}

func SfdpTcpSessionCreatedTest(s *SfdpSuite) {
	serverAddr := s.ServerAddr()
	port := 9998

	// Start iperf3 server in server netns
	serverCmd := exec.Command("ip", "netns", "exec", s.NetNamespaces.Server,
		"iperf3", "-s", "-B", serverAddr, "-p", fmt.Sprintf("%d", port), "--one-off")
	AssertNil(serverCmd.Start())
	defer serverCmd.Process.Kill()
	time.Sleep(100 * time.Millisecond)

	// Start iperf3 client in client netns
	clientCmd := exec.Command("ip", "netns", "exec", s.NetNamespaces.Client,
		"iperf3", "-c", serverAddr, "-p", fmt.Sprintf("%d", port), "-t", "5")
	AssertNil(clientCmd.Start())
	defer clientCmd.Process.Kill()

	// Verify that SFDP TCP session exists, and is in established state
	sessions := s.GetSfdpSessions()
	Log("Parsed sessions: %+v", sessions)
	found := false
	for _, sess := range sessions {
		if sess.Proto == "TCP" && sess.State == "established" {
			found = true
			break
		}
	}
	AssertEqual(true, found, "expected SFDP TCP session in established state")

	// Verify that SFDP session stats service reports TCP activity
	stats := s.GetSfdpSessionStats()
	Log("Parsed session stats: %+v", stats)
	found = false
	for _, st := range stats {
		if st.Proto == 6 && st.PacketsFwd > 0 {
			found = true
			break
		}
	}
	AssertEqual(true, found, "expected SFDP session stats with proto 6 and Pkts(fwd) > 0")

}
