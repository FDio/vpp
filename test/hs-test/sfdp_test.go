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

	serverCmd := exec.Command("ip", "netns", "exec", s.NetNamespaces.Server,
		"iperf3", "-s", "-B", serverAddr, "-p", fmt.Sprintf("%d", port), "--one-off")
	AssertNil(serverCmd.Start())
	defer serverCmd.Process.Kill()
	time.Sleep(100 * time.Millisecond)

	clientCmd := exec.Command("ip", "netns", "exec", s.NetNamespaces.Client,
		"iperf3", "-c", serverAddr, "-p", fmt.Sprintf("%d", port), "-u", "-t", "5", "-b", "1M")
	AssertNil(clientCmd.Start())
	defer clientCmd.Process.Kill()

	vpps := []*VppInstance{
		s.Containers.Vpp1.VppInstance,
		s.Containers.Vpp2.VppInstance,
		s.Containers.Vpp3.VppInstance,
	}
	for i, vpp := range vpps {
		stats := s.GetSfdpSessionStatsFromVpp(vpp)
		Log("VPP%d session stats: %+v", i+1, stats)
		found := false
		for _, st := range stats {
			if st.Proto == 17 && st.PacketsFwd > 0 {
				found = true
				break
			}
		}
		AssertEqual(true, found, fmt.Sprintf("VPP%d: expected SFDP session stats with proto 17 and Pkts(fwd) > 0", i+1))
	}

	// UDP ACK packets from server promote the session to established on all VPPs
	for i, vpp := range vpps {
		sessions := s.GetSfdpSessionsFromVpp(vpp)
		Log("VPP%d sessions: %+v", i+1, sessions)
		found := false
		for _, sess := range sessions {
			if sess.Proto == "UDP" && sess.State == "established" {
				found = true
				break
			}
		}
		AssertEqual(true, found, fmt.Sprintf("VPP%d: expected SFDP UDP session in established state", i+1))
	}
}

func SfdpTcpSessionCreatedTest(s *SfdpSuite) {
	serverAddr := s.ServerAddr()
	port := 9998

	serverCmd := exec.Command("ip", "netns", "exec", s.NetNamespaces.Server,
		"iperf3", "-s", "-B", serverAddr, "-p", fmt.Sprintf("%d", port), "--one-off")
	AssertNil(serverCmd.Start())
	defer serverCmd.Process.Kill()
	time.Sleep(100 * time.Millisecond)

	clientCmd := exec.Command("ip", "netns", "exec", s.NetNamespaces.Client,
		"iperf3", "-c", serverAddr, "-p", fmt.Sprintf("%d", port), "-t", "5")
	AssertNil(clientCmd.Start())
	defer clientCmd.Process.Kill()

	vpps := []*VppInstance{
		s.Containers.Vpp1.VppInstance,
		s.Containers.Vpp2.VppInstance,
		s.Containers.Vpp3.VppInstance,
	}
	for i, vpp := range vpps {
		sessions := s.GetSfdpSessionsFromVpp(vpp)
		Log("VPP%d sessions: %+v", i+1, sessions)
		found := false
		for _, sess := range sessions {
			if sess.Proto == "TCP" && sess.State == "established" {
				found = true
				break
			}
		}
		AssertEqual(true, found, fmt.Sprintf("VPP%d: expected SFDP TCP session in established state", i+1))
	}

	for i, vpp := range vpps {
		stats := s.GetSfdpSessionStatsFromVpp(vpp)
		Log("VPP%d session stats: %+v", i+1, stats)
		found := false
		for _, st := range stats {
			if st.Proto == 6 && st.PacketsFwd > 0 {
				found = true
				break
			}
		}
		AssertEqual(true, found, fmt.Sprintf("VPP%d: expected SFDP session stats with proto 6 and Pkts(fwd) > 0", i+1))
	}
}
