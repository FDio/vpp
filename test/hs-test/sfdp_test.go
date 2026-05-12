package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"sync"
	"time"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterSfdpTests(
		SfdpUdpSessionCreatedTest,
		SfdpTcpSessionCreatedTest,
		SfdpFaultLocalizationHop2FwdLossUdpTest,
		SfdpFaultLocalizationHop2FwdLossTcpTest,
		SfdpFaultLocalizationHop2FwdReorderTcpTest,
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

	// Check SFDP Session Stats on each VPP instance in the chain
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

// SfdpFaultLocalizationHop2FwdLossUdpTest introduces packet loss on the
// forward path between VPP2 and VPP3, and checks impact on UDP traffic.
//
// Topology:
//
//	cln --> VPP1 --> VPP2 --> [~30% loss] --> VPP3 --> srv   (forward)
//	cln <-- VPP1 <-- VPP2 <----------------- VPP3 <-- srv   (reverse, no loss)
//
// Expected SFDP observations:
//   - Forward: VPP1.pkts_fwd == VPP2.pkts_fwd > VPP3.pkts_fwd  (loss localised to hop-2)
//   - Reverse: VPP1.pkts_rev == VPP2.pkts_rev == VPP3.pkts_rev  (reverse path untouched)
func SfdpFaultLocalizationHop2FwdLossUdpTest(s *SfdpSuite) {
	serverAddr := s.ServerAddr()
	port := 9997

	serverCmd := exec.Command("ip", "netns", "exec", s.NetNamespaces.Server,
		"iperf3", "-s", "-B", serverAddr, "-p", fmt.Sprintf("%d", port), "--one-off")
	AssertNil(serverCmd.Start())
	defer serverCmd.Process.Kill()
	time.Sleep(100 * time.Millisecond)

	// Start the client in the background so that the iperf3 TCP control connection
	// (handshake + parameter exchange) can complete before loss is enabled
	clientCmd := exec.Command("ip", "netns", "exec", s.NetNamespaces.Client,
		"iperf3", "-c", serverAddr, "-p", fmt.Sprintf("%d", port), "-u", "-t", "5", "-b", "1M")
	var clientOut bytes.Buffer
	clientCmd.Stdout = &clientOut
	AssertNil(clientCmd.Start())

	// Wait for the TCP control connection to complete, then induce
	// loss with tc-netem & expect it to impact UDP data stream.
	time.Sleep(200 * time.Millisecond)
	removeNetem := s.ApplyNetemOnHop2Fwd("loss", "30%")
	defer removeNetem()

	err := clientCmd.Wait()
	AssertNil(err, fmt.Sprintf("iperf3 UDP client failed: %s", clientOut.String()))

	// Verify loss reported by iperf3 and verify it is in acceptable range [10%, 55%]
	// to avoid packet drops due to another external factor (e.g. unexpected congestion).
	iperfResult, parseErr := ParseIperfText(clientOut.String())
	if parseErr == nil && iperfResult.Protocol == "UDP" {
		Log("iperf3 UDP reported %.1f%% packet loss", iperfResult.PacketLoss)
		AssertGreaterEqual(iperfResult.PacketLoss, 10.0,
			"iperf3 observed less loss than expected - netem may not have applied")
		AssertLessEqual(iperfResult.PacketLoss, 55.0,
			"iperf3 observed far more loss than configured - unexpected congestion?")
	}

	// Get snapshot of stats from all VPP instances in the chain
	vpps := []*VppInstance{
		s.Containers.Vpp1.VppInstance,
		s.Containers.Vpp2.VppInstance,
		s.Containers.Vpp3.VppInstance,
	}

	findStats := func(vpp *VppInstance, vppNum int) SfdpSessionStats {
		for _, st := range s.GetSfdpSessionStatsFromVpp(vpp) {
			if st.Proto == 17 && st.PacketsFwd > 0 {
				return st
			}
		}
		AssertFail("VPP%d: no UDP session stats with PacketsFwd > 0", vppNum)
		return SfdpSessionStats{}
	}

	st1 := findStats(vpps[0], 1)
	st2 := findStats(vpps[1], 2)
	st3 := findStats(vpps[2], 3)

	Log("UDP loss test - VPP1 fwd=%d rev=%d  VPP2 fwd=%d rev=%d  VPP3 fwd=%d rev=%d",
		st1.PacketsFwd, st1.PacketsRev,
		st2.PacketsFwd, st2.PacketsRev,
		st3.PacketsFwd, st3.PacketsRev)

	// Forward: hop-1 is clean - VPP1 and VPP2 must agree exactly.
	AssertEqual(st1.PacketsFwd, st2.PacketsFwd,
		"VPP1 and VPP2 forward packet counts must match (no loss on hop-1)")
	AssertEqual(st1.BytesFwd, st2.BytesFwd,
		"VPP1 and VPP2 forward byte counts must match (no loss on hop-1)")
	// Forward: hop-2 has loss - VPP2 must have seen more packets and bytes than VPP3.
	AssertGreaterThan(st2.PacketsFwd, st3.PacketsFwd,
		"VPP2 must have seen more forward packets than VPP3 (loss on hop-2 forward)")
	AssertGreaterThan(st2.BytesFwd, st3.BytesFwd,
		"VPP2 must have seen more forward bytes than VPP3 (loss on hop-2 forward)")

	// Reverse: iperf3 UDP sends a single end-of-test report datagram from server to client,
	// so PacketsRev is expected to be exactly 1.  Guard against SFDP silently not tracking
	// reverse traffic (rev=0 across all hops would satisfy equality without proving anything).
	AssertGreaterThan(st1.PacketsRev, uint64(0),
		"VPP1 must have observed at least one reverse UDP packet (iperf3 end-of-test report)")
	AssertEqual(st1.PacketsRev, st2.PacketsRev,
		"VPP1 and VPP2 reverse packet counts must match (no loss on reverse path)")
	AssertEqual(st1.BytesRev, st2.BytesRev,
		"VPP1 and VPP2 reverse byte counts must match (no loss on reverse path)")
	AssertEqual(st2.PacketsRev, st3.PacketsRev,
		"VPP2 and VPP3 reverse packet counts must match (no loss on reverse path)")
	AssertEqual(st2.BytesRev, st3.BytesRev,
		"VPP2 and VPP3 reverse byte counts must match (no loss on reverse path)")
}

// SfdpFaultLocalizationHop2FwdLossTcpTest introduces packet loss on the
// forward path between VPP2 and VPP3, and checks impact on TCP traffic.
//
// Topology:
//
//	cln --> VPP1 --> VPP2 --> [~10% loss] --> VPP3 --> srv   (forward)
//	cln <-- VPP1 <-- VPP2 <----------------- VPP3 <-- srv   (reverse, no loss)
//
// Expected SFDP session stats observations:
//   - Forward: VPP1.pkts_fwd == VPP2.pkts_fwd > VPP3.pkts_fwd  (loss localised to hop-2)
//     VPP1 and VPP2 see original transmissions plus retransmissions triggered by the loss.
//     VPP3 only sees what survives the drop.
//   - Reverse: VPP1.pkts_rev == VPP2.pkts_rev == VPP3.pkts_rev
//     Reverse carries ACKs and dupACKs from the server; All three VPPs see the same reverse packet count
//     within an expected threshold
func SfdpFaultLocalizationHop2FwdLossTcpTest(s *SfdpSuite) {
	serverAddr := s.ServerAddr()
	port := 9996

	serverCmd := exec.Command("ip", "netns", "exec", s.NetNamespaces.Server,
		"iperf3", "-s", "-B", serverAddr, "-p", fmt.Sprintf("%d", port), "--one-off")
	AssertNil(serverCmd.Start())
	defer serverCmd.Process.Kill()
	time.Sleep(100 * time.Millisecond)

	// Start the client in the background so the TCP 3-way handshake completes before
	// loss is injected, then inject loss so only the data stream is affected.
	// This is done to ensure that no packet is dropped during the TCP 3-way handshake
	// & the session is always created in 'established' state in sfdp l4-lifecycle service
	clientCmd := exec.Command("ip", "netns", "exec", s.NetNamespaces.Client,
		"iperf3", "-c", serverAddr, "-p", fmt.Sprintf("%d", port), "-t", "10", "-b", "10M")
	var clientOut bytes.Buffer
	clientCmd.Stdout = &clientOut
	AssertNil(clientCmd.Start())

	vpps := []*VppInstance{
		s.Containers.Vpp1.VppInstance,
		s.Containers.Vpp2.VppInstance,
		s.Containers.Vpp3.VppInstance,
	}

	time.Sleep(1 * time.Second)
	removeNetem := s.ApplyNetemOnHop2Fwd("loss", "10%")
	defer removeNetem()

	// iperf3 opens two TCP sessions: a low-volume control session for
	// parameter exchange and a high-volume data session for the actual test traffic.
	// Collect stats mid-flight (while the data session is still active) since
	// sfdp-l4-lifecycle removes  the session entries from sfdp from on connection close.
	//
	// To ensure we get the stats from the TCP data session for iperf,
	// we select the session in sfdp with the highest PacketsFwd value.
	//
	// All three VPPs are snapshotted concurrently to reduce potential timing drift in statistics
	// and a certain drift threshold is accepted still.
	time.Sleep(5 * time.Second)
	type vppStatResult struct {
		stats SfdpSessionStats
	}
	results := make([]vppStatResult, 3)
	var wg sync.WaitGroup
	for i, vpp := range vpps {
		wg.Add(1)
		go func(idx int, v *VppInstance) {
			defer wg.Done()
			for _, st := range s.GetSfdpSessionStatsFromVpp(v) {
				if st.Proto == 6 && st.PacketsFwd > results[idx].stats.PacketsFwd {
					results[idx].stats = st
				}
			}
		}(i, vpp)
	}
	wg.Wait()
	for i, res := range results {
		AssertGreaterThan(res.stats.PacketsFwd, uint64(0),
			fmt.Sprintf("VPP%d: no TCP session stats with PacketsFwd > 0", i+1))
	}
	st1, st2, st3 := results[0].stats, results[1].stats, results[2].stats

	// Let the client finish cleanly after stats have been collected.
	AssertNil(clientCmd.Wait(), fmt.Sprintf("iperf3 TCP client failed: %s", clientOut.String()))

	Log("TCP loss test - VPP1 fwd=%d rev=%d retr=%d  VPP2 fwd=%d rev=%d retr=%d  VPP3 fwd=%d rev=%d retr=%d",
		st1.PacketsFwd, st1.PacketsRev, st1.Tcp.RetransmissionsFwd,
		st2.PacketsFwd, st2.PacketsRev, st2.Tcp.RetransmissionsFwd,
		st3.PacketsFwd, st3.PacketsRev, st3.Tcp.RetransmissionsFwd)

	// withinPct returns a 2% tolerance on the larger of the two values.
	// This absorbs snapshot drift
	withinPct := func(a, b uint64) uint64 {
		if a > b {
			return uint64(float64(a) * 0.02)
		}
		return uint64(float64(b) * 0.02)
	}

	// Forward: hop-1 is clean - VPP1 and VPP2 must agree within tolerance.
	AssertEqualWithinThreshold(st1.PacketsFwd, st2.PacketsFwd, withinPct(st1.PacketsFwd, st2.PacketsFwd),
		"VPP1 and VPP2 forward packet counts must match (no loss on hop-1)")
	AssertEqualWithinThreshold(st1.BytesFwd, st2.BytesFwd, withinPct(st1.BytesFwd, st2.BytesFwd),
		"VPP1 and VPP2 forward byte counts must match (no loss on hop-1)")
	// Forward: hop-2 has loss - VPP2 must have seen significantly more packets than VPP3.
	AssertGreaterThan(st2.PacketsFwd, uint64(float64(st3.PacketsFwd)*1.05),
		"VPP2 must have seen significantly more forward packets than VPP3 (loss on hop-2 forward)")
	AssertGreaterThan(st2.BytesFwd, uint64(float64(st3.BytesFwd)*1.05),
		"VPP2 must have seen significantly more forward bytes than VPP3 (loss on hop-2 forward)")

	// Retransmission localization: 10% loss on hop-2 forward causes the sender to
	// retransmit. VPP1-VPP2 see both the original transmissions and the retransmissions
	// (all of which traverse hop-1 cleanly). VPP3 only sees what survives the drop,
	// so VPP2 must have observed more or equal retransmissions than VPP3.
	// VPP1 and VPP2 are on a clean hop, so their retransmission counts should match.
	AssertGreaterThan(st2.Tcp.RetransmissionsFwd, uint32(0),
		"VPP2 must have observed retransmissions (10% loss on hop-2 forward)")
	// Check if VPP1/VPP2 report a similar retransmission counter, within a reasonable threshold
	retrThresh := max(uint32(withinPct(uint64(st1.Tcp.RetransmissionsFwd), uint64(st2.Tcp.RetransmissionsFwd))), uint32(5))
	AssertEqualWithinThreshold(st1.Tcp.RetransmissionsFwd, st2.Tcp.RetransmissionsFwd, retrThresh,
		"VPP1 and VPP2 retransmission counts must match (clean hop-1)")
	AssertGreaterEqual(st2.Tcp.RetransmissionsFwd, st3.Tcp.RetransmissionsFwd,
		"VPP2 must have seen at least as many retransmissions as VPP3 (loss localised to hop-2)")

	// Reverse: no loss on the return path - all three VPPs must agree within tolerance.
	// The reverse direction carries ACKs and dupACKs from the server; their count is
	// inflated by the loss (more dupACKs), but that inflation is seen equally by all
	// three hops because there is nothing dropping packets on the reverse side.
	AssertEqualWithinThreshold(st1.PacketsRev, st2.PacketsRev, withinPct(st1.PacketsRev, st2.PacketsRev),
		"VPP1 and VPP2 reverse packet counts must match (no loss on reverse path)")
	AssertEqualWithinThreshold(st1.BytesRev, st2.BytesRev, withinPct(st1.BytesRev, st2.BytesRev),
		"VPP1 and VPP2 reverse byte counts must match (no loss on reverse path)")
	AssertEqualWithinThreshold(st2.PacketsRev, st3.PacketsRev, withinPct(st2.PacketsRev, st3.PacketsRev),
		"VPP2 and VPP3 reverse packet counts must match (no loss on reverse path)")
	AssertEqualWithinThreshold(st2.BytesRev, st3.BytesRev, withinPct(st2.BytesRev, st3.BytesRev),
		"VPP2 and VPP3 reverse byte counts must match (no loss on reverse path)")
}

func SfdpTcpSessionCreatedTest(s *SfdpSuite) {
	serverAddr := s.ServerAddr()
	port := 9998

	serverCmd := exec.Command("ip", "netns", "exec", s.NetNamespaces.Server,
		"iperf3", "-s", "-B", serverAddr, "-p", fmt.Sprintf("%d", port), "--one-off")
	AssertNil(serverCmd.Start())
	defer serverCmd.Process.Kill()
	time.Sleep(100 * time.Millisecond)

	// Use a long duration so the sessions are still active when stats are queried.
	// sfdp-l4-lifecycle removes TCP session entries on connection close, so all
	// assertions must be made while iperf3 is still running.
	clientCmd := exec.Command("ip", "netns", "exec", s.NetNamespaces.Client,
		"iperf3", "-c", serverAddr, "-p", fmt.Sprintf("%d", port), "-t", "10")
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

	// Check SFDP Session Stats on each VPP instance in the chain
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

// SfdpFaultLocalizationHop2FwdReorderTcpTest verifies per-hop TCP out-of-order
// localisation via SFDP session stats when a forward-path reorder impairment is
// applied between VPP2 and VPP3.
//
// Topology:
//
//	cln --> VPP1 --> VPP2 --> [5ms / 25% reorder / 50% corr] --> VPP3 --> srv   (forward)
//	cln <-- VPP1 <-- VPP2 <-- VPP3 <-- [50ms delay in srv netns] <-- srv        (reverse)
//
// Expected SFDP session stats observations:
//   - Forward: pkts roughly equal across all three hops (reorder, no drops).
//   - VPP3.ooo_fwd > 0 and VPP3.ooo_fwd > VPP1.ooo_fwd / VPP2.ooo_fwd
//     (OOO localised to impaired-and-downstream hop).
//   - Reverse: pkts roughly equal across all three hops (reverse netem is in
//     srv netns, downstream of every VPP).
func SfdpFaultLocalizationHop2FwdReorderTcpTest(s *SfdpSuite) {
	serverAddr := s.ServerAddr()
	port := 9995

	// Apply 50ms reverse-path delay in the server netns *before* iperf3 starts
	// This lets the out-of-order branch fire, since it loses the dupACK race for any
	// reordered forward fill.
	removeRevDelay := s.ApplyNetem(s.NetNamespaces.Server, s.Interfaces.Server.Host.Name(),
		"delay", "50ms")
	defer removeRevDelay()

	serverCmd := exec.Command("ip", "netns", "exec", s.NetNamespaces.Server,
		"iperf3", "-s", "-B", serverAddr, "-p", fmt.Sprintf("%d", port), "--one-off")
	AssertNil(serverCmd.Start())
	defer serverCmd.Process.Kill()
	time.Sleep(100 * time.Millisecond)

	clientCmd := exec.Command("ip", "netns", "exec", s.NetNamespaces.Client,
		"iperf3", "-c", serverAddr, "-p", fmt.Sprintf("%d", port), "-t", "15", "-b", "10M")
	var clientOut bytes.Buffer
	clientCmd.Stdout = &clientOut
	AssertNil(clientCmd.Start())

	vpps := []*VppInstance{
		s.Containers.Vpp1.VppInstance,
		s.Containers.Vpp2.VppInstance,
		s.Containers.Vpp3.VppInstance,
	}

	// Wait 1s before injecting reorder so both iperf3 control + data TCP
	// handshakes complete cleanly without reorder noise.
	time.Sleep(1 * time.Second)
	removeReorder := s.ApplyNetemOnHop2Fwd("delay", "5ms", "reorder", "25%", "50%")
	defer removeReorder()

	// Collect stats while sessions are still active in SFDP
	time.Sleep(8 * time.Second)
	type vppStatResult struct {
		stats SfdpSessionStats
	}
	results := make([]vppStatResult, 3)
	var wg sync.WaitGroup
	for i, vpp := range vpps {
		wg.Add(1)
		go func(idx int, v *VppInstance) {
			defer wg.Done()
			for _, st := range s.GetSfdpSessionStatsFromVpp(v) {
				if st.Proto == 6 && st.PacketsFwd > results[idx].stats.PacketsFwd {
					results[idx].stats = st
				}
			}
		}(i, vpp)
	}
	wg.Wait()
	for i, res := range results {
		AssertGreaterThan(res.stats.PacketsFwd, uint64(0),
			fmt.Sprintf("VPP%d: no TCP session stats with PacketsFwd > 0", i+1))
	}
	st1, st2, st3 := results[0].stats, results[1].stats, results[2].stats

	AssertNil(clientCmd.Wait(), fmt.Sprintf("iperf3 TCP client failed: %s", clientOut.String()))

	Log("Reorder test - VPP1 fwd=%d rev=%d retr=%d ooo=%d  VPP2 fwd=%d rev=%d retr=%d ooo=%d  VPP3 fwd=%d rev=%d retr=%d ooo=%d",
		st1.PacketsFwd, st1.PacketsRev, st1.Tcp.RetransmissionsFwd, st1.Tcp.OooFwd,
		st2.PacketsFwd, st2.PacketsRev, st2.Tcp.RetransmissionsFwd, st2.Tcp.OooFwd,
		st3.PacketsFwd, st3.PacketsRev, st3.Tcp.RetransmissionsFwd, st3.Tcp.OooFwd)

	withinPct := func(a, b uint64) uint64 {
		if a > b {
			return uint64(float64(a) * 0.05)
		}
		return uint64(float64(b) * 0.05)
	}

	// Forward: pure reorder, no drops - all three hops see roughly the same
	// packet/byte counts within acceptable threshold (5%)
	AssertEqualWithinThreshold(st1.PacketsFwd, st2.PacketsFwd, withinPct(st1.PacketsFwd, st2.PacketsFwd),
		"VPP1 and VPP2 forward packet counts must match (no loss on hop-1)")
	AssertEqualWithinThreshold(st2.PacketsFwd, st3.PacketsFwd, withinPct(st2.PacketsFwd, st3.PacketsFwd),
		"VPP2 and VPP3 forward packet counts must match (reorder only, no loss)")

	// OOO localization: VPP3 must have non-zero forward out-of-order counter from the reordering.
	// VPP1-VPP2 might have non-zero out-of-order counters too, but our expectation
	// is that there is a directional bump and that VPP3.OOO > VPP2.OOO and VPP3.OOO > VPP1.OOO is what matters.
	AssertGreaterThan(st3.Tcp.OooFwd, uint32(0),
		"VPP3 must observe forward OOO (reorder on hop-2 forward)")
	// Check if VPP1/VPP2 report a similar out-of-order counter, within a reasonable threshold
	oooThresh := max(uint32(withinPct(uint64(st1.Tcp.OooFwd), uint64(st2.Tcp.OooFwd))), uint32(5))
	AssertEqualWithinThreshold(st1.Tcp.OooFwd, st2.Tcp.OooFwd, oooThresh,
		"VPP1 and VPP2 OOO counts must match (clean hop-1)")
	AssertGreaterThan(st3.Tcp.OooFwd, st1.Tcp.OooFwd,
		"VPP3 must observe more forward OOO than VPP1 (OOO localised to hop-2 forward)")
	AssertGreaterThan(st3.Tcp.OooFwd, st2.Tcp.OooFwd,
		"VPP3 must observe more forward OOO than VPP2 (OOO localised to hop-2 forward)")

	// Re-ordering causes VPP3 to see reordered segments as potential retransmissions
	retrThresh := max(uint32(withinPct(uint64(st1.Tcp.RetransmissionsFwd), uint64(st2.Tcp.RetransmissionsFwd))), uint32(5))
	AssertEqualWithinThreshold(st1.Tcp.RetransmissionsFwd, st2.Tcp.RetransmissionsFwd, retrThresh,
		"VPP1 and VPP2 retransmission counts must match (clean hop-1)")
	AssertGreaterThan(st3.Tcp.RetransmissionsFwd, st1.Tcp.RetransmissionsFwd,
		"VPP3 must observe more forward retransmissions than VPP1 (reorder localised to hop-2 forward)")
	AssertGreaterThan(st3.Tcp.RetransmissionsFwd, st2.Tcp.RetransmissionsFwd,
		"VPP3 must observe more forward retransmissions than VPP2 (reorder localised to hop-2 forward)")

	// All three VPPs should see the same delayed reverse stream, as tc netem is not applied
	// on the reverse stream
	AssertEqualWithinThreshold(st1.PacketsRev, st2.PacketsRev, withinPct(st1.PacketsRev, st2.PacketsRev),
		"VPP1 and VPP2 reverse packet counts must match (no loss on reverse path)")
	AssertEqualWithinThreshold(st2.PacketsRev, st3.PacketsRev, withinPct(st2.PacketsRev, st3.PacketsRev),
		"VPP2 and VPP3 reverse packet counts must match (no loss on reverse path)")
}
