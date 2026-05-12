// SFDP test suite: three-VPP service chain topology.
//
//	netns "cln" <--> VPP1 (SFDP) <--> VPP2 (SFDP) <--> VPP3 (SFDP) <--> netns "srv"
//
// Two inter-VPP veth pairs are bridged by the host so that tc-netem can be
// applied independently on each hop and in each direction, enabling per-hop
// fault localisation tests.

package hst

import (
	"fmt"
	"os/exec"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
)

type SfdpSuite struct {
	HstSuite
	Interfaces struct {
		Client *NetInterface // hclnvpp1: client-netns <-> VPP1
		V1V2   *NetInterface // hv1v2:    VPP1 side of hop-1 link
		V2V1   *NetInterface // hv2v1:    VPP2 side of hop-1 link
		V2V3   *NetInterface // hv2v3:    VPP2 side of hop-2 link
		V3V2   *NetInterface // hv3v2:    VPP3 side of hop-2 link
		Server *NetInterface // hsrvvpp3: VPP3 <-> server-netns
	}
	Containers struct {
		Vpp1 *Container
		Vpp2 *Container
		Vpp3 *Container
	}
	NetNamespaces struct {
		Client string
		Server string
	}
}

var sfdpTests = map[string][]func(s *SfdpSuite){}

func RegisterSfdpTests(tests ...func(s *SfdpSuite)) {
	sfdpTests[GetTestFilename()] = tests
}

func (s *SfdpSuite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.ConfigureNetworkTopology("sfdp")
	s.LoadContainerTopology("sfdp")
	s.Interfaces.Client = s.GetInterfaceByName("hclnvpp1")
	s.Interfaces.V1V2 = s.GetInterfaceByName("hv1v2")
	s.Interfaces.V2V1 = s.GetInterfaceByName("hv2v1")
	s.Interfaces.V2V3 = s.GetInterfaceByName("hv2v3")
	s.Interfaces.V3V2 = s.GetInterfaceByName("hv3v2")
	s.Interfaces.Server = s.GetInterfaceByName("hsrvvpp3")
	s.NetNamespaces.Client = s.GetNetNamespaceByName("cln")
	s.NetNamespaces.Server = s.GetNetNamespaceByName("srv")
	s.Containers.Vpp1 = s.GetContainerByName("vpp1")
	s.Containers.Vpp2 = s.GetContainerByName("vpp2")
	s.Containers.Vpp3 = s.GetContainerByName("vpp3")
}

func (s *SfdpSuite) SetupTest() {
	s.HstSuite.SetupTest()

	vpp1, err := s.Containers.Vpp1.newVppInstance(s.Containers.Vpp1.AllocatedCpus)
	AssertNotNil(vpp1, fmt.Sprint(err))
	AssertNil(vpp1.Start())

	vpp2, err := s.Containers.Vpp2.newVppInstance(s.Containers.Vpp2.AllocatedCpus)
	AssertNotNil(vpp2, fmt.Sprint(err))
	AssertNil(vpp2.Start())

	vpp3, err := s.Containers.Vpp3.newVppInstance(s.Containers.Vpp3.AllocatedCpus)
	AssertNotNil(vpp3, fmt.Sprint(err))
	AssertNil(vpp3.Start())

	/* TODO - We are currently enforcing single RX/TX queues for af-packet interfaces */
	/* We should ideally test with an appropriate multi-queue setup */
	createIf := func(vpp *VppInstance, iface *NetInterface) {
		idx, e := vpp.createAfPacket(iface, false, WithNumRxQueues(1), WithNumTxQueues(1))
		AssertNil(e, fmt.Sprint(e))
		AssertNotEqual(0, idx)
	}

	createIf(vpp1, s.Interfaces.Client)
	createIf(vpp1, s.Interfaces.V1V2)
	createIf(vpp2, s.Interfaces.V2V1)
	createIf(vpp2, s.Interfaces.V2V3)
	createIf(vpp3, s.Interfaces.V3V2)
	createIf(vpp3, s.Interfaces.Server)

	setNeigh := func(vpp *VppInstance, iface *NetInterface, peerIP string, peerMAC any) {
		Log(vpp.Vppctl(fmt.Sprintf("set ip neighbor %s %s %s",
			iface.VppName(), peerIP, peerMAC)))
	}

	// Client-netns route: reach server via VPP1 client-side address
	cmd := exec.Command("ip", "netns", "exec", s.NetNamespaces.Client,
		"ip", "route", "replace", s.ServerAddr(), "via", s.Interfaces.Client.Ip4AddressString())
	Log(cmd.String())
	o, err2 := cmd.CombinedOutput()
	AssertNil(err2, string(o))

	// Server-netns route: reach client via VPP3 server-side address
	cmd = exec.Command("ip", "netns", "exec", s.NetNamespaces.Server,
		"ip", "route", "replace", s.Interfaces.Client.Host.Ip4AddressString()+"/32",
		"via", s.Interfaces.Server.Ip4AddressString())
	Log(cmd.String())
	o, err2 = cmd.CombinedOutput()
	AssertNil(err2, string(o))

	// VPP1: knows client host and next-hop VPP2 side of hop-1
	setNeigh(vpp1, s.Interfaces.Client, s.Interfaces.Client.Host.Ip4AddressString(), s.Interfaces.Client.Host.HwAddress)
	setNeigh(vpp1, s.Interfaces.V1V2, s.Interfaces.V2V1.Ip4AddressString(), s.Interfaces.V2V1.HwAddress)
	Log(vpp1.Vppctl(fmt.Sprintf("ip route add %s/32 via %s %s",
		s.ServerAddr(), s.Interfaces.V2V1.Ip4AddressString(), s.Interfaces.V1V2.VppName())))
	Log(vpp1.Vppctl(fmt.Sprintf("ip route add %s/32 via %s %s",
		s.Interfaces.Client.Host.Ip4AddressString(), s.Interfaces.Client.Host.Ip4AddressString(), s.Interfaces.Client.VppName())))

	// VPP2: bridges hop-1 and hop-2
	setNeigh(vpp2, s.Interfaces.V2V1, s.Interfaces.V1V2.Ip4AddressString(), s.Interfaces.V1V2.HwAddress)
	setNeigh(vpp2, s.Interfaces.V2V3, s.Interfaces.V3V2.Ip4AddressString(), s.Interfaces.V3V2.HwAddress)
	Log(vpp2.Vppctl(fmt.Sprintf("ip route add %s/32 via %s %s",
		s.ServerAddr(), s.Interfaces.V3V2.Ip4AddressString(), s.Interfaces.V2V3.VppName())))
	Log(vpp2.Vppctl(fmt.Sprintf("ip route add %s/32 via %s %s",
		s.Interfaces.Client.Host.Ip4AddressString(), s.Interfaces.V1V2.Ip4AddressString(), s.Interfaces.V2V1.VppName())))

	// VPP3: knows server host and next-hop VPP2 side of hop-2
	setNeigh(vpp3, s.Interfaces.V3V2, s.Interfaces.V2V3.Ip4AddressString(), s.Interfaces.V2V3.HwAddress)
	setNeigh(vpp3, s.Interfaces.Server, s.Interfaces.Server.Host.Ip4AddressString(), s.Interfaces.Server.Host.HwAddress)
	Log(vpp3.Vppctl(fmt.Sprintf("ip route add %s/32 via %s %s",
		s.Interfaces.Client.Host.Ip4AddressString(), s.Interfaces.V2V3.Ip4AddressString(), s.Interfaces.V3V2.VppName())))
	Log(vpp3.Vppctl(fmt.Sprintf("ip route add %s/32 via %s %s",
		s.ServerAddr(), s.Interfaces.Server.Host.Ip4AddressString(), s.Interfaces.Server.VppName())))

	// SFDP on all three VPPs
	for _, vpp := range []*VppInstance{vpp1, vpp2, vpp3} {
		Log(vpp.Vppctl("sfdp tenant add 1 context 0"))
		Log(vpp.Vppctl("set sfdp services tenant 1 sfdp-l4-lifecycle sfdp-session-stats ip4-lookup forward"))
		Log(vpp.Vppctl("set sfdp services tenant 1 sfdp-l4-lifecycle sfdp-session-stats ip4-lookup reverse"))
	}
	Log(vpp1.Vppctl(fmt.Sprintf("set sfdp interface-input %s tenant 1", s.Interfaces.Client.VppName())))
	Log(vpp1.Vppctl(fmt.Sprintf("set sfdp interface-input %s tenant 1", s.Interfaces.V1V2.VppName())))
	Log(vpp2.Vppctl(fmt.Sprintf("set sfdp interface-input %s tenant 1", s.Interfaces.V2V1.VppName())))
	Log(vpp2.Vppctl(fmt.Sprintf("set sfdp interface-input %s tenant 1", s.Interfaces.V2V3.VppName())))
	Log(vpp3.Vppctl(fmt.Sprintf("set sfdp interface-input %s tenant 1", s.Interfaces.V3V2.VppName())))
	Log(vpp3.Vppctl(fmt.Sprintf("set sfdp interface-input %s tenant 1", s.Interfaces.Server.VppName())))

	if *DryRun {
		s.LogStartedContainers()
		Log("%s* SFDP Chain Configuration:%s", Colors.pur, Colors.rst)
		Log("  VPP1 interfaces: %s, %s", s.Interfaces.Client.VppName(), s.Interfaces.V1V2.VppName())
		Log("  VPP2 interfaces: %s, %s", s.Interfaces.V2V1.VppName(), s.Interfaces.V2V3.VppName())
		Log("  VPP3 interfaces: %s, %s", s.Interfaces.V3V2.VppName(), s.Interfaces.Server.VppName())
		s.Skip("Dry run mode = true")
	}

	// Verify end-to-end connectivity. ICMP creates an SFDP session but tests
	// filter by proto (TCP/UDP) so the ICMP entry does not skew assertions.
	pingCmd := exec.Command("ip", "netns", "exec", s.NetNamespaces.Client,
		"ping", "-c", "2", "-W", "1", s.ServerAddr())
	Log(pingCmd.String())
	out, pingErr := pingCmd.CombinedOutput()
	Log(string(out))
	AssertNil(pingErr, fmt.Sprintf("chain connectivity check failed (ping %s):\n%s", s.ServerAddr(), string(out)))
}

func (s *SfdpSuite) TeardownTest() {
	defer s.HstSuite.TeardownTest()
	for _, c := range []*Container{s.Containers.Vpp1, s.Containers.Vpp2, s.Containers.Vpp3} {
		if c.VppInstance != nil && CurrentSpecReport().Failed() {
			Log(c.VppInstance.Vppctl("show sfdp session-table"))
			Log(c.VppInstance.Vppctl("show sfdp session stats verbose"))
			Log(c.VppInstance.Vppctl("show interface"))
			Log(c.VppInstance.Vppctl("show error"))
		}
	}
}

func (s *SfdpSuite) ServerAddr() string {
	return s.Interfaces.Server.Host.Ip4AddressString()
}

// Stripping ANSI codes is required for SFDP CLI output
// since tables might output entries with ANSI color codes.
var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripAnsi(s string) string {
	return ansiEscape.ReplaceAllString(s, "")
}

// TODO - we currently use regex to parse CLI output for
// SFDP session table and SFDP session stats.
// We should ideally move towards using the SFDP APIs to fetch
// this information (requires support for SFDP APIs in govpp)

// ApplyNetem applies tc-netem to an interface inside a network namespace.
// Returns a cleanup function that removes the qdisc.
func (s *SfdpSuite) ApplyNetem(netns string, iface string, args ...string) func() {
	fullArgs := []string{"netns", "exec", netns, "tc", "qdisc", "add", "dev", iface, "root", "netem"}
	fullArgs = append(fullArgs, args...)
	cmd := exec.Command("ip", fullArgs...)
	Log(cmd.String())
	o, err := cmd.CombinedOutput()
	AssertNil(err, string(o))
	return func() {
		exec.Command("ip", "netns", "exec", netns, "tc", "qdisc", "del", "dev", iface, "root").Run()
	}
}

// SfdpSessionStatsTcp holds TCP-specific counters parsed from the verbose CLI output.
// Fields match what cli.c emits for TCP sessions.
type SfdpSessionStatsTcp struct {
	SynPackets         uint32
	FinPackets         uint32
	RstPackets         uint32
	HandshakeComplete  uint8
	MssFwd             uint32
	MssRev             uint32
	SynRtt             float64
	TsNegotiated       bool
	DataPacketsFwd     uint64
	DataPacketsRev     uint64
	RetransmissionsFwd uint32
	RetransmissionsRev uint32
	ZeroWindowFwd      uint32
	ZeroWindowRev      uint32
	OooFwd             uint32
	OooRev             uint32
	EcnEct             uint32
	EcnCe              uint32
	Ece                uint32
	Cwr                uint32
}

type SfdpSessionStats struct {
	SessionId  string
	Proto      int
	Tenant     int
	PacketsFwd uint64
	PacketsRev uint64
	BytesFwd   uint64
	BytesRev   uint64
	Tcp        SfdpSessionStatsTcp
}

type SfdpSession struct {
	Id     string
	Tenant string
	Proto  string
	State  string
}

// parseSfdpSessionStats parses "show sfdp session stats verbose" output into
// SfdpSessionStats structs. The current CLI format for TCP sessions is:
//
//	TCP: syn=N fin=N rst=N hs=N mss(fwd/rev)=N/N syn-rtt=N.N timestamp-option-negotiated=yes|no
//	TCP data: pkts(fwd/rev)=N/N
//	TCP ev: retr(fwd/rev)=N/N zero-win(fwd/rev)=N/N ooo(fwd/rev)=N/N
//	TCP seq: last-seq(fwd/rev)=N/N last-ack(fwd/rev)=N/N
//	TCP ecn: ect=N ce=N ece=N cwr=N
func parseSfdpSessionStats(showOut string) []SfdpSessionStats {
	reSession := regexp.MustCompile(`(?m)^\s*(0x[0-9a-fA-F]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$`)
	reTcp := regexp.MustCompile(`TCP: syn=(\d+) fin=(\d+) rst=(\d+) hs=(\d+) mss\(fwd/rev\)=(\d+)/(\d+) syn-rtt=([0-9.]+) timestamp-option-negotiated=(yes|no)`)
	reTcpData := regexp.MustCompile(`TCP data: pkts\(fwd/rev\)=(\d+)/(\d+)`)
	reTcpEv := regexp.MustCompile(`TCP ev: retr\(fwd/rev\)=(\d+)/(\d+) zero-win\(fwd/rev\)=(\d+)/(\d+) ooo\(fwd/rev\)=(\d+)/(\d+)`)
	reTcpEcn := regexp.MustCompile(`TCP ecn: ect=(\d+) ce=(\d+) ece=(\d+) cwr=(\d+)`)

	u32 := func(s string) uint32 {
		v, _ := strconv.ParseUint(s, 10, 32)
		return uint32(v)
	}
	u64 := func(s string) uint64 {
		v, _ := strconv.ParseUint(s, 10, 64)
		return v
	}
	f64 := func(s string) float64 {
		v, _ := strconv.ParseFloat(s, 64)
		return v
	}

	var sessions []SfdpSessionStats
	matches := reSession.FindAllStringSubmatch(showOut, -1)
	for _, m := range matches {
		proto, _ := strconv.Atoi(m[2])
		tenant, _ := strconv.Atoi(m[3])
		sessions = append(sessions, SfdpSessionStats{
			SessionId:  m[1],
			Proto:      proto,
			Tenant:     tenant,
			PacketsFwd: u64(m[4]),
			PacketsRev: u64(m[5]),
			BytesFwd:   u64(m[6]),
			BytesRev:   u64(m[7]),
		})
	}

	tcpMatches := reTcp.FindAllStringSubmatch(showOut, -1)
	tcpDataMatches := reTcpData.FindAllStringSubmatch(showOut, -1)
	tcpEvMatches := reTcpEv.FindAllStringSubmatch(showOut, -1)
	tcpEcnMatches := reTcpEcn.FindAllStringSubmatch(showOut, -1)

	// Only TCP sessions emit TCP detail blocks
	tcpIdx := 0
	for i := range sessions {
		if sessions[i].Proto != 6 {
			continue
		}
		if tcpIdx < len(tcpMatches) {
			m := tcpMatches[tcpIdx]
			sessions[i].Tcp.SynPackets = u32(m[1])
			sessions[i].Tcp.FinPackets = u32(m[2])
			sessions[i].Tcp.RstPackets = u32(m[3])
			hs, _ := strconv.ParseUint(m[4], 10, 8)
			sessions[i].Tcp.HandshakeComplete = uint8(hs)
			sessions[i].Tcp.MssFwd = u32(m[5])
			sessions[i].Tcp.MssRev = u32(m[6])
			sessions[i].Tcp.SynRtt = f64(m[7])
			sessions[i].Tcp.TsNegotiated = m[8] == "yes"
		}
		if tcpIdx < len(tcpDataMatches) {
			m := tcpDataMatches[tcpIdx]
			sessions[i].Tcp.DataPacketsFwd = u64(m[1])
			sessions[i].Tcp.DataPacketsRev = u64(m[2])
		}
		if tcpIdx < len(tcpEvMatches) {
			m := tcpEvMatches[tcpIdx]
			sessions[i].Tcp.RetransmissionsFwd = u32(m[1])
			sessions[i].Tcp.RetransmissionsRev = u32(m[2])
			sessions[i].Tcp.ZeroWindowFwd = u32(m[3])
			sessions[i].Tcp.ZeroWindowRev = u32(m[4])
			sessions[i].Tcp.OooFwd = u32(m[5])
			sessions[i].Tcp.OooRev = u32(m[6])
		}
		if tcpIdx < len(tcpEcnMatches) {
			m := tcpEcnMatches[tcpIdx]
			sessions[i].Tcp.EcnEct = u32(m[1])
			sessions[i].Tcp.EcnCe = u32(m[2])
			sessions[i].Tcp.Ece = u32(m[3])
			sessions[i].Tcp.Cwr = u32(m[4])
		}
		tcpIdx++
	}
	return sessions
}

// parseSfdpSessions parses "show sfdp session-table unsafe-show-all" output into SfdpSession structs.
func parseSfdpSessions(showOut string) []SfdpSession {
	var sessions []SfdpSession
	for _, line := range strings.Split(showOut, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 11 && strings.HasPrefix(fields[0], "0x") {
			sessions = append(sessions, SfdpSession{
				Id:     fields[0],
				Tenant: fields[1],
				Proto:  fields[5],
				State:  fields[9],
			})
		}
	}
	return sessions
}

// GetSfdpSessionStatsFromVpp returns parsed session stats from a specific VPP instance.
// Retries up to 10 times (200ms apart) until at least one session is found.
func (s *SfdpSuite) GetSfdpSessionStatsFromVpp(vpp *VppInstance) []SfdpSessionStats {
	var sessions []SfdpSessionStats
	var showOut string
	for i := 0; i < 10; i++ {
		showOut = stripAnsi(vpp.Vppctl("show sfdp session stats verbose"))
		sessions = parseSfdpSessionStats(showOut)
		if len(sessions) > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	Log(showOut)
	return sessions
}

// GetSfdpSessionsFromVpp polls and parses session-table entries from a specific VPP instance.
// Retries up to 10 times (200ms apart) until at least one session is found.
func (s *SfdpSuite) GetSfdpSessionsFromVpp(vpp *VppInstance) []SfdpSession {
	var sessions []SfdpSession
	var showOut string
	for i := 0; i < 10; i++ {
		showOut = stripAnsi(vpp.Vppctl("show sfdp session-table unsafe-show-all"))
		sessions = parseSfdpSessions(showOut)
		if len(sessions) > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	Log(showOut)
	return sessions
}

// NetemStats holds the counters reported by "tc -s qdisc show" for a netem qdisc.
// Only dropped packets (from loss impairments) are directly observable here;
// delayed and reordered packets are not separately counted by the kernel.
type NetemStats struct {
	SentBytes   uint64
	SentPkts    uint64
	DroppedPkts uint64
}

// GetNetemStats returns the current counters for the netem qdisc on iface and
// logs the raw output. Returns an error if no netem qdisc is present.
func GetNetemStats(iface string) (NetemStats, error) {
	cmd := exec.Command("tc", "-s", "qdisc", "show", "dev", iface)
	out, err := cmd.CombinedOutput()
	Log("tc -s qdisc show dev %s:\n%s", iface, string(out))
	if err != nil {
		return NetemStats{}, fmt.Errorf("tc -s qdisc show dev %s: %w", iface, err)
	}

	raw := string(out)
	if !strings.Contains(raw, "netem") {
		return NetemStats{}, fmt.Errorf("no netem qdisc found on %s", iface)
	}

	// "Sent 1234 bytes 20 pkt (dropped 1, overlimits 0 requeues 0)"
	reSent := regexp.MustCompile(`Sent\s+(\d+)\s+bytes\s+(\d+)\s+pkt\s+\(dropped\s+(\d+)`)
	m := reSent.FindStringSubmatch(raw)
	if m == nil {
		return NetemStats{}, fmt.Errorf("could not parse tc stats from: %s", raw)
	}
	var ns NetemStats
	fmt.Sscanf(m[1], "%d", &ns.SentBytes)
	fmt.Sscanf(m[2], "%d", &ns.SentPkts)
	fmt.Sscanf(m[3], "%d", &ns.DroppedPkts)
	return ns, nil
}

// applyNetem applies a tc-netem root qdisc on iface and returns a cleanup function.
func applyNetem(iface string, args []string) func() {
	fullArgs := append([]string{"qdisc", "add", "dev", iface, "root", "netem"}, args...)
	cmd := exec.Command("tc", fullArgs...)
	Log(cmd.String())
	o, err := cmd.CombinedOutput()
	AssertNil(err, string(o))
	return func() {
		exec.Command("tc", "qdisc", "del", "dev", iface, "root").Run()
	}
}

// Hop-1 is the VPP1<->VPP2 link. The two sides of the bridge are:
//   - vpp1side  (V1V2.Host): egress here impairs VPP2->VPP1 traffic (reverse)
//   - vpp2sidea (V2V1.Host): egress here impairs VPP1->VPP2 traffic (forward)

// ApplyNetemOnHop1Fwd impairs VPP1->VPP2 (forward) on hop-1.
func (s *SfdpSuite) ApplyNetemOnHop1Fwd(args ...string) func() {
	return applyNetem(s.Interfaces.V2V1.Host.Name(), args)
}

// ApplyNetemOnHop1Rev impairs VPP2->VPP1 (reverse) on hop-1.
func (s *SfdpSuite) ApplyNetemOnHop1Rev(args ...string) func() {
	return applyNetem(s.Interfaces.V1V2.Host.Name(), args)
}

// Hop-2 is the VPP2<->VPP3 link. The two sides of the bridge are:
//   - vpp2sideb (V2V3.Host): egress here impairs VPP3->VPP2 traffic (reverse)
//   - vpp3side  (V3V2.Host): egress here impairs VPP2->VPP3 traffic (forward)

// ApplyNetemOnHop2Fwd impairs VPP2->VPP3 (forward) on hop-2.
func (s *SfdpSuite) ApplyNetemOnHop2Fwd(args ...string) func() {
	return applyNetem(s.Interfaces.V3V2.Host.Name(), args)
}

// ApplyNetemOnHop2Rev impairs VPP3->VPP2 (reverse) on hop-2.
func (s *SfdpSuite) ApplyNetemOnHop2Rev(args ...string) func() {
	return applyNetem(s.Interfaces.V2V3.Host.Name(), args)
}

var _ = Describe("SfdpSuite", Ordered, ContinueOnFailure, Serial, Label("SFDP"), func() {
	var s SfdpSuite
	BeforeAll(func() {
		s.SetupSuite()
	})
	BeforeEach(func() {
		s.SetupTest()
	})
	AfterAll(func() {
		s.TeardownSuite()
	})
	AfterEach(func() {
		s.TeardownTest()
	})

	for filename, tests := range sfdpTests {
		for _, test := range tests {
			test := test
			pc := reflect.ValueOf(test).Pointer()
			funcValue := runtime.FuncForPC(pc)
			testName := filename + "/" + strings.Split(funcValue.Name(), ".")[2]
			It(testName, func(ctx SpecContext) {
				Log("[* TEST BEGIN]: " + testName)
				test(&s)
			}, SpecTimeout(TestTimeout))
		}
	}
})
