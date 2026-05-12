// The topology consists of 1 VPP container acting as an L3 forwarder with SFDP session tracking.
// Client and server are isolated in separate network namespaces; all traffic must traverse VPP.
//
//  +----------------+       +------------------------------------------+       +----------------+
//  | netns "cln"    |       |               VPP (SFDP)                 |       | netns "srv"    |
//  |                |       |                                          |       |                |
//  | client app     |       |  af_packet(hclnvpp) -> af_packet(hsrvvpp)|       | echo server    |
//  |    10.x.1.1  --+-veth--+--  10.x.1.2           10.x.2.2  --------+-veth--+--  10.x.2.1    |
//  +----------------+       +------------------------------------------+       +----------------+

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
		Client *NetInterface
		Server *NetInterface
	}
	Containers struct {
		Vpp *Container
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
	s.LoadContainerTopology("single")
	s.Interfaces.Client = s.GetInterfaceByName("hclnvpp")
	s.Interfaces.Server = s.GetInterfaceByName("hsrvvpp")
	s.NetNamespaces.Client = s.GetNetNamespaceByName("cln")
	s.NetNamespaces.Server = s.GetNetNamespaceByName("srv")
	s.Containers.Vpp = s.GetContainerByName("vpp")
}

func (s *SfdpSuite) SetupTest() {
	s.HstSuite.SetupTest()

	vpp, err := s.Containers.Vpp.newVppInstance(s.Containers.Vpp.AllocatedCpus)
	AssertNotNil(vpp, fmt.Sprint(err))

	AssertNil(vpp.Start())

	/* TODO - We are currently enforcing single RX/TX queues for af-packet interfaces */
	/* We should ideally test with an appropriate multi-queue setup */
	idx, err := vpp.createAfPacket(s.Interfaces.Client, false, WithNumRxQueues(1), WithNumTxQueues(1))
	AssertNil(err, fmt.Sprint(err))
	AssertNotEqual(0, idx)

	idx, err = vpp.createAfPacket(s.Interfaces.Server, false, WithNumRxQueues(1), WithNumTxQueues(1))
	AssertNil(err, fmt.Sprint(err))
	AssertNotEqual(0, idx)

	// Client netns configuration
	cmd := exec.Command("ip", "netns", "exec", s.NetNamespaces.Client,
		"ip", "route", "replace", s.ServerAddr(), "via", s.Interfaces.Client.Ip4AddressString())
	Log(cmd.String())
	o, err2 := cmd.CombinedOutput()
	AssertNil(err2, string(o))

	// Server netns configuration
	cmd = exec.Command("ip", "netns", "exec", s.NetNamespaces.Server,
		"ip", "route", "replace", s.Interfaces.Client.Host.Ip4AddressString()+"/32",
		"via", s.Interfaces.Server.Ip4AddressString())
	Log(cmd.String())
	o, err2 = cmd.CombinedOutput()
	AssertNil(err2, string(o))

	arp := fmt.Sprintf("set ip neighbor %s %s %s",
		s.Interfaces.Client.VppName(),
		s.Interfaces.Client.Host.Ip4AddressString(),
		s.Interfaces.Client.Host.HwAddress)
	Log(vpp.Vppctl(arp))

	arp = fmt.Sprintf("set ip neighbor %s %s %s",
		s.Interfaces.Server.VppName(),
		s.Interfaces.Server.Host.Ip4AddressString(),
		s.Interfaces.Server.Host.HwAddress)
	Log(vpp.Vppctl(arp))

	/* Configuring SFDP, with single tenant and L4 lifecycle / session stats */
	/* on input feature arc of client and server interface */
	Log(vpp.Vppctl("sfdp tenant add 1 context 0"))
	Log(vpp.Vppctl("set sfdp services tenant 1 sfdp-l4-lifecycle sfdp-session-stats ip4-lookup forward"))
	Log(vpp.Vppctl("set sfdp services tenant 1 sfdp-l4-lifecycle sfdp-session-stats ip4-lookup reverse"))
	Log(vpp.Vppctl(fmt.Sprintf("set sfdp interface-input %s tenant 1", s.Interfaces.Client.VppName())))
	Log(vpp.Vppctl(fmt.Sprintf("set sfdp interface-input %s tenant 1", s.Interfaces.Server.VppName())))

	if *DryRun {
		s.LogStartedContainers()
		Log("%s* SFDP Configuration:%s", Colors.pur, Colors.rst)
		Log("  Interface-input: %s, %s", s.Interfaces.Client.VppName(), s.Interfaces.Server.VppName())
		Log("  Client netns: %s, Client IP: %s", s.NetNamespaces.Client, s.Interfaces.Client.Host.Ip4AddressString())
		Log("  Server netns: %s, Server IP: %s", s.NetNamespaces.Server, s.ServerAddr())
		s.Skip("Dry run mode = true")
	}
}

func (s *SfdpSuite) TeardownTest() {
	defer s.HstSuite.TeardownTest()
	vpp := s.Containers.Vpp.VppInstance
	if CurrentSpecReport().Failed() {
		Log(vpp.Vppctl("show sfdp session-table"))
		Log(vpp.Vppctl("show sfdp session stats verbose"))
		Log(vpp.Vppctl("show interface"))
		Log(vpp.Vppctl("show error"))
	}
}

func (s *SfdpSuite) ServerAddr() string {
	return s.Interfaces.Server.Host.Ip4AddressString()
}

// Stripping ANSI codes is required for SFDP CLI output
// since tables might output entries with ANSI color codes
// associated.
var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripAnsi(s string) string {
	return ansiEscape.ReplaceAllString(s, "")
}

// TODO - we currently use regex to parse CLI output for
// SFDP session table and SFDP session stats.
// We should ideally move towards using the SFDP APIs to fetch
// this information (requires support for SFDP APIs in govpp)
type SfdpSessionStats struct {
	SessionId  string
	Proto      int
	Tenant     int
	PacketsFwd uint64
	PacketsRev uint64
	BytesFwd   uint64
	BytesRev   uint64
}

type SfdpSession struct {
	Id     string
	Tenant string
	Proto  string
	State  string
}

func (s *SfdpSuite) GetSfdpSessionStats() []SfdpSessionStats {
	vpp := s.Containers.Vpp.VppInstance

	// Poll "show sfdp session stats verbose" and parses all session entries
	// Regex expression is used parse entries with the following format:
	//
	//	Session            Proto  Tenant     Pkts(fwd)    Pkts(rev)    Bytes(fwd)   Bytes(rev)
	//	------------------ ------ ---------- ------------ ------------ ------------ ------------
	//	0xf953000000000008 6      0          723          336          1052988      84488
	//	           First seen: 1234.567890, Last seen: 1240.123456
	//	           Duration: 5.555566
	//	           TTL fwd(min/max/mean/stddev)=64/64/64.000/0.000 rev(...)
	//	           RTT fwd(mean/stddev)=0.001234/0.000567 rev(...)
	//	           TCP: syn=1 fin=0 rst=0 hs=1 mss=1460 syn-rtt=0.000456
	//	           TCP data: pkts(fwd/rev)=700/300
	//	           TCP ev: retr(fwd/rev)=0/0 zero-win(fwd/rev)=0/0 dupack(fwd/rev)=0/0
	//	           TCP seq: last-seq(fwd/rev)=... last-ack(fwd/rev)=... ooo(fwd/rev)=0/0 overlap(fwd/rev)=0/0
	//	           TCP ecn: ect=0 ce=0 ece=0 cwr=0
	re := regexp.MustCompile(`(?m)^\s*(0x[0-9a-fA-F]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$`)

	var sessions []SfdpSessionStats
	var showOut string
	for i := 0; i < 10; i++ {
		showOut = stripAnsi(vpp.Vppctl("show sfdp session stats verbose"))
		matches := re.FindAllStringSubmatch(showOut, -1)
		for _, m := range matches {
			proto, _ := strconv.Atoi(m[2])
			tenant, _ := strconv.Atoi(m[3])
			pktsFwd, _ := strconv.ParseUint(m[4], 10, 64)
			pktsRev, _ := strconv.ParseUint(m[5], 10, 64)
			bytesFwd, _ := strconv.ParseUint(m[6], 10, 64)
			bytesRev, _ := strconv.ParseUint(m[7], 10, 64)
			sessions = append(sessions, SfdpSessionStats{
				SessionId:  m[1],
				Proto:      proto,
				Tenant:     tenant,
				PacketsFwd: pktsFwd,
				PacketsRev: pktsRev,
				BytesFwd:   bytesFwd,
				BytesRev:   bytesRev,
			})
		}

		// Retries up to 10 times (200ms apart) until at least one session is found.
		if len(sessions) > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	Log(showOut)
	return sessions
}

func (s *SfdpSuite) GetSfdpSessions() []SfdpSession {
	vpp := s.Containers.Vpp.VppInstance

	// Poll "show sfdp session-table" and parses all SFDP session entries.
	// Expected output is as follow
	//
	//	id(0)              tenant(1) thread(2) index(3) type(4) proto(5) context(6) ingress(7)        egress(8)         state(9)     TTL(10)
	//	0xf953000000000008 1         0         0        ip4     TCP      0          10.10.1.1:54312   10.10.2.1:9998    established  119.5

	var sessions []SfdpSession
	var showOut string
	for i := 0; i < 10; i++ {
		// Parameter 'unsafe-show-all' is used to ensure we display all sfdp session entries
		showOut = stripAnsi(vpp.Vppctl("show sfdp session-table unsafe-show-all"))
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

		// Retries up to 10 times (200ms apart) until at least one session is found.
		if len(sessions) > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	Log(showOut)
	return sessions
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
