package hst

import (
	"fmt"
	"os/exec"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
)

type HsiSuite struct {
	HstSuite
	maxTimeout int
	Interfaces struct {
		Client *NetInterface
		Server *NetInterface
	}
	Containers struct {
		Vpp                  *Container
		NginxServerTransient *Container
	}
	Ports struct {
		Server    uint16
		ServerSsl uint16
	}
	NetNamespaces struct {
		Client string
	}
}

var hsiTests = map[string][]func(s *HsiSuite){}
var hsiMWTests = map[string][]func(s *HsiSuite){}

func RegisterHsiTests(tests ...func(s *HsiSuite)) {
	hsiTests[GetTestFilename()] = tests
}

func RegisterHsiMWTests(tests ...func(s *HsiSuite)) {
	hsiMWTests[GetTestFilename()] = tests
}

func (s *HsiSuite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.ConfigureNetworkTopology("ns")
	s.LoadContainerTopology("single")
	s.Ports.Server = s.GeneratePortAsInt()
	s.Ports.ServerSsl = s.GeneratePortAsInt()

	if *IsVppDebug {
		s.maxTimeout = 600
	} else {
		s.maxTimeout = 60
	}
	s.Interfaces.Client = s.GetInterfaceByName("hclnvpp")
	s.Interfaces.Server = s.GetInterfaceByName("hsrvvpp")
	s.NetNamespaces.Client = s.GetNetNamespaceByName("cln")
	s.Containers.NginxServerTransient = s.GetTransientContainerByName("nginx-server")
	s.Containers.Vpp = s.GetContainerByName("vpp")
}

func (s *HsiSuite) SetupTest() {
	s.HstSuite.SetupTest()

	vpp, err := s.Containers.Vpp.newVppInstance(s.Containers.Vpp.AllocatedCpus)
	AssertNotNil(vpp, fmt.Sprint(err))

	AssertNil(vpp.Start())
	numCpus := uint16(len(s.Containers.Vpp.AllocatedCpus))
	numWorkers := uint16(max(numCpus-1, 1))
	idx, err := vpp.createAfPacket(s.Interfaces.Client, false, WithNumRxQueues(numWorkers), WithNumTxQueues(numCpus))
	AssertNil(err, fmt.Sprint(err))
	AssertNotEqual(0, idx)
	idx, err = vpp.createAfPacket(s.Interfaces.Server, false, WithNumRxQueues(numWorkers), WithNumTxQueues(numCpus))
	AssertNil(err, fmt.Sprint(err))
	AssertNotEqual(0, idx)

	Log(vpp.Vppctl("set interface feature " + s.Interfaces.Client.VppName() + " hsi4-in arc ip4-unicast"))
	Log(vpp.Vppctl("set interface feature " + s.Interfaces.Server.VppName() + " hsi4-in arc ip4-unicast"))

	s.setupIpv6(vpp)

	// let the host know howto get to the server
	cmd := exec.Command("ip", "netns", "exec", s.NetNamespaces.Client, "ip", "route", "replace",
		s.ServerAddr(), "via", s.Interfaces.Client.Ip4AddressString())
	Log(cmd.String())
	_, err = cmd.CombinedOutput()
	AssertNil(err, fmt.Sprint(err))

	if *DryRun {
		s.LogStartedContainers()
		s.Skip("Dry run mode = true")
	}
}

func (s *HsiSuite) setupIpv6(vpp *VppInstance) {
	s.setupInterfaceIpv6(vpp, s.Interfaces.Client)
	s.setupInterfaceIpv6(vpp, s.Interfaces.Server)

	Log(vpp.Vppctl("set interface feature " + s.Interfaces.Client.VppName() + " hsi6-in arc ip6-unicast"))
	Log(vpp.Vppctl("set interface feature " + s.Interfaces.Server.VppName() + " hsi6-in arc ip6-unicast"))

	cmd := exec.Command("ip", "netns", "exec", s.NetNamespaces.Client, "ip", "-6", "route", "replace",
		s.ServerAddr6(), "via", s.Interfaces.Client.Ip6AddressString(), "dev",
		s.Interfaces.Client.Host.Name(), "src", s.Interfaces.Client.Host.Ip6AddressString())
	Log(cmd.String())
	output, err := cmd.CombinedOutput()
	AssertNil(err, string(output))
}

func (s *HsiSuite) setupInterfaceIpv6(vpp *VppInstance, intf *NetInterface) {
	var err error

	if intf.Ip6AddrAllocator == nil {
		intf.Ip6AddrAllocator = s.Ip6AddrAllocator
	}
	if intf.Host.Ip6AddrAllocator == nil {
		intf.Host.Ip6AddrAllocator = s.Ip6AddrAllocator
	}
	if intf.Ip6Address == "" {
		intf.Ip6Address, err = intf.Ip6AddrAllocator.NewIp6InterfaceAddress(intf.Host.NetworkNumber)
		AssertNil(err, fmt.Sprint(err))
	}
	if intf.Host.Ip6Address == "" {
		intf.Host.Ip6Address, err = intf.Host.Ip6AddrAllocator.NewIp6InterfaceAddress(intf.Host.NetworkNumber)
		AssertNil(err, fmt.Sprint(err))
		cmd := appendNetns([]string{"ip", "-6", "addr", "add", intf.Host.Ip6Address, "dev",
			intf.Host.Name(), "nodad"}, intf.Host.NetworkNamespace)
		output, err := cmd.CombinedOutput()
		AssertNil(err, string(output))
	}

	Log(vpp.Vppctl("set interface ip address %s %s", intf.VppName(), intf.Ip6Address))
}

func (s *HsiSuite) TeardownTest() {
	defer s.HstSuite.TeardownTest()
	vpp := s.Containers.Vpp.VppInstance
	if CurrentSpecReport().Failed() {
		Log(vpp.Vppctl("show session verbose 2"))
		Log(vpp.Vppctl("show error"))
		CollectNginxLogs(s.Containers.NginxServerTransient)
	}
}

func (s *HsiSuite) setupNginxServer(listenIp6 bool) {
	AssertNil(s.Containers.NginxServerTransient.Create())
	nginxSettings := struct {
		LogPrefix string
		Address   string
		Port      uint16
		PortSsl   uint16
		Http2     string
		Timeout   int
		ListenIp6 bool
	}{
		LogPrefix: s.Containers.NginxServerTransient.Name,
		Address:   s.ServerAddr(),
		Port:      s.Ports.Server,
		PortSsl:   s.Ports.ServerSsl,
		Http2:     "off",
		Timeout:   s.maxTimeout,
		ListenIp6: listenIp6,
	}
	s.Containers.NginxServerTransient.CreateConfigFromTemplate(
		"/nginx.conf",
		"./resources/nginx/nginx_server.conf",
		nginxSettings,
	)
	AssertNil(s.Containers.NginxServerTransient.Start())
}

func (s *HsiSuite) SetupNginxServer() {
	s.setupNginxServer(false)
}

func (s *HsiSuite) SetupNginxServerIp6() {
	s.setupNginxServer(true)
}

func (s *HsiSuite) ServerAddr() string {
	return s.Interfaces.Server.Host.Ip4AddressString()
}

func (s *HsiSuite) ServerAddr6() string {
	return s.Interfaces.Server.Host.Ip6AddressString()
}

func HsiUriHost(addr string) string {
	if strings.Contains(addr, ":") {
		return "[" + addr + "]"
	}
	return addr
}

func HsiUri(proto, addr string, port uint16) string {
	return fmt.Sprintf("%s://%s:%d", proto, HsiUriHost(addr), port)
}

func HsiAnyAddr(isIp6 bool) string {
	if isIp6 {
		return "[::]"
	}
	return "0.0.0.0"
}

func (s *HsiSuite) StartProxyLite(serverURI, clientURI string, options ...string) string {
	cmd := fmt.Sprintf("proxy-lite server-uri %s client-uri %s", serverURI, clientURI)
	if len(options) > 0 {
		cmd += " " + strings.Join(options, " ")
	}
	output := s.Containers.Vpp.VppInstance.Vppctl(cmd)
	Log(output)
	return output
}

func (s *HsiSuite) StartProxyLiteTcp4(options ...string) string {
	return s.StartProxyLite(HsiUri("tcp", "0.0.0.0", s.Ports.Server),
		HsiUri("tcp", s.ServerAddr(), s.Ports.Server), options...)
}

func (s *HsiSuite) StartProxyLiteTcp6(options ...string) string {
	return s.StartProxyLite(HsiUri("tcp", "::", s.Ports.Server),
		HsiUri("tcp", s.ServerAddr6(), s.Ports.Server), options...)
}

func (s *HsiSuite) StartProxyLiteUdp4(options ...string) string {
	return s.StartProxyLite(HsiUri("udp", "0.0.0.0", s.Ports.Server),
		HsiUri("udp", s.ServerAddr(), s.Ports.Server), options...)
}

func (s *HsiSuite) StartProxyLiteUdp6(options ...string) string {
	return s.StartProxyLite(HsiUri("udp", "::", s.Ports.Server),
		HsiUri("udp", s.ServerAddr6(), s.Ports.Server), options...)
}

func WaitProxyLiteTrackedCount(vpp *VppInstance, count int, cancel func()) string {
	var lastOutput string
	deadline := time.Now().Add(5 * time.Second)
	want := fmt.Sprintf("hsi tracked %d", count)
	for time.Now().Before(deadline) {
		output := vpp.Vppctl("show proxy-lite")
		if output != "" {
			lastOutput = output
		}
		if strings.Contains(output, want) {
			return output
		}
		if strings.Contains(output, "failed 1") {
			cancel()
			AssertFail("proxy-lite hsi offload failed before completion:\n%s", output)
		}
		time.Sleep(100 * time.Millisecond)
	}

	cancel()
	AssertFail("timed out waiting for proxy-lite hsi offload; last output:\n%s", lastOutput)
	return lastOutput
}

func WaitProxyLiteTracked(vpp *VppInstance, cancel func()) string {
	return WaitProxyLiteTrackedCount(vpp, 1, cancel)
}

func WaitHsiContains(vpp *VppInstance, want string) string {
	var lastOutput string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		output := vpp.Vppctl("show hsi")
		if output != "" {
			lastOutput = output
		}
		if strings.Contains(output, want) {
			return output
		}
		time.Sleep(100 * time.Millisecond)
	}

	AssertFail("timed out waiting for show hsi to contain %q; last output:\n%s", want, lastOutput)
	return lastOutput
}

func WaitHsiCounterAtLeast(vpp *VppInstance, name string, want int) string {
	var lastOutput string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		output := vpp.Vppctl("show hsi")
		if output != "" {
			lastOutput = output
		}
		if HsiCounterValue(output, name) >= want {
			return output
		}
		time.Sleep(100 * time.Millisecond)
	}

	AssertFail("timed out waiting for show hsi counter %q >= %d; last output:\n%s", name, want, lastOutput)
	return lastOutput
}

func AssertHsiUdpDrainCompleted(vpp *VppInstance) string {
	var lastOutput string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		output := vpp.Vppctl("show hsi")
		if output != "" {
			lastOutput = output
		}
		if HsiCounterValue(output, "udp-drain-completed") >= 2 &&
			!strings.Contains(output, "udp-drain session") {
			return output
		}
		time.Sleep(100 * time.Millisecond)
	}

	AssertFail("timed out waiting for udp drain completion; last output:\n%s", lastOutput)
	return lastOutput
}

func AssertHsiUdpCleaned(vpp *VppInstance, expectedCleanupMin int) string {
	var lastOutput string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		output := vpp.Vppctl("show hsi")
		if output != "" {
			lastOutput = output
		}
		if HsiCounterValue(output, "udp-cleanup-completed") >= expectedCleanupMin &&
			!strings.Contains(output, "udp-tracked session") &&
			!strings.Contains(output, "udp-drain session") {
			return output
		}
		time.Sleep(100 * time.Millisecond)
	}

	AssertFail("timed out waiting for udp cleanup; last output:\n%s", lastOutput)
	return lastOutput
}

func AssertHsiTcpCleaned(vpp *VppInstance, expectedCleanupMin int) string {
	var lastOutput string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		output := vpp.Vppctl("show hsi")
		if output != "" {
			lastOutput = output
		}
		if HsiCounterValue(output, "tcp-cleanup-completed") >= expectedCleanupMin &&
			!strings.Contains(output, "tcp-tracked session") &&
			!strings.Contains(output, "tcp-drain session") {
			return output
		}
		time.Sleep(100 * time.Millisecond)
	}

	AssertFail("timed out waiting for tcp cleanup; last output:\n%s", lastOutput)
	return lastOutput
}

func AssertHsiNoTrackedOrDraining(hsi string) {
	AssertNotContains(hsi, "tcp-tracked session")
	AssertNotContains(hsi, "tcp-drain session")
	AssertNotContains(hsi, "udp-tracked session")
	AssertNotContains(hsi, "udp-drain session")
}

func HsiCounterValue(hsi, name string) int {
	total := 0
	for _, line := range strings.Split(hsi, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 4 || fields[2] != name {
			continue
		}
		value, err := strconv.Atoi(fields[3])
		AssertNil(err)
		total += value
	}
	return total
}

func AssertProxyLiteSessionsCleanedCount(s *HsiSuite, expectedCleanups int) {
	vpp := s.Containers.Vpp.VppInstance
	proxyClientConn := fmt.Sprintf("[T] %s:%d->%s", s.ServerAddr(), s.Ports.Server,
		s.Interfaces.Client.Host.Ip4AddressString())
	proxyTargetConn := fmt.Sprintf("->%s:%d", s.ServerAddr(), s.Ports.Server)
	for range 10 {
		sessions := vpp.Vppctl("show session verbose 2")
		if !strings.Contains(sessions, proxyClientConn) &&
			!strings.Contains(sessions, proxyTargetConn) {
			break
		}
		time.Sleep(1 * time.Second)
	}

	hsi := vpp.Vppctl("show hsi")
	sessions := vpp.Vppctl("show session verbose 2")
	Log(hsi)
	Log(sessions)
	AssertNotContains(sessions, proxyClientConn, "client-proxy session not cleaned up")
	AssertNotContains(sessions, proxyTargetConn, "proxy-server session not cleaned up")

	AssertEqual(expectedCleanups, HsiCounterValue(hsi, "tcp-cleanup-completed"))
	AssertNotContains(hsi, "tcp-tracked session")
	AssertNotContains(hsi, "tcp-drain session")
}

func AssertProxyLiteSessionsCleaned(s *HsiSuite) {
	AssertProxyLiteSessionsCleanedCount(s, 2)
}

var _ = Describe("HsiSuite", Ordered, ContinueOnFailure, Label("HSI"), func() {
	var s HsiSuite
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

	for filename, tests := range hsiTests {
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

var _ = Describe("HsiMWSuite", Ordered, ContinueOnFailure, Serial, Label("HSI", "Solo", "MW"), func() {
	var s HsiSuite
	BeforeAll(func() {
		s.SetupSuite()
	})
	BeforeEach(func() {
		s.SkipIfNotEnoughCpus = true
	})
	AfterAll(func() {
		s.TeardownSuite()
	})
	AfterEach(func() {
		s.TeardownTest()
	})

	for filename, tests := range hsiMWTests {
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
