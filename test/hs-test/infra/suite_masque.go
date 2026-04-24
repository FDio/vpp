package hst

import (
	"fmt"
	"net"
	"os/exec"
	"reflect"
	"runtime"
	"strings"

	"time"

	. "github.com/onsi/ginkgo/v2"
)

type MasqueSuite struct {
	HstSuite
	Interfaces struct {
		Client       *NetInterface
		TunnelClient *NetInterface
		TunnelServer *NetInterface
		Server       *NetInterface
	}
	Containers struct {
		VppClient   *Container
		VppServer   *Container
		NginxServer *Container
		IperfServer *Container
	}
	Ports struct {
		Nginx    string
		NginxSsl string
		Proxy    string
		Unused   string
	}
	NetNamespaces struct {
		Client string
	}
}

var masqueTests = map[string][]func(s *MasqueSuite){}
var masqueSoloTests = map[string][]func(s *MasqueSuite){}
var masqueMWTests = map[string][]func(s *MasqueSuite){}

func RegisterMasqueTests(tests ...func(s *MasqueSuite)) {
	masqueTests[GetTestFilename()] = tests
}

func RegisterMasqueSoloTests(tests ...func(s *MasqueSuite)) {
	masqueSoloTests[GetTestFilename()] = tests
}

func RegisterMasqueMWTests(tests ...func(s *MasqueSuite)) {
	masqueMWTests[GetTestFilename()] = tests
}

func (s *MasqueSuite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.ConfigureNetworkTopology("masque")
	s.LoadContainerTopology("masque")
	s.Ports.Nginx = s.GeneratePort()
	s.Ports.NginxSsl = s.GeneratePort()
	s.Ports.Proxy = s.GeneratePort()
	s.Ports.Unused = s.GeneratePort()
	s.NetNamespaces.Client = s.GetNetNamespaceByName("client-ns")
	s.Interfaces.Client = s.GetInterfaceByName("cln-src")
	s.Interfaces.TunnelClient = s.GetInterfaceByName("cln-tun")
	s.Interfaces.TunnelServer = s.GetInterfaceByName("srv-tun")
	s.Interfaces.Server = s.GetInterfaceByName("srv-dst")
	s.Containers.VppClient = s.GetContainerByName("vpp-masque-client")
	s.Containers.VppServer = s.GetContainerByName("vpp-masque-server")
	s.Containers.NginxServer = s.GetContainerByName("nginx-server")
	s.Containers.IperfServer = s.GetContainerByName("iperf-server")
}

func (s *MasqueSuite) SetupTest(serverExtraArgs ...string) {
	s.HstSuite.SetupTest()

	var memoryConfig Stanza
	memoryConfig.NewStanza("memory").Append("main-heap-size 2G")

	// vpp masque proxy client
	clientVpp, err := s.Containers.VppClient.newVppInstance(s.Containers.VppClient.AllocatedCpus, memoryConfig)
	AssertNotNil(clientVpp, fmt.Sprint(err))
	AssertNil(clientVpp.Start())
	err = clientVpp.CreateTap(s.Interfaces.Client, false, 1)
	AssertNil(err, fmt.Sprint(err))
	err = clientVpp.CreateTap(s.Interfaces.TunnelClient, false, 2)
	AssertNil(err, fmt.Sprint(err))

	// vpp masque proxy server
	serverVpp, err := s.Containers.VppServer.newVppInstance(s.Containers.VppServer.AllocatedCpus, memoryConfig)
	AssertNotNil(serverVpp, fmt.Sprint(err))
	AssertNil(serverVpp.Start())
	err = serverVpp.CreateTap(s.Interfaces.TunnelServer, false, 3)
	AssertNil(err, fmt.Sprint(err))
	err = serverVpp.CreateTap(s.Interfaces.Server, false, 4)
	AssertNil(err, fmt.Sprint(err))

	extras := ""
	if len(serverExtraArgs) > 0 {
		extras = strings.Join(serverExtraArgs, " ")
	}
	proxyCmd := fmt.Sprintf("test proxy server fifo-size 512k server-uri https://%s:%s %s", s.ProxyAddr(), s.Ports.Proxy, extras)
	o := serverVpp.Vppctl(proxyCmd)
	Log(o)
	AssertNotContains(o, "failed")

	// let the client know howto get to the server (must be created here after vpp interface)
	_, ipNet, err := net.ParseCIDR(s.Interfaces.Server.Host.Ip4Address)
	AssertNil(err)
	cmd := exec.Command("ip", "netns", "exec", s.NetNamespaces.Client, "ip", "route", "add",
		ipNet.String(), "via", s.Interfaces.Client.Ip4AddressString())
	Log(cmd.String())
	co, err := cmd.CombinedOutput()
	Log(string(co))
	AssertNil(err, fmt.Sprint(err))

	arp := fmt.Sprintf("set ip neighbor %s %s %s",
		s.Interfaces.Client.Name(),
		s.Interfaces.Client.Host.Ip4AddressString(),
		s.Interfaces.Client.Host.HwAddress)
	Log(clientVpp.Vppctl(arp))

	arp = fmt.Sprintf("set ip neighbor %s %s %s",
		s.Interfaces.TunnelClient.Name(),
		s.ProxyAddr(),
		s.Interfaces.TunnelServer.HwAddress)
	Log(clientVpp.Vppctl(arp))

	_, ipNet, err = net.ParseCIDR(s.Interfaces.TunnelServer.Ip4Address)
	AssertNil(err)
	route := fmt.Sprintf("ip route add %s via %s %s",
		ipNet.String(),
		s.Interfaces.TunnelClient.Host.Ip4AddressString(),
		s.Interfaces.TunnelClient.name)
	Log(clientVpp.Vppctl(route))

	arp = fmt.Sprintf("set ip neighbor %s %s %s",
		s.Interfaces.TunnelServer.Name(),
		s.Interfaces.TunnelClient.Ip4AddressString(),
		s.Interfaces.TunnelClient.HwAddress)
	Log(serverVpp.Vppctl(arp))

	_, ipNet, err = net.ParseCIDR(s.Interfaces.TunnelClient.Ip4Address)
	AssertNil(err)
	route = fmt.Sprintf("ip route add %s via %s %s",
		ipNet.String(),
		s.Interfaces.TunnelServer.Host.Ip4AddressString(),
		s.Interfaces.TunnelServer.name)
	Log(serverVpp.Vppctl(route))

	arp = fmt.Sprintf("set ip neighbor %s %s %s",
		s.Interfaces.Server.Name(),
		s.NginxAddr(),
		s.Interfaces.Server.Host.HwAddress)
	Log(serverVpp.Vppctl(arp))

	if *DryRun {
		s.LogStartedContainers()
		s.Skip("Dry run mode = true")
	}
}

func (s *MasqueSuite) TeardownTest() {
	defer s.HstSuite.TeardownTest()
	// delete route
	_, ipNet, err := net.ParseCIDR(s.Interfaces.Server.Host.Ip4Address)
	AssertNil(err)
	cmd := exec.Command("ip", "netns", "exec", s.NetNamespaces.Client, "ip", "route", "del",
		ipNet.String(), "via", s.Interfaces.Client.Ip4AddressString())
	Log(cmd.String())
	o, err := cmd.CombinedOutput()
	Log(string(o))
	AssertNil(err, fmt.Sprint(err))

	clientVpp := s.Containers.VppClient.VppInstance
	serverVpp := s.Containers.VppServer.VppInstance
	if CurrentSpecReport().Failed() {
		CollectNginxLogs(s.Containers.NginxServer)
		CollectIperfLogs(s.Containers.IperfServer)
		Log(clientVpp.Vppctl("show session verbose 2"))
		Log(clientVpp.Vppctl("show error"))
		Log(clientVpp.Vppctl("show http connect proxy client listeners sessions stats"))
		Log(clientVpp.Vppctl("show http stats"))
		Log(clientVpp.Vppctl("show http"))
		Log(clientVpp.Vppctl("show tcp stats"))
		Log(clientVpp.Vppctl("show quic"))
		Log(serverVpp.Vppctl("show session verbose 2"))
		Log(serverVpp.Vppctl("show error"))
		Log(serverVpp.Vppctl("show http stats"))
		Log(serverVpp.Vppctl("show http"))
		Log(serverVpp.Vppctl("show tcp stats"))
		Log(serverVpp.Vppctl("show quic"))
	}
}

func (s *MasqueSuite) ProxyClientConnect(proto, port string, extraArgs ...string) {
	extras := ""
	if len(extraArgs) > 0 {
		extras = strings.Join(extraArgs, " ")
	}
	vpp := s.Containers.VppClient.VppInstance
	cmd := fmt.Sprintf("http connect proxy client enable server-uri https://%s:%s listener %s://0.0.0.0:%s interface %s %s",
		s.ProxyAddr(), s.Ports.Proxy, proto, port, s.Interfaces.Client.Name(), extras)
	Log(vpp.Vppctl(cmd))

	connected := false
	for range 10 {
		o := vpp.Vppctl("show http connect proxy client")
		if strings.Contains(strings.ToLower(o), "connection state: connected") {
			connected = true
			break
		}
		time.Sleep(1 * time.Second)
	}
	AssertEqual(connected, true, "client not connected to the server")
}

func (s *MasqueSuite) StartNginxServer() {
	AssertNil(s.Containers.NginxServer.Create())
	nginxSettings := struct {
		LogPrefix string
		Address   string
		Port      string
		PortSsl   string
	}{
		LogPrefix: s.Containers.NginxServer.Name,
		Address:   s.NginxAddr(),
		Port:      s.Ports.Nginx,
		PortSsl:   s.Ports.NginxSsl,
	}
	s.Containers.NginxServer.CreateConfigFromTemplate(
		"/nginx.conf",
		"./resources/nginx/nginx_masque.conf",
		nginxSettings,
	)
	AssertNil(s.Containers.NginxServer.Start())
}

func (s *MasqueSuite) NginxAddr() string {
	return s.Interfaces.Server.Host.Ip4AddressString()
}

func (s *MasqueSuite) ProxyAddr() string {
	return s.Interfaces.TunnelServer.Ip4AddressString()
}

var _ = Describe("MasqueSuite", Ordered, ContinueOnFailure, Label("Masque", "Proxy", "ConnectProxy"), func() {
	var s MasqueSuite
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

	for filename, tests := range masqueTests {
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

var _ = Describe("MasqueSoloSuite", Ordered, ContinueOnFailure, Serial, Label("Masque", "Proxy", "ConnectProxy"), func() {
	var s MasqueSuite
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

	for filename, tests := range masqueSoloTests {
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

var _ = Describe("MasqueSuite", Ordered, ContinueOnFailure, Serial, Label("Masque", "Proxy", "ConnectProxy", "MW"), func() {
	var s MasqueSuite
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

	for filename, tests := range masqueMWTests {
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
