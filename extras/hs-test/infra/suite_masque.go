package hst

import (
	"fmt"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"time"

	. "fd.io/hs-test/infra/common"
	. "github.com/onsi/ginkgo/v2"
)

type MasqueSuite struct {
	HstSuite
	maxTimeout int
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
	s.NetNamespaces.Client = s.GetNetNamespaceByName("client-ns")
	s.Interfaces.Client = s.GetInterfaceByName("cln")
	s.Interfaces.TunnelClient = s.GetInterfaceByName("cln-tun")
	s.Interfaces.TunnelServer = s.GetInterfaceByName("srv-tun")
	s.Interfaces.Server = s.GetInterfaceByName("srv")
	s.Containers.VppClient = s.GetContainerByName("vpp-masque-client")
	s.Containers.VppServer = s.GetContainerByName("vpp-masque-server")
	s.Containers.NginxServer = s.GetContainerByName("nginx-server")
	s.Containers.IperfServer = s.GetContainerByName("iperf-server")
}

func (s *MasqueSuite) SetupTest() {
	s.HstSuite.SetupTest()

	// vpp masque proxy client
	clientVpp, err := s.Containers.VppClient.newVppInstance(s.Containers.VppClient.AllocatedCpus)
	s.AssertNotNil(clientVpp, fmt.Sprint(err))
	s.AssertNil(clientVpp.Start())
	idx, err := clientVpp.createAfPacket(s.Interfaces.Client, false)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertNotEqual(0, idx)
	idx, err = clientVpp.createAfPacket(s.Interfaces.TunnelClient, false)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertNotEqual(0, idx)

	// vpp masque proxy server
	serverVpp, err := s.Containers.VppServer.newVppInstance(s.Containers.VppServer.AllocatedCpus)
	s.AssertNotNil(serverVpp, fmt.Sprint(err))
	s.AssertNil(serverVpp.Start())
	idx, err = serverVpp.createAfPacket(s.Interfaces.TunnelServer, false)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertNotEqual(0, idx)
	idx, err = serverVpp.createAfPacket(s.Interfaces.Server, false)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertNotEqual(0, idx)
	proxyCmd := fmt.Sprintf("test proxy server fifo-size 512k server-uri https://%s:%s", s.ProxyAddr(), s.Ports.Proxy)
	s.Log(serverVpp.Vppctl(proxyCmd))

	// let the client know howto get to the server (must be created here after vpp interface)
	cmd := exec.Command("ip", "netns", "exec", s.NetNamespaces.Client, "ip", "route", "add",
		s.NginxAddr(), "via", s.Interfaces.Client.Ip4AddressString())
	s.Log(cmd.String())
	o, err := cmd.CombinedOutput()
	s.Log(string(o))
	s.AssertNil(err, fmt.Sprint(err))

	arp := fmt.Sprintf("set ip neighbor host-%s %s %s",
		s.Interfaces.TunnelClient.Name(),
		s.ProxyAddr(),
		s.Interfaces.TunnelServer.HwAddress)
	s.Log(clientVpp.Vppctl(arp))
	arp = fmt.Sprintf("set ip neighbor host-%s %s %s",
		s.Interfaces.Client.Name(),
		s.Interfaces.Client.Peer.Ip4AddressString(),
		s.Interfaces.Client.Peer.HwAddress)
	s.Log(clientVpp.Vppctl(arp))
	arp = fmt.Sprintf("set ip neighbor host-%s %s %s",
		s.Interfaces.Server.Name(),
		s.NginxAddr(),
		s.Interfaces.Server.Peer.HwAddress)
	s.Log(serverVpp.Vppctl(arp))

	if *DryRun {
		s.LogStartedContainers()
		s.Skip("Dry run mode = true")
	}
}

func (s *MasqueSuite) TeardownTest() {
	defer s.HstSuite.TeardownTest()
	// delete route
	cmd := exec.Command("ip", "netns", "exec", s.NetNamespaces.Client, "ip", "route", "del",
		s.NginxAddr(), "via", s.Interfaces.Client.Ip4AddressString())
	s.Log(cmd.String())
	o, err := cmd.CombinedOutput()
	s.Log(string(o))
	s.AssertNil(err, fmt.Sprint(err))
	clientVpp := s.Containers.VppClient.VppInstance
	serverVpp := s.Containers.VppServer.VppInstance
	if CurrentSpecReport().Failed() {
		s.CollectNginxLogs(s.Containers.NginxServer)
		s.Log(clientVpp.Vppctl("show session verbose 2"))
		s.Log(clientVpp.Vppctl("show error"))
		s.Log(clientVpp.Vppctl("show http connect proxy client listeners sessions"))
		s.Log(serverVpp.Vppctl("show session verbose 2"))
		s.Log(serverVpp.Vppctl("show error"))
	}
}

func (s *MasqueSuite) ProxyClientConnect(proto, port string) {
	vpp := s.Containers.VppClient.VppInstance
	cmd := fmt.Sprintf("http connect proxy client enable server-uri https://%s:%s listener %s://0.0.0.0:%s interface host-%s",
		s.ProxyAddr(), s.Ports.Proxy, proto, port, s.Interfaces.Client.Name())
	s.Log(vpp.Vppctl(cmd))

	connected := false
	for nTries := 0; nTries < 10; nTries++ {
		o := vpp.Vppctl("show http connect proxy client")
		if strings.Contains(o, "connection state: connected") {
			connected = true
			break
		}
		time.Sleep(1 * time.Second)
	}
	vpp.Container.Suite.AssertEqual(connected, true)
}

func (s *MasqueSuite) StartNginxServer() {
	s.AssertNil(s.Containers.NginxServer.Create())
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
	s.AssertNil(s.Containers.NginxServer.Start())
}

func (s *MasqueSuite) NginxAddr() string {
	return s.Interfaces.Server.Peer.Ip4AddressString()
}

func (s *MasqueSuite) ProxyAddr() string {
	return s.Interfaces.TunnelServer.Ip4AddressString()
}

var _ = Describe("MasqueSuite", Ordered, ContinueOnFailure, func() {
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
				s.Log(testName + ": BEGIN")
				test(&s)
			}, SpecTimeout(TestTimeout))
		}
	}
})

var _ = Describe("MasqueSoloSuite", Ordered, ContinueOnFailure, Serial, func() {
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
			It(testName, Label("SOLO"), func(ctx SpecContext) {
				s.Log(testName + ": BEGIN")
				test(&s)
			}, SpecTimeout(TestTimeout))
		}
	}
})

var _ = Describe("MasqueMWSuite", Ordered, ContinueOnFailure, Serial, func() {
	var s MasqueSuite
	BeforeAll(func() {
		s.SetupSuite()
	})
	BeforeEach(func() {
		s.SkipIfNotEnoguhCpus = true
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
			It(testName, Label("SOLO", "VPP Multi-Worker"), func(ctx SpecContext) {
				s.Log(testName + ": BEGIN")
				test(&s)
			}, SpecTimeout(TestTimeout))
		}
	}
})
