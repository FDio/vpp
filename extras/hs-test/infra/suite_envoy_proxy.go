// Suite for Envoy proxy testing
//
// The topology consists of 4 containers: curl (client), VPP (session layer), Envoy (proxy), nginx (target HTTP server).
// VPP has 2 tap interfaces configured, one for client network and second for server/target network.

package hst

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
)

type EnvoyProxySuite struct {
	HstSuite
	nginxPort  uint16
	proxyPort  uint16
	maxTimeout int
	Interfaces struct {
		Server *NetInterface
		Client *NetInterface
	}
	Containers struct {
		EnvoyProxy           *Container
		NginxServerTransient *Container
		Vpp                  *Container
		Curl                 *Container
	}
}

var envoyProxyTests = map[string][]func(s *EnvoyProxySuite){}
var envoyProxySoloTests = map[string][]func(s *EnvoyProxySuite){}

func RegisterEnvoyProxyTests(tests ...func(s *EnvoyProxySuite)) {
	envoyProxyTests[getTestFilename()] = tests
}

func RegisterEnvoyProxySoloTests(tests ...func(s *EnvoyProxySuite)) {
	envoyProxySoloTests[getTestFilename()] = tests
}

func (s *EnvoyProxySuite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.LoadNetworkTopology("2taps")
	s.LoadContainerTopology("envoyProxy")

	if *IsVppDebug {
		s.maxTimeout = 600
	} else {
		s.maxTimeout = 60
	}
	s.Interfaces.Client = s.GetInterfaceByName("hstcln")
	s.Interfaces.Server = s.GetInterfaceByName("hstsrv")
	s.Containers.NginxServerTransient = s.GetTransientContainerByName("nginx-server")
	s.Containers.Vpp = s.GetContainerByName("vpp")
	s.Containers.EnvoyProxy = s.GetContainerByName("envoy-vcl")
	s.Containers.Curl = s.GetContainerByName("curl")
}

func (s *EnvoyProxySuite) SetupTest() {
	s.HstSuite.SetupTest()

	// VPP
	var sessionConfig Stanza
	sessionConfig.
		NewStanza("session").
		Append("enable").
		Append("use-app-socket-api").
		Append("evt_qs_memfd_seg").
		Append("event-queue-length 100000")

	vpp, err := s.Containers.Vpp.newVppInstance(s.Containers.Vpp.AllocatedCpus, sessionConfig)
	s.AssertNotNil(vpp, fmt.Sprint(err))

	// nginx HTTP server
	s.AssertNil(s.Containers.NginxServerTransient.Create())
	s.nginxPort = 80
	nginxSettings := struct {
		LogPrefix string
		Address   string
		Port      uint16
		Timeout   int
	}{
		LogPrefix: s.Containers.NginxServerTransient.Name,
		Address:   s.Interfaces.Server.Ip4AddressString(),
		Port:      s.nginxPort,
		Timeout:   s.maxTimeout,
	}
	s.Containers.NginxServerTransient.CreateConfigFromTemplate(
		"/nginx.conf",
		"./resources/nginx/nginx_server.conf",
		nginxSettings,
	)

	// Envoy
	s.AssertNil(s.Containers.EnvoyProxy.Create())

	s.proxyPort = 8080
	envoySettings := struct {
		LogPrefix     string
		ServerAddress string
		ServerPort    uint16
		ProxyPort     uint16
	}{
		LogPrefix:     s.Containers.EnvoyProxy.Name,
		ServerAddress: s.Interfaces.Server.Ip4AddressString(),
		ServerPort:    s.nginxPort,
		ProxyPort:     s.proxyPort,
	}
	s.Containers.EnvoyProxy.CreateConfigFromTemplate(
		"/etc/envoy/envoy.yaml",
		"resources/envoy/proxy.yaml",
		envoySettings,
	)

	s.AssertNil(vpp.Start())
	// wait for VPP to start
	time.Sleep(time.Second * 1)
	s.AssertNil(vpp.CreateTap(s.Interfaces.Client, false, 1, 1))
	s.AssertNil(vpp.CreateTap(s.Interfaces.Server, false, 1, 2))
	s.Containers.Vpp.Exec(false, "chmod 777 -R %s", s.Containers.Vpp.GetContainerWorkDir())

	// Add Ipv4 ARP entry for nginx HTTP server, otherwise first request fail (HTTP error 503)
	arp := fmt.Sprintf("set ip neighbor %s %s %s",
		s.Interfaces.Server.Peer.Name(),
		s.Interfaces.Server.Ip4AddressString(),
		s.Interfaces.Server.HwAddress)

	if *DryRun {
		vpp.AppendToCliConfig(arp)
		s.LogStartedContainers()
		s.Log("%s* Proxy IP used in tests: %s:%d%s", Colors.pur, s.ProxyAddr(), s.ProxyPort(), Colors.rst)
		s.Skip("Dry run mode = true")
	}

	s.Containers.Vpp.VppInstance.Vppctl(arp)
	s.AssertNil(s.Containers.NginxServerTransient.Start())
	s.AssertNil(s.Containers.EnvoyProxy.Start())
}

func (s *EnvoyProxySuite) TearDownTest() {
	if CurrentSpecReport().Failed() {
		s.CollectNginxLogs(s.Containers.NginxServerTransient)
		s.CollectEnvoyLogs(s.Containers.EnvoyProxy)
	}
	s.HstSuite.TearDownTest()
}

func (s *EnvoyProxySuite) ProxyPort() uint16 {
	return s.proxyPort
}

func (s *EnvoyProxySuite) ProxyAddr() string {
	return s.Interfaces.Client.Peer.Ip4AddressString()
}

func (s *EnvoyProxySuite) CurlDownloadResource(uri string) {
	args := fmt.Sprintf("-w @/tmp/write_out_download --max-time %d --insecure --noproxy '*' --remote-name --output-dir /tmp %s", s.maxTimeout, uri)
	writeOut, log := s.RunCurlContainer(s.Containers.Curl, args)
	s.AssertContains(writeOut, "GET response code: 200")
	s.AssertNotContains(log, "bytes remaining to read")
	s.AssertNotContains(log, "Operation timed out")
}

func (s *EnvoyProxySuite) CurlUploadResource(uri, file string) {
	args := fmt.Sprintf("-w @/tmp/write_out_upload --max-time %d --insecure --noproxy '*' -T %s %s", s.maxTimeout, file, uri)
	writeOut, log := s.RunCurlContainer(s.Containers.Curl, args)
	s.AssertContains(writeOut, "PUT response code: 201")
	s.AssertNotContains(log, "Operation timed out")
}

var _ = Describe("EnvoyProxySuite", Ordered, ContinueOnFailure, func() {
	var s EnvoyProxySuite
	BeforeAll(func() {
		s.SetupSuite()
	})
	BeforeEach(func() {
		s.SetupTest()
	})
	AfterAll(func() {
		s.TearDownSuite()
	})
	AfterEach(func() {
		s.TearDownTest()
	})

	for filename, tests := range envoyProxyTests {
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

var _ = Describe("EnvoyProxySuiteSolo", Ordered, ContinueOnFailure, func() {
	var s EnvoyProxySuite
	BeforeAll(func() {
		s.SetupSuite()
	})
	BeforeEach(func() {
		s.SetupTest()
	})
	AfterAll(func() {
		s.TearDownSuite()
	})
	AfterEach(func() {
		s.TearDownTest()
	})

	for filename, tests := range envoyProxySoloTests {
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
