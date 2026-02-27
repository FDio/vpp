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
	Ports struct {
		Nginx      uint16
		NginxSsl   uint16
		Proxy      uint16
		EnvoyAdmin uint16
	}
}

var envoyProxyTests = map[string][]func(s *EnvoyProxySuite){}
var envoyProxySoloTests = map[string][]func(s *EnvoyProxySuite){}

func RegisterEnvoyProxyTests(tests ...func(s *EnvoyProxySuite)) {
	envoyProxyTests[GetTestFilename()] = tests
}

func RegisterEnvoyProxySoloTests(tests ...func(s *EnvoyProxySuite)) {
	envoyProxySoloTests[GetTestFilename()] = tests
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
	s.Ports.Nginx = s.GeneratePortAsInt()
	s.Ports.NginxSsl = s.GeneratePortAsInt()
	s.Ports.Proxy = s.GeneratePortAsInt()
	s.Ports.EnvoyAdmin = s.GeneratePortAsInt()
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
	AssertNotNil(vpp, fmt.Sprint(err))

	// nginx HTTP server
	AssertNil(s.Containers.NginxServerTransient.Create())
	nginxSettings := struct {
		LogPrefix string
		Address   string
		Port      uint16
		PortSsl   uint16
		Http2     string
		Timeout   int
	}{
		LogPrefix: s.Containers.NginxServerTransient.Name,
		Address:   s.Interfaces.Server.Host.Ip4AddressString(),
		Port:      s.Ports.Nginx,
		PortSsl:   s.Ports.NginxSsl,
		Http2:     "off",
		Timeout:   s.maxTimeout,
	}
	s.Containers.NginxServerTransient.CreateConfigFromTemplate(
		"/nginx.conf",
		"./resources/nginx/nginx_server.conf",
		nginxSettings,
	)

	// Envoy
	AssertNil(s.Containers.EnvoyProxy.Create())

	envoySettings := struct {
		LogPrefix      string
		ServerAddress  string
		ServerPort     uint16
		ProxyPort      uint16
		ProxyAddr      string
		EnvoyAdminPort uint16
	}{
		LogPrefix:      s.Containers.EnvoyProxy.Name,
		ServerAddress:  s.Interfaces.Server.Host.Ip4AddressString(),
		ServerPort:     s.Ports.Nginx,
		ProxyPort:      s.Ports.Proxy,
		ProxyAddr:      s.ProxyAddr(),
		EnvoyAdminPort: s.Ports.EnvoyAdmin,
	}
	s.Containers.EnvoyProxy.CreateConfigFromTemplate(
		"/etc/envoy/envoy.yaml",
		"resources/envoy/proxy.yaml",
		envoySettings,
	)

	AssertNil(vpp.Start())
	// wait for VPP to start
	time.Sleep(time.Second * 1)
	AssertNil(vpp.CreateTap(s.Interfaces.Client, false, 1))
	AssertNil(vpp.CreateTap(s.Interfaces.Server, false, 2))
	s.Containers.Vpp.Exec(false, "chmod 777 -R %s", s.Containers.Vpp.GetContainerWorkDir())

	// Add Ipv4 ARP entry for nginx HTTP server, otherwise first request fail (HTTP error 503)
	arp := fmt.Sprintf("set ip neighbor %s %s %s",
		s.Interfaces.Server.Name(),
		s.Interfaces.Server.Host.Ip4AddressString(),
		s.Interfaces.Server.Host.HwAddress)

	if *DryRun {
		vpp.AppendToCliConfig(arp)
		s.LogStartedContainers()
		Log("%s* Proxy IP used in tests: %s:%d%s", Colors.pur, s.ProxyAddr(), s.Ports.Proxy, Colors.rst)
		s.Skip("Dry run mode = true")
	}

	s.Containers.Vpp.VppInstance.Vppctl(arp)
	AssertNil(s.Containers.NginxServerTransient.Start())
	AssertNil(s.Containers.EnvoyProxy.Start())
	// give envoy some time to start
	time.Sleep(time.Second * 2)
}

func (s *EnvoyProxySuite) TeardownTest() {
	defer s.HstSuite.TeardownTest()
	if CurrentSpecReport().Failed() {
		CollectNginxLogs(s.Containers.NginxServerTransient)
		CollectEnvoyLogs(s.Containers.EnvoyProxy)
	}
}

func (s *EnvoyProxySuite) ProxyAddr() string {
	return s.Interfaces.Client.Ip4AddressString()
}

func (s *EnvoyProxySuite) CurlDownloadResource(uri string) {
	args := fmt.Sprintf("-w @/tmp/write_out_download --max-time %d --insecure --noproxy '*' --remote-name --output-dir /tmp %s", s.maxTimeout, uri)
	writeOut, log := RunCurlContainer(s.Containers.Curl, args)
	AssertContains(writeOut, "GET response code: 200")
	AssertNotContains(log, "bytes remaining to read")
	AssertNotContains(log, "Operation timed out")
}

func (s *EnvoyProxySuite) CurlUploadResource(uri, file string) {
	args := fmt.Sprintf("-w @/tmp/write_out_upload --max-time %d --insecure --noproxy '*' -T %s %s", s.maxTimeout, file, uri)
	writeOut, log := RunCurlContainer(s.Containers.Curl, args)
	AssertContains(writeOut, "PUT response code: 201")
	AssertNotContains(log, "Operation timed out")
}

var _ = Describe("EnvoyProxySuite", Ordered, ContinueOnFailure, Label("Envoy", "Proxy", "VCL"), func() {
	var s EnvoyProxySuite
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

	for filename, tests := range envoyProxyTests {
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

var _ = Describe("EnvoyProxySuiteSolo", Ordered, ContinueOnFailure, Label("Envoy", "Proxy"), func() {
	var s EnvoyProxySuite
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

	for filename, tests := range envoyProxySoloTests {
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
