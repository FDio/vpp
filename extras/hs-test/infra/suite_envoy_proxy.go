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

const (
	VppContainerName        = "vpp"
	EnvoyProxyContainerName = "envoy-vcl"
)

type EnvoyProxySuite struct {
	HstSuite
	nginxPort  uint16
	proxyPort  uint16
	maxTimeout int
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

	vppContainer := s.GetContainerByName(VppContainerName)
	vpp, err := vppContainer.newVppInstance(vppContainer.AllocatedCpus, sessionConfig)
	s.AssertNotNil(vpp, fmt.Sprint(err))
	clientInterface := s.GetInterfaceByName(ClientTapInterfaceName)
	serverInterface := s.GetInterfaceByName(ServerTapInterfaceName)

	// nginx HTTP server
	nginxContainer := s.GetTransientContainerByName(NginxServerContainerName)
	s.AssertNil(nginxContainer.Create())
	s.nginxPort = 80
	nginxSettings := struct {
		LogPrefix string
		Address   string
		Port      uint16
		Timeout   int
	}{
		LogPrefix: nginxContainer.Name,
		Address:   serverInterface.Ip4AddressString(),
		Port:      s.nginxPort,
		Timeout:   s.maxTimeout,
	}
	nginxContainer.CreateConfig(
		"/nginx.conf",
		"./resources/nginx/nginx_server.conf",
		nginxSettings,
	)

	// Envoy
	envoyContainer := s.GetContainerByName(EnvoyProxyContainerName)
	s.AssertNil(envoyContainer.Create())

	s.proxyPort = 8080
	envoySettings := struct {
		LogPrefix     string
		ServerAddress string
		ServerPort    uint16
		ProxyPort     uint16
	}{
		LogPrefix:     envoyContainer.Name,
		ServerAddress: serverInterface.Ip4AddressString(),
		ServerPort:    s.nginxPort,
		ProxyPort:     s.proxyPort,
	}
	envoyContainer.CreateConfig(
		"/etc/envoy/envoy.yaml",
		"resources/envoy/proxy.yaml",
		envoySettings,
	)

	if *DryRun {
		s.LogStartedContainers()
		vpp.CreateVppConfig()
		vppInterfaceConfig := fmt.Sprintf("create tap id 1 host-if-name %s\n"+
			"set int ip addr tap1 %s\n"+
			"set int state tap1 up\n"+
			"create tap id 2 host-if-name %s\n"+
			"set int ip addr tap2 %s\n"+
			"set int state tap2 up\n",
			clientInterface.name,
			clientInterface.Peer.Ip4Address,
			serverInterface.name,
			serverInterface.Peer.Ip4Address,
		)
		s.AssertNil(vppContainer.CreateFileInWorkDir("vpp-config.conf", vppInterfaceConfig),
			"cannot create file")

		s.Log("\n%s* This config will be loaded on VPP startup:\n%s", Colors.grn, vppInterfaceConfig)

		s.Log("%s* Please add IP addresses manually:", Colors.pur)
		s.Log("sudo ip addr add %s dev %s", clientInterface.Ip4Address, clientInterface.name)
		s.Log("sudo ip addr add %s dev %s\n", serverInterface.Ip4Address, serverInterface.name)
		s.Log("* Proxy IP used in tests: %s:%d%s", s.ProxyAddr(), s.ProxyPort(), Colors.rst)

		s.Skip("Dry run mode = true")
	}

	s.AssertNil(vpp.Start())
	// wait for VPP to start
	time.Sleep(time.Second * 1)
	s.AssertNil(vpp.createTap(clientInterface, 1))
	s.AssertNil(vpp.createTap(serverInterface, 2))
	vppContainer.Exec(false, "chmod 777 -R %s", vppContainer.GetContainerWorkDir())

	// Add Ipv4 ARP entry for nginx HTTP server, otherwise first request fail (HTTP error 503)
	arp := fmt.Sprintf("set ip neighbor %s %s %s",
		serverInterface.Peer.Name(),
		serverInterface.Ip4AddressString(),
		serverInterface.HwAddress)
	vppContainer.VppInstance.Vppctl(arp)

	s.AssertNil(nginxContainer.Start())
	s.AssertNil(envoyContainer.Start())
}

func (s *EnvoyProxySuite) TearDownTest() {
	if CurrentSpecReport().Failed() {
		s.CollectNginxLogs(NginxServerContainerName)
		s.CollectEnvoyLogs(EnvoyProxyContainerName)
	}
	s.HstSuite.TearDownTest()
}

func (s *EnvoyProxySuite) ProxyPort() uint16 {
	return s.proxyPort
}

func (s *EnvoyProxySuite) ProxyAddr() string {
	return s.GetInterfaceByName(ClientTapInterfaceName).Peer.Ip4AddressString()
}

func (s *EnvoyProxySuite) CurlDownloadResource(uri string) {
	args := fmt.Sprintf("-w @/tmp/write_out_download --max-time %d --insecure --noproxy '*' --remote-name --output-dir /tmp %s", s.maxTimeout, uri)
	writeOut, log := s.RunCurlContainer(args)
	s.AssertContains(writeOut, "GET response code: 200")
	s.AssertNotContains(log, "bytes remaining to read")
	s.AssertNotContains(log, "Operation timed out")
}

func (s *EnvoyProxySuite) CurlUploadResource(uri, file string) {
	args := fmt.Sprintf("-w @/tmp/write_out_upload --max-time %d --insecure --noproxy '*' -T %s %s", s.maxTimeout, file, uri)
	writeOut, log := s.RunCurlContainer(args)
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
			}, SpecTimeout(SuiteTimeout))
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
			}, SpecTimeout(SuiteTimeout))
		}
	}
})
