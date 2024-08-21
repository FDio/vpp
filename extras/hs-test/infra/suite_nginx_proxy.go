package hst

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
)

// These correspond to names used in yaml config
const (
	NginxProxyContainerName      = "nginx-proxy"
	NginxServerContainerName     = "nginx-server"
	MirroringClientInterfaceName = "hstcln"
	MirroringServerInterfaceName = "hstsrv"
)

var nginxProxyTests = map[string][]func(s *NginxProxySuite){}
var nginxProxySoloTests = map[string][]func(s *NginxProxySuite){}

type NginxProxySuite struct {
	HstSuite
	proxyPort uint16
}

func RegisterNginxProxyTests(tests ...func(s *NginxProxySuite)) {
	nginxProxyTests[getTestFilename()] = tests
}
func RegisterNginxProxySoloTests(tests ...func(s *NginxProxySuite)) {
	nginxProxySoloTests[getTestFilename()] = tests
}

func (s *NginxProxySuite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.LoadNetworkTopology("2taps")
	s.LoadContainerTopology("nginxProxy")
}

func (s *NginxProxySuite) SetupTest() {
	s.HstSuite.SetupTest()

	// VPP
	var sessionConfig Stanza
	sessionConfig.
		NewStanza("session").
		Append("enable").
		Append("use-app-socket-api")

	vppContainer := s.GetContainerByName(VppContainerName)
	vpp, err := vppContainer.newVppInstance(vppContainer.AllocatedCpus, sessionConfig)
	s.AssertNotNil(vpp, fmt.Sprint(err))
	s.AssertNil(vpp.Start())
	clientInterface := s.GetInterfaceByName(MirroringClientInterfaceName)
	s.AssertNil(vpp.createTap(clientInterface, 1))
	serverInterface := s.GetInterfaceByName(MirroringServerInterfaceName)
	s.AssertNil(vpp.createTap(serverInterface, 2))

	// nginx proxy
	nginxProxyContainer := s.GetTransientContainerByName(NginxProxyContainerName)
	s.AssertNil(nginxProxyContainer.Create())
	s.proxyPort = 80
	values := struct {
		LogPrefix string
		Proxy     string
		Server    string
		Port      uint16
	}{
		LogPrefix: nginxProxyContainer.Name,
		Proxy:     clientInterface.Peer.Ip4AddressString(),
		Server:    serverInterface.Ip4AddressString(),
		Port:      s.proxyPort,
	}
	nginxProxyContainer.CreateConfig(
		"/nginx.conf",
		"./resources/nginx/nginx_proxy_mirroring.conf",
		values,
	)
	s.AssertNil(nginxProxyContainer.Start())

	// nginx HTTP server
	nginxServerContainer := s.GetTransientContainerByName(NginxServerContainerName)
	s.AssertNil(nginxServerContainer.Create())
	nginxSettings := struct {
		LogPrefix string
		Address   string
	}{
		LogPrefix: nginxServerContainer.Name,
		Address:   serverInterface.Ip4AddressString(),
	}
	nginxServerContainer.CreateConfig(
		"/nginx.conf",
		"./resources/nginx/nginx_server_mirroring.conf",
		nginxSettings,
	)
	s.AssertNil(nginxServerContainer.Start())

	vpp.WaitForApp("nginx-", 5)
}

func (s *NginxProxySuite) TearDownTest() {
	if CurrentSpecReport().Failed() {
		s.CollectNginxLogs(NginxServerContainerName)
		s.CollectNginxLogs(NginxProxyContainerName)
	}
	s.HstSuite.TearDownTest()
}

func (s *NginxProxySuite) ProxyPort() uint16 {
	return s.proxyPort
}

func (s *NginxProxySuite) ProxyAddr() string {
	return s.GetInterfaceByName(MirroringClientInterfaceName).Peer.Ip4AddressString()
}

func (s *NginxProxySuite) CurlDownloadResource(uri string) {
	args := fmt.Sprintf("--insecure --noproxy '*' --remote-name --output-dir /tmp %s", uri)
	_, log := s.RunCurlContainer(args)
	s.AssertNotContains(log, "Recv failure")
	s.AssertContains(log, "HTTP/1.1 200")
}

var _ = Describe("NginxProxySuite", Ordered, ContinueOnFailure, func() {
	var s NginxProxySuite
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

	for filename, tests := range nginxProxyTests {
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

var _ = Describe("NginxProxySuiteSolo", Ordered, ContinueOnFailure, Serial, func() {
	var s NginxProxySuite
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

	for filename, tests := range nginxProxySoloTests {
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
