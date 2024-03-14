package main

import (
	"reflect"
	"runtime"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
)

// These correspond to names used in yaml config
const (
	vppProxyContainerName        = "vpp-proxy"
	nginxProxyContainerName      = "nginx-proxy"
	nginxServerContainerName     = "nginx-server"
	mirroringClientInterfaceName = "hstcln"
	mirroringServerInterfaceName = "hstsrv"
)

var nginxTests = []func(s *NginxSuite){}
var nginxSoloTests = []func(s *NginxSuite){}

type NginxSuite struct {
	HstSuite
}

func registerNginxTests(tests ...func(s *NginxSuite)) {
	nginxTests = append(nginxTests, tests...)
}
func registerNginxSoloTests(tests ...func(s *NginxSuite)) {
	nginxSoloTests = append(nginxSoloTests, tests...)
}

func (s *NginxSuite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.loadNetworkTopology("2taps")
	s.loadContainerTopology("nginxProxyAndServer")
}

func (s *NginxSuite) SetupTest() {
	s.HstSuite.SetupTest()

	// Setup test conditions
	var sessionConfig Stanza
	sessionConfig.
		newStanza("session").
		append("enable").
		append("use-app-socket-api").close()

	cpus := s.AllocateCpus()
	// ... for proxy
	vppProxyContainer := s.getContainerByName(vppProxyContainerName)
	proxyVpp, _ := vppProxyContainer.newVppInstance(cpus, sessionConfig)
	s.assertNil(proxyVpp.start())

	clientInterface := s.getInterfaceByName(mirroringClientInterfaceName)
	s.assertNil(proxyVpp.createTap(clientInterface, 1))

	serverInterface := s.getInterfaceByName(mirroringServerInterfaceName)
	s.assertNil(proxyVpp.createTap(serverInterface, 2))

	nginxContainer := s.getTransientContainerByName(nginxProxyContainerName)
	nginxContainer.create()

	values := struct {
		Proxy  string
		Server string
	}{
		Proxy:  clientInterface.peer.ip4AddressString(),
		Server: serverInterface.ip4AddressString(),
	}
	nginxContainer.createConfig(
		"/nginx.conf",
		"./resources/nginx/nginx_proxy_mirroring.conf",
		values,
	)
	s.assertNil(nginxContainer.start())

	proxyVpp.waitForApp("nginx-", 5)
}

var _ = Describe("NginxSuite", Ordered, ContinueOnFailure, func() {
	var s NginxSuite
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
	for _, test := range nginxTests {
		test := test
		pc := reflect.ValueOf(test).Pointer()
		funcValue := runtime.FuncForPC(pc)
		It(strings.Split(funcValue.Name(), ".")[2], func(ctx SpecContext) {
			test(&s)
		}, SpecTimeout(time.Minute*5))
	}
})

var _ = Describe("NginxSuiteSolo", Ordered, ContinueOnFailure, Serial, func() {
	var s NginxSuite
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
	for _, test := range nginxSoloTests {
		test := test
		pc := reflect.ValueOf(test).Pointer()
		funcValue := runtime.FuncForPC(pc)
		It(strings.Split(funcValue.Name(), ".")[2], Label("SOLO"), func(ctx SpecContext) {
			test(&s)
		}, SpecTimeout(time.Minute*5))
	}
})
