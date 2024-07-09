package hst

import (
	"reflect"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
)

// These correspond to names used in yaml config
const (
	VppProxyContainerName        = "vpp-proxy"
	NginxProxyContainerName      = "nginx-proxy"
	NginxServerContainerName     = "nginx-server"
	MirroringClientInterfaceName = "hstcln"
	MirroringServerInterfaceName = "hstsrv"
)

var nginxTests = map[string][]func(s *NginxSuite){}
var nginxSoloTests = map[string][]func(s *NginxSuite){}

type NginxSuite struct {
	HstSuite
}

func RegisterNginxTests(tests ...func(s *NginxSuite)) {
	nginxTests[getTestFilename()] = tests
}
func RegisterNginxSoloTests(tests ...func(s *NginxSuite)) {
	nginxSoloTests[getTestFilename()] = tests
}

func (s *NginxSuite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.LoadNetworkTopology("2taps")
	s.LoadContainerTopology("nginxProxyAndServer")
}

func (s *NginxSuite) SetupTest() {
	s.HstSuite.SetupTest()

	// Setup test conditions
	var sessionConfig Stanza
	sessionConfig.
		NewStanza("session").
		Append("enable").
		Append("use-app-socket-api")

	if strings.Contains(CurrentSpecReport().LeafNodeText, "InterruptMode") {
		sessionConfig.Append("use-private-rx-mqs").Close()
		s.Log("**********************INTERRUPT MODE**********************")
	} else {
		sessionConfig.Close()
	}

	// ... for proxy
	vppProxyContainer := s.GetContainerByName(VppProxyContainerName)
	proxyVpp, _ := vppProxyContainer.newVppInstance(vppProxyContainer.AllocatedCpus, sessionConfig)
	s.AssertNil(proxyVpp.Start())

	clientInterface := s.GetInterfaceByName(MirroringClientInterfaceName)
	s.AssertNil(proxyVpp.createTap(clientInterface, 1))

	serverInterface := s.GetInterfaceByName(MirroringServerInterfaceName)
	s.AssertNil(proxyVpp.createTap(serverInterface, 2))

	nginxContainer := s.GetTransientContainerByName(NginxProxyContainerName)
	s.AssertNil(nginxContainer.Create())

	values := struct {
		Proxy  string
		Server string
	}{
		Proxy:  clientInterface.Peer.Ip4AddressString(),
		Server: serverInterface.Ip4AddressString(),
	}
	nginxContainer.CreateConfig(
		"/nginx.conf",
		"./resources/nginx/nginx_proxy_mirroring.conf",
		values,
	)
	s.AssertNil(nginxContainer.Start())

	proxyVpp.WaitForApp("nginx-", 5)
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

	for filename, tests := range nginxTests {
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

	for filename, tests := range nginxSoloTests {
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
