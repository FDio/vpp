// Suite for VPP proxy testing
//
// The topology consists of 3 containers: curl (client), VPP (proxy), nginx (target HTTP server).
// VPP has 2 tap interfaces configured, one for client network and second for server/target network.

package hst

import (
	"fmt"
	. "github.com/onsi/ginkgo/v2"
	"reflect"
	"runtime"
	"strings"
)

// These correspond to names used in yaml config
const (
	VppProxyContainerName  = "vpp-proxy"
	ClientTapInterfaceName = "hstcln"
	ServerTapInterfaceName = "hstsrv"
	CurlContainerTestFile  = "/tmp/testFile"
)

type VppProxySuite struct {
	HstSuite
	nginxPort uint16
}

var vppProxyTests = map[string][]func(s *VppProxySuite){}
var vppProxySoloTests = map[string][]func(s *VppProxySuite){}

func RegisterVppProxyTests(tests ...func(s *VppProxySuite)) {
	vppProxyTests[getTestFilename()] = tests
}

func RegisterVppProxySoloTests(tests ...func(s *VppProxySuite)) {
	vppProxySoloTests[getTestFilename()] = tests
}

func (s *VppProxySuite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.LoadNetworkTopology("2taps")
	s.LoadContainerTopology("vppProxy")
}

func (s *VppProxySuite) SetupTest() {
	s.HstSuite.SetupTest()

	// VPP HTTP connect-proxy
	vppContainer := s.GetContainerByName(VppProxyContainerName)
	vpp, err := vppContainer.newVppInstance(vppContainer.AllocatedCpus)
	s.AssertNotNil(vpp, fmt.Sprint(err))
	s.AssertNil(vpp.Start())
	clientInterface := s.GetInterfaceByName(ClientTapInterfaceName)
	s.AssertNil(vpp.createTap(clientInterface, 1))
	serverInterface := s.GetInterfaceByName(ServerTapInterfaceName)
	s.AssertNil(vpp.createTap(serverInterface, 2))

	// nginx HTTP server
	nginxContainer := s.GetTransientContainerByName(NginxServerContainerName)
	s.AssertNil(nginxContainer.Create())
	s.nginxPort = 80
	nginxSettings := struct {
		LogPrefix string
		Address   string
		Port      uint16
	}{
		LogPrefix: nginxContainer.Name,
		Address:   serverInterface.Ip4AddressString(),
		Port:      s.nginxPort,
	}
	nginxContainer.CreateConfig(
		"/nginx.conf",
		"./resources/nginx/nginx_server.conf",
		nginxSettings,
	)
	s.AssertNil(nginxContainer.Start())
}

func (s *VppProxySuite) TearDownTest() {
	if CurrentSpecReport().Failed() {
		s.CollectNginxLogs(NginxServerContainerName)
	}
	s.HstSuite.TearDownTest()
}

func (s *VppProxySuite) NginxPort() uint16 {
	return s.nginxPort
}

func (s *VppProxySuite) NginxAddr() string {
	return s.GetInterfaceByName(ServerTapInterfaceName).Ip4AddressString()
}

func (s *VppProxySuite) VppProxyAddr() string {
	return s.GetInterfaceByName(ClientTapInterfaceName).Peer.Ip4AddressString()
}

func (s *VppProxySuite) CurlRequest(targetUri string) (string, string) {
	args := fmt.Sprintf("--insecure --noproxy '*' %s", targetUri)
	body, log := s.RunCurlContainer(args)
	return body, log
}

func (s *VppProxySuite) CurlRequestViaTunnel(targetUri string, proxyUri string) (string, string) {
	args := fmt.Sprintf("--max-time 60 --insecure -p -x %s %s", proxyUri, targetUri)
	body, log := s.RunCurlContainer(args)
	return body, log
}

func (s *VppProxySuite) CurlDownloadResource(uri string) {
	args := fmt.Sprintf("--insecure --noproxy '*' --remote-name --output-dir /tmp %s", uri)
	_, log := s.RunCurlContainer(args)
	s.AssertNotContains(log, "Recv failure")
	s.AssertContains(log, "HTTP/1.1 200")
}

func (s *VppProxySuite) CurlUploadResource(uri, file string) {
	args := fmt.Sprintf("--insecure --noproxy '*' -T %s %s", file, uri)
	_, log := s.RunCurlContainer(args)
	s.AssertContains(log, "HTTP/1.1 201")
}

func (s *VppProxySuite) CurlDownloadResourceViaTunnel(uri string, proxyUri string) {
	args := fmt.Sprintf("--max-time 180 --insecure -p -x %s --remote-name --output-dir /tmp %s", proxyUri, uri)
	_, log := s.RunCurlContainer(args)
	s.AssertNotContains(log, "Recv failure")
	s.AssertNotContains(log, "Operation timed out")
	s.AssertContains(log, "CONNECT tunnel established")
	s.AssertContains(log, "HTTP/1.1 200")
	s.AssertNotContains(log, "bytes remaining to read")
}

func (s *VppProxySuite) CurlUploadResourceViaTunnel(uri, proxyUri, file string) {
	args := fmt.Sprintf("--max-time 180 --insecure -p -x %s -T %s %s", proxyUri, file, uri)
	_, log := s.RunCurlContainer(args)
	s.AssertNotContains(log, "Operation timed out")
	s.AssertContains(log, "CONNECT tunnel established")
	s.AssertContains(log, "HTTP/1.1 201")
}

var _ = Describe("VppProxySuite", Ordered, ContinueOnFailure, func() {
	var s VppProxySuite
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

	for filename, tests := range vppProxyTests {
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

var _ = Describe("VppProxySuiteSolo", Ordered, ContinueOnFailure, func() {
	var s VppProxySuite
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

	for filename, tests := range vppProxySoloTests {
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
