// Suite for VPP proxy testing
//
// The topology consists of 3 containers: curl (client), VPP (proxy), nginx (target HTTP server).
// VPP has 2 tap interfaces configured, one for client network and second for server/target network.

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
	VppProxyContainerName  = "vpp-proxy"
	ClientTapInterfaceName = "hstcln"
	ServerTapInterfaceName = "hstsrv"
	CurlContainerTestFile  = "/tmp/testFile"
)

type VppProxySuite struct {
	HstSuite
	nginxPort  uint16
	maxTimeout int
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

	if *IsVppDebug {
		s.maxTimeout = 600
	} else {
		s.maxTimeout = 60
	}
}

func (s *VppProxySuite) SetupTest() {
	s.HstSuite.SetupTest()

	// VPP HTTP connect-proxy
	vppContainer := s.GetContainerByName(VppProxyContainerName)
	vpp, err := vppContainer.newVppInstance(vppContainer.AllocatedCpus)
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
	nginxContainer.CreateConfigFromTemplate(
		"/nginx.conf",
		"./resources/nginx/nginx_server.conf",
		nginxSettings,
	)
	s.AssertNil(nginxContainer.Start())

	s.AssertNil(vpp.Start())
	s.AssertNil(vpp.createTap(clientInterface, 1))
	s.AssertNil(vpp.createTap(serverInterface, 2))

	if *DryRun {
		s.LogStartedContainers()
		s.Skip("Dry run mode = true")
	}
}

func (s *VppProxySuite) TearDownTest() {
	vpp := s.GetContainerByName(VppProxyContainerName).VppInstance
	if CurrentSpecReport().Failed() {
		s.Log(vpp.Vppctl("show session verbose 2"))
		s.Log(vpp.Vppctl("show error"))
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
	args := fmt.Sprintf("--max-time %d --insecure -p -x %s %s", s.maxTimeout, proxyUri, targetUri)
	body, log := s.RunCurlContainer(args)
	return body, log
}

func (s *VppProxySuite) CurlDownloadResource(uri string) {
	args := fmt.Sprintf("-w @/tmp/write_out_download --max-time %d --insecure --noproxy '*' --remote-name --output-dir /tmp %s", s.maxTimeout, uri)
	writeOut, log := s.RunCurlContainer(args)
	s.AssertContains(writeOut, "GET response code: 200")
	s.AssertNotContains(log, "bytes remaining to read")
	s.AssertNotContains(log, "Operation timed out")
}

func (s *VppProxySuite) CurlUploadResource(uri, file string) {
	args := fmt.Sprintf("-w @/tmp/write_out_upload --max-time %d --insecure --noproxy '*' -T %s %s", s.maxTimeout, file, uri)
	writeOut, log := s.RunCurlContainer(args)
	s.AssertContains(writeOut, "PUT response code: 201")
	s.AssertNotContains(log, "Operation timed out")
}

func (s *VppProxySuite) CurlDownloadResourceViaTunnel(uri string, proxyUri string) {
	args := fmt.Sprintf("-w @/tmp/write_out_download_connect --max-time %d --insecure -p -x %s --remote-name --output-dir /tmp %s", s.maxTimeout, proxyUri, uri)
	writeOut, log := s.RunCurlContainer(args)
	s.AssertContains(writeOut, "CONNECT response code: 200")
	s.AssertContains(writeOut, "GET response code: 200")
	s.AssertNotContains(log, "bytes remaining to read")
	s.AssertNotContains(log, "Operation timed out")
}

func (s *VppProxySuite) CurlUploadResourceViaTunnel(uri, proxyUri, file string) {
	args := fmt.Sprintf("-w @/tmp/write_out_upload_connect --max-time %d --insecure -p -x %s -T %s %s", s.maxTimeout, proxyUri, file, uri)
	writeOut, log := s.RunCurlContainer(args)
	s.AssertContains(writeOut, "CONNECT response code: 200")
	s.AssertContains(writeOut, "PUT response code: 201")
	s.AssertNotContains(log, "Operation timed out")
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
			}, SpecTimeout(TestTimeout))
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
			}, SpecTimeout(TestTimeout))
		}
	}
})
