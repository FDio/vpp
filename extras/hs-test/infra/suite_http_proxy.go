// Suite for HTTP CONNECT proxy (tunnel) testing
//
// The topology consists of 3 containers: curl (client), VPP (proxy), nginx (tunnel target).
// VPP has 2 tap interfaces configured, one for client network and second for server/target network.

package hst

import (
	"fmt"
	. "github.com/onsi/ginkgo/v2"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
)

type HttpProxySuite struct {
	HstSuite
	nginxPort uint16
}

var httpProxyTests = map[string][]func(s *HttpProxySuite){}
var httpProxySoloTests = map[string][]func(s *HttpProxySuite){}

func RegisterHttpProxyTests(tests ...func(s *HttpProxySuite)) {
	httpProxyTests[getTestFilename()] = tests
}

func RegisterHttpProxySoloTests(tests ...func(s *HttpProxySuite)) {
	httpProxySoloTests[getTestFilename()] = tests
}

func (s *HttpProxySuite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.LoadNetworkTopology("2taps")
	s.LoadContainerTopology("httpProxy")
}

func (s *HttpProxySuite) SetupTest() {
	s.HstSuite.SetupTest()

	// VPP HTTP connect-proxy
	vppContainer := s.GetContainerByName(VppProxyContainerName)
	vpp, err := vppContainer.newVppInstance(vppContainer.AllocatedCpus)
	s.AssertNotNil(vpp, fmt.Sprint(err))
	s.AssertNil(vpp.Start())
	clientInterface := s.GetInterfaceByName(MirroringClientInterfaceName)
	s.AssertNil(vpp.createTap(clientInterface, 1))
	serverInterface := s.GetInterfaceByName(MirroringServerInterfaceName)
	s.AssertNil(vpp.createTap(serverInterface, 2))

	// nginx HTTP server
	nginxContainer := s.GetTransientContainerByName(NginxServerContainerName)
	s.AssertNil(nginxContainer.Create())
	s.nginxPort = 80
	address := struct {
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
		address,
	)
	s.AssertNil(nginxContainer.Start())
}

func (s *HttpProxySuite) saveNginxLogs() {
	nginxContainer := s.GetContainerByName(NginxServerContainerName)
	targetDir := nginxContainer.getLogDirPath()
	source := nginxContainer.GetHostWorkDir() + "/" + nginxContainer.Name + "-"
	cmd := exec.Command("cp", "-t", targetDir, source+"error.log", source+"access.log")
	s.Log(cmd.String())
	err := cmd.Run()
	if err != nil {
		s.Log(fmt.Sprint(err))
	}
}

func (s *HttpProxySuite) TearDownTest() {
	if CurrentSpecReport().Failed() {
		s.saveNginxLogs()
	}
	s.HstSuite.TearDownTest()
}

func (s *HttpProxySuite) NginxPort() uint16 {
	return s.nginxPort
}

func (s *HttpProxySuite) NginxAddr() string {
	return s.GetInterfaceByName(MirroringServerInterfaceName).Ip4AddressString()
}

func (s *HttpProxySuite) VppProxyAddr() string {
	return s.GetInterfaceByName(MirroringClientInterfaceName).Peer.Ip4AddressString()
}

func (s *HttpProxySuite) DoCurlRequest(proxyPort uint16, target string) (string, string) {
	curlCont := s.GetContainerByName("curl")
	args := fmt.Sprintf("curl -v -s -p -x http://%s:%d http://%s:%d/%s", s.VppProxyAddr(), proxyPort, s.NginxAddr(), s.NginxPort(), target)
	s.Log(args)
	curlCont.ExtraRunningArgs = args
	curlCont.Run()
	body, log := curlCont.GetOutput()
	s.Log(log)
	s.Log(body)
	return body, log
}

var _ = Describe("HttpProxySuite", Ordered, ContinueOnFailure, func() {
	var s HttpProxySuite
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

	for filename, tests := range httpProxyTests {
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

var _ = Describe("HttpProxySuiteSolo", Ordered, ContinueOnFailure, func() {
	var s HttpProxySuite
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

	for filename, tests := range httpProxySoloTests {
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
