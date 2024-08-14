// Suite for VPP proxy testing
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

// These correspond to names used in yaml config
const (
	ClientTapInterfaceName = "hstcln"
	ServerTapInterfaceName = "hstsrv"
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

func (s *VppProxySuite) saveNginxLogs() {
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

func (s *VppProxySuite) TearDownTest() {
	if CurrentSpecReport().Failed() {
		s.saveNginxLogs()
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

func (s *VppProxySuite) DoCurlRequest(proxyPort uint16, target string) (string, string) {
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
