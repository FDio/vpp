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

	if *DryRun {
		vpp.CreateVppConfig()
		uri := fmt.Sprintf("http://%s:%d/httpTestFile", s.VppProxyAddr(), 8080)
		for name := range s.Containers {
			s.Log("\033[36m"+"docker start %s && docker exec -it %s bash", name, name)
		}
		s.Log("\nvpp -c /tmp/vpp/etc/vpp/startup.conf &> /proc/1/fd/1")
		s.Log("vppctl -s /tmp/vpp/var/run/vpp/cli.sock\n")
		startupConfig := fmt.Sprintf("create tap id 1 host-if-name %s\n"+
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
		s.AssertNil(vppContainer.CreateFileInWorkDir("vpp-config.conf", startupConfig),
			"cannot create file")

		s.Log("This config will be loaded on VPP startup:\n%s", startupConfig)

		s.Log("test proxy server server-uri [proto]://%s/%d client-uri tcp://%s/%d\n",
			s.VppProxyAddr(),
			8080,
			s.NginxAddr(),
			s.nginxPort,
		)
		s.Log("docker run --rm --name curl%s hs-test/curl curl -v -s --insecure --noproxy '*' --remote-name --output-dir /tmp %s", s.Ppid, uri)

		s.Log("sudo ip addr add %s dev %s", clientInterface.Ip4Address, clientInterface.name)
		s.Log("sudo ip addr add %s dev %s\033[0m", serverInterface.Ip4Address, serverInterface.name)

		s.Skip("Dry run mode = true")
	}
	s.AssertNil(vpp.Start())
	s.AssertNil(vpp.createTap(clientInterface, 1))
	s.AssertNil(vpp.createTap(serverInterface, 2))
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
