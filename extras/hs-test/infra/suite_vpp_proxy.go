// Suite for VPP proxy testing
//
// The topology consists of 3 containers: curl (client), VPP (proxy), nginx (target HTTP server).
// VPP has 2 tap interfaces configured, one for client network and second for server/target network.

package hst

import (
	"fmt"
	"net"
	"reflect"
	"runtime"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
)

const (
	CurlContainerTestFile = "/tmp/testFile"
)

type VppProxySuite struct {
	HstSuite
	serverPort uint16
	maxTimeout int
	Interfaces struct {
		Client *NetInterface
		Server *NetInterface
	}
	Containers struct {
		VppProxy             *Container
		Curl                 *Container
		NginxServerTransient *Container
		IperfS               *Container
		IperfC               *Container
	}
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

	s.serverPort = 80
	if *IsVppDebug {
		s.maxTimeout = 600
	} else {
		s.maxTimeout = 60
	}
	s.Interfaces.Client = s.GetInterfaceByName("hstcln")
	s.Interfaces.Server = s.GetInterfaceByName("hstsrv")
	s.Containers.NginxServerTransient = s.GetTransientContainerByName("nginx-server")
	s.Containers.VppProxy = s.GetContainerByName("vpp-proxy")
	s.Containers.Curl = s.GetContainerByName("curl")
	s.Containers.IperfC = s.GetContainerByName("iperfC")
	s.Containers.IperfS = s.GetContainerByName("iperfS")
}

func (s *VppProxySuite) SetupTest() {
	s.HstSuite.SetupTest()

	// VPP HTTP connect-proxy
	var memoryConfig Stanza
	memoryConfig.NewStanza("memory").Append("main-heap-size 2G")
	vpp, err := s.Containers.VppProxy.newVppInstance(s.Containers.VppProxy.AllocatedCpus, memoryConfig)
	s.AssertNotNil(vpp, fmt.Sprint(err))

	s.AssertNil(vpp.Start())
	s.AssertNil(vpp.CreateTap(s.Interfaces.Client, false, 1, 1))
	s.AssertNil(vpp.CreateTap(s.Interfaces.Server, false, 1, 2))

	if *DryRun {
		s.LogStartedContainers()
		s.Skip("Dry run mode = true")
	}
}

func (s *VppProxySuite) TearDownTest() {
	vpp := s.Containers.VppProxy.VppInstance
	if CurrentSpecReport().Failed() {
		s.Log(vpp.Vppctl("show session verbose 2"))
		s.Log(vpp.Vppctl("show error"))
		s.CollectNginxLogs(s.Containers.NginxServerTransient)
		s.CollectIperfLogs(s.Containers.IperfS)
	}
	s.HstSuite.TearDownTest()
}

func (s *VppProxySuite) SetupNginxServer() {
	s.AssertNil(s.Containers.NginxServerTransient.Create())
	nginxSettings := struct {
		LogPrefix string
		Address   string
		Port      uint16
		Timeout   int
	}{
		LogPrefix: s.Containers.NginxServerTransient.Name,
		Address:   s.Interfaces.Server.Ip4AddressString(),
		Port:      s.serverPort,
		Timeout:   s.maxTimeout,
	}
	s.Containers.NginxServerTransient.CreateConfigFromTemplate(
		"/nginx.conf",
		"./resources/nginx/nginx_server.conf",
		nginxSettings,
	)
	s.AssertNil(s.Containers.NginxServerTransient.Start())
}

func (s *VppProxySuite) ServerPort() uint16 {
	return s.serverPort
}

func (s *VppProxySuite) ServerAddr() string {
	return s.Interfaces.Server.Ip4AddressString()
}

func (s *VppProxySuite) VppProxyAddr() string {
	return s.Interfaces.Client.Peer.Ip4AddressString()
}

func (s *VppProxySuite) ClientAddr() string {
	return s.Interfaces.Client.Ip4AddressString()
}

func (s *VppProxySuite) CurlRequest(targetUri string) (string, string) {
	args := fmt.Sprintf("--insecure --noproxy '*' %s", targetUri)
	body, log := s.RunCurlContainer(s.Containers.Curl, args)
	return body, log
}

func (s *VppProxySuite) CurlRequestViaTunnel(targetUri string, proxyUri string) (string, string) {
	args := fmt.Sprintf("--max-time %d --insecure -p -x %s %s", s.maxTimeout, proxyUri, targetUri)
	body, log := s.RunCurlContainer(s.Containers.Curl, args)
	return body, log
}

func (s *VppProxySuite) CurlDownloadResource(uri string) {
	args := fmt.Sprintf("-w @/tmp/write_out_download --max-time %d --insecure --noproxy '*' --remote-name --output-dir /tmp %s", s.maxTimeout, uri)
	writeOut, log := s.RunCurlContainer(s.Containers.Curl, args)
	s.AssertContains(writeOut, "GET response code: 200")
	s.AssertNotContains(log, "bytes remaining to read")
	s.AssertNotContains(log, "Operation timed out")
}

func (s *VppProxySuite) CurlUploadResource(uri, file string) {
	args := fmt.Sprintf("-w @/tmp/write_out_upload --max-time %d --insecure --noproxy '*' -T %s %s", s.maxTimeout, file, uri)
	writeOut, log := s.RunCurlContainer(s.Containers.Curl, args)
	s.AssertContains(writeOut, "PUT response code: 201")
	s.AssertNotContains(log, "Operation timed out")
}

func (s *VppProxySuite) CurlDownloadResourceViaTunnel(uri string, proxyUri string) {
	args := fmt.Sprintf("-w @/tmp/write_out_download_connect --max-time %d --insecure -p -x %s --remote-name --output-dir /tmp %s", s.maxTimeout, proxyUri, uri)
	writeOut, log := s.RunCurlContainer(s.Containers.Curl, args)
	s.AssertContains(writeOut, "CONNECT response code: 200")
	s.AssertContains(writeOut, "GET response code: 200")
	s.AssertNotContains(log, "bytes remaining to read")
	s.AssertNotContains(log, "Operation timed out")
	s.AssertNotContains(log, "Upgrade:")
}

func (s *VppProxySuite) CurlUploadResourceViaTunnel(uri, proxyUri, file string) {
	args := fmt.Sprintf("-w @/tmp/write_out_upload_connect --max-time %d --insecure -p -x %s -T %s %s", s.maxTimeout, proxyUri, file, uri)
	writeOut, log := s.RunCurlContainer(s.Containers.Curl, args)
	s.AssertContains(writeOut, "CONNECT response code: 200")
	s.AssertContains(writeOut, "PUT response code: 201")
	s.AssertNotContains(log, "Operation timed out")
	s.AssertNotContains(log, "Upgrade:")
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 1500)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		_, err = conn.Write(buf[:n])
		if err != nil {
			break
		}
	}
}

func (s *VppProxySuite) StartEchoServer() *net.TCPListener {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP(s.ServerAddr()), Port: int(s.ServerPort())})
	s.AssertNil(err, fmt.Sprint(err))
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}
			go handleConn(conn)
		}
	}()
	s.Log("* started tcp echo server " + s.ServerAddr() + ":" + strconv.Itoa(int(s.ServerPort())))
	return listener
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

var _ = Describe("VppProxySuiteSolo", Ordered, ContinueOnFailure, Serial, func() {
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
