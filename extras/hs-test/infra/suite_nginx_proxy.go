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
	proxyPort  uint16
	maxTimeout int
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

	if *IsVppDebug {
		s.maxTimeout = 600
	} else {
		s.maxTimeout = 60
	}
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
	clientInterface := s.GetInterfaceByName(MirroringClientInterfaceName)
	serverInterface := s.GetInterfaceByName(MirroringServerInterfaceName)

	// nginx proxy
	nginxProxyContainer := s.GetContainerByName(NginxProxyContainerName)
	s.AssertNil(nginxProxyContainer.Create())
	s.proxyPort = 80

	// nginx HTTP server
	nginxServerContainer := s.GetTransientContainerByName(NginxServerContainerName)
	s.AssertNil(nginxServerContainer.Create())
	nginxSettings := struct {
		LogPrefix string
		Address   string
		Timeout   int
	}{
		LogPrefix: nginxServerContainer.Name,
		Address:   serverInterface.Ip4AddressString(),
		Timeout:   s.maxTimeout,
	}
	nginxServerContainer.CreateConfig(
		"/nginx.conf",
		"./resources/nginx/nginx_server_mirroring.conf",
		nginxSettings,
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
	s.AssertNil(vpp.createTap(clientInterface, 1))
	s.AssertNil(vpp.createTap(serverInterface, 2))
	s.AssertNil(nginxProxyContainer.Start())
	s.AssertNil(nginxServerContainer.Start())
}

func (s *NginxProxySuite) TearDownTest() {
	if CurrentSpecReport().Failed() {
		s.CollectNginxLogs(NginxServerContainerName)
		s.CollectNginxLogs(NginxProxyContainerName)
	}
	s.HstSuite.TearDownTest()
}

func (s *NginxProxySuite) CreateNginxProxyConfig(container *Container, multiThreadWorkers bool) {
	clientInterface := s.GetInterfaceByName(MirroringClientInterfaceName)
	serverInterface := s.GetInterfaceByName(MirroringServerInterfaceName)
	var workers uint8
	if multiThreadWorkers {
		workers = 2
	} else {
		workers = 1
	}
	values := struct {
		Workers   uint8
		LogPrefix string
		Proxy     string
		Server    string
		Port      uint16
	}{
		Workers:   workers,
		LogPrefix: container.Name,
		Proxy:     clientInterface.Peer.Ip4AddressString(),
		Server:    serverInterface.Ip4AddressString(),
		Port:      s.proxyPort,
	}
	container.CreateConfig(
		"/nginx.conf",
		"./resources/nginx/nginx_proxy_mirroring.conf",
		values,
	)
}

func (s *NginxProxySuite) ProxyPort() uint16 {
	return s.proxyPort
}

func (s *NginxProxySuite) ProxyAddr() string {
	return s.GetInterfaceByName(MirroringClientInterfaceName).Peer.Ip4AddressString()
}

func (s *NginxProxySuite) CurlDownloadResource(uri string) {
	args := fmt.Sprintf("-w @/tmp/write_out_download --max-time %d --insecure --noproxy '*' --remote-name --output-dir /tmp %s", s.maxTimeout, uri)
	writeOut, log := s.RunCurlContainer(args)
	s.AssertContains(writeOut, "GET response code: 200")
	s.AssertNotContains(log, "bytes remaining to read")
	s.AssertNotContains(log, "Operation timed out")
}

func (s *NginxProxySuite) AddVclConfig(container *Container, multiThreadWorkers bool) {
	var vclConf Stanza
	vclFileName := container.GetHostWorkDir() + "/vcl.conf"

	appSocketApi := fmt.Sprintf("app-socket-api %s/var/run/app_ns_sockets/default",
		container.GetContainerWorkDir())

	vclConf.
		NewStanza("vcl").
		Append("heapsize 64M").
		Append("rx-fifo-size 4000000").
		Append("tx-fifo-size 4000000").
		Append("segment-size 4000000000").
		Append("add-segment-size 4000000000").
		Append("event-queue-size 100000").
		Append("use-mq-eventfd").
		Append(appSocketApi)
	if multiThreadWorkers {
		vclConf.Append("multi-thread-workers")
	}

	err := vclConf.Close().SaveToFile(vclFileName)
	s.AssertNil(err, fmt.Sprint(err))
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
