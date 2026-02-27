package hst

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
)

var nginxProxyTests = map[string][]func(s *NginxProxySuite){}
var nginxProxySoloTests = map[string][]func(s *NginxProxySuite){}

type NginxProxySuite struct {
	HstSuite
	maxTimeout int
	Interfaces struct {
		Server *NetInterface
		Client *NetInterface
	}
	Containers struct {
		NginxProxy           *Container
		NginxServerTransient *Container
		Vpp                  *Container
		Curl                 *Container
	}
	Ports struct {
		Proxy     uint16
		Upstream1 string
		Upstream2 string
		Upstream3 string
	}
}

func RegisterNginxProxyTests(tests ...func(s *NginxProxySuite)) {
	nginxProxyTests[GetTestFilename()] = tests
}
func RegisterNginxProxySoloTests(tests ...func(s *NginxProxySuite)) {
	nginxProxySoloTests[GetTestFilename()] = tests
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
	s.Interfaces.Client = s.GetInterfaceByName("hstcln")
	s.Interfaces.Server = s.GetInterfaceByName("hstsrv")
	s.Containers.NginxProxy = s.GetContainerByName("nginx-proxy")
	s.Containers.NginxServerTransient = s.GetTransientContainerByName("nginx-server")
	s.Containers.Vpp = s.GetContainerByName("vpp")
	s.Containers.Curl = s.GetContainerByName("curl")
	s.Ports.Proxy = s.GeneratePortAsInt()
	s.Ports.Upstream1 = s.GeneratePort()
	s.Ports.Upstream2 = s.GeneratePort()
	s.Ports.Upstream3 = s.GeneratePort()
}

func (s *NginxProxySuite) SetupTest() {
	s.HstSuite.SetupTest()

	// VPP
	var sessionConfig Stanza
	sessionConfig.
		NewStanza("session").
		Append("enable").
		Append("use-app-socket-api")

	vpp, err := s.Containers.Vpp.newVppInstance(s.Containers.Vpp.AllocatedCpus, sessionConfig)
	AssertNotNil(vpp, fmt.Sprint(err))

	// nginx proxy
	AssertNil(s.Containers.NginxProxy.Create())

	// nginx HTTP server
	AssertNil(s.Containers.NginxServerTransient.Create())
	nginxSettings := struct {
		LogPrefix string
		Address   string
		Timeout   int
		Upstream1 string
		Upstream2 string
		Upstream3 string
	}{
		LogPrefix: s.Containers.NginxServerTransient.Name,
		Address:   s.Interfaces.Server.Host.Ip4AddressString(),
		Timeout:   s.maxTimeout,
		Upstream1: s.Ports.Upstream1,
		Upstream2: s.Ports.Upstream2,
		Upstream3: s.Ports.Upstream3,
	}
	s.Containers.NginxServerTransient.CreateConfigFromTemplate(
		"/nginx.conf",
		"./resources/nginx/nginx_server_mirroring.conf",
		nginxSettings,
	)

	AssertNil(vpp.Start())
	AssertNil(vpp.CreateTap(s.Interfaces.Client, false, 1))
	AssertNil(vpp.CreateTap(s.Interfaces.Server, false, 2))

	if *DryRun {
		s.LogStartedContainers()
		Log("%s* Proxy IP used in tests: %s:%d%s", Colors.pur, s.ProxyAddr(), s.ProxyPort(), Colors.rst)
		s.Skip("Dry run mode = true")
	}

	AssertNil(s.Containers.NginxServerTransient.Start())
}

func (s *NginxProxySuite) TeardownTest() {
	defer s.HstSuite.TeardownTest()
	if CurrentSpecReport().Failed() {
		CollectNginxLogs(s.Containers.NginxProxy)
		CollectNginxLogs(s.Containers.NginxServerTransient)
	}
}

func (s *NginxProxySuite) CreateNginxProxyConfig(container *Container, multiThreadWorkers bool) {
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
		Upstream1 string
		Upstream2 string
		Upstream3 string
	}{
		Workers:   workers,
		LogPrefix: container.Name,
		Proxy:     s.Interfaces.Client.Ip4AddressString(),
		Server:    s.Interfaces.Server.Host.Ip4AddressString(),
		Port:      s.Ports.Proxy,
		Upstream1: s.Ports.Upstream1,
		Upstream2: s.Ports.Upstream2,
		Upstream3: s.Ports.Upstream3,
	}
	container.CreateConfigFromTemplate(
		"/nginx.conf",
		"./resources/nginx/nginx_proxy_mirroring.conf",
		values,
	)
}

func (s *NginxProxySuite) ProxyPort() uint16 {
	return s.Ports.Proxy
}

func (s *NginxProxySuite) ProxyAddr() string {
	return s.Interfaces.Client.Ip4AddressString()
}

func (s *NginxProxySuite) CurlDownloadResource(uri string) {
	args := fmt.Sprintf("-w @/tmp/write_out_download --max-time %d --insecure --noproxy '*' --remote-name --output-dir /tmp %s", s.maxTimeout, uri)
	writeOut, log := RunCurlContainer(s.Containers.Curl, args)
	AssertContains(writeOut, "GET response code: 200")
	AssertNotContains(log, "bytes remaining to read")
	AssertNotContains(log, "Operation timed out")
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
	AssertNil(err, fmt.Sprint(err))
}

var _ = Describe("NginxProxySuite", Ordered, ContinueOnFailure, Label("Nginx", "Proxy", "LDP", "VCL"), func() {
	var s NginxProxySuite
	BeforeAll(func() {
		s.SetupSuite()
	})
	BeforeEach(func() {
		s.SetupTest()
	})
	AfterAll(func() {
		s.TeardownSuite()
	})
	AfterEach(func() {
		s.TeardownTest()
	})

	for filename, tests := range nginxProxyTests {
		for _, test := range tests {
			test := test
			pc := reflect.ValueOf(test).Pointer()
			funcValue := runtime.FuncForPC(pc)
			testName := filename + "/" + strings.Split(funcValue.Name(), ".")[2]
			It(testName, func(ctx SpecContext) {
				Log("[* TEST BEGIN]: " + testName)
				test(&s)
			}, SpecTimeout(TestTimeout))
		}
	}
})

var _ = Describe("NginxProxySuiteSolo", Ordered, ContinueOnFailure, Serial, Label("Nginx", "Proxy", "LDP", "VCL"), func() {
	var s NginxProxySuite
	BeforeAll(func() {
		s.SetupSuite()
	})
	BeforeEach(func() {
		s.SetupTest()
	})
	AfterAll(func() {
		s.TeardownSuite()
	})
	AfterEach(func() {
		s.TeardownTest()
	})

	for filename, tests := range nginxProxySoloTests {
		for _, test := range tests {
			test := test
			pc := reflect.ValueOf(test).Pointer()
			funcValue := runtime.FuncForPC(pc)
			testName := filename + "/" + strings.Split(funcValue.Name(), ".")[2]
			It(testName, func(ctx SpecContext) {
				Log("[* TEST BEGIN]: " + testName)
				test(&s)
			}, SpecTimeout(TestTimeout))
		}
	}
})
