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
	proxyPort  uint16
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
	s.Interfaces.Client = s.GetInterfaceByName("hstcln")
	s.Interfaces.Server = s.GetInterfaceByName("hstsrv")
	s.Containers.NginxProxy = s.GetContainerByName("nginx-proxy")
	s.Containers.NginxServerTransient = s.GetTransientContainerByName("nginx-server")
	s.Containers.Vpp = s.GetContainerByName("vpp")
	s.Containers.Curl = s.GetContainerByName("curl")
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
	s.AssertNotNil(vpp, fmt.Sprint(err))

	// nginx proxy
	s.AssertNil(s.Containers.NginxProxy.Create())
	s.proxyPort = 80

	// nginx HTTP server
	s.AssertNil(s.Containers.NginxServerTransient.Create())
	nginxSettings := struct {
		LogPrefix string
		Address   string
		Timeout   int
	}{
		LogPrefix: s.Containers.NginxServerTransient.Name,
		Address:   s.Interfaces.Server.Ip4AddressString(),
		Timeout:   s.maxTimeout,
	}
	s.Containers.NginxServerTransient.CreateConfigFromTemplate(
		"/nginx.conf",
		"./resources/nginx/nginx_server_mirroring.conf",
		nginxSettings,
	)

	s.AssertNil(vpp.Start())
	s.AssertNil(vpp.CreateTap(s.Interfaces.Client, false, 1, 1))
	s.AssertNil(vpp.CreateTap(s.Interfaces.Server, false, 1, 2))

	if *DryRun {
		s.LogStartedContainers()
		s.Log("%s* Proxy IP used in tests: %s:%d%s", Colors.pur, s.ProxyAddr(), s.ProxyPort(), Colors.rst)
		s.Skip("Dry run mode = true")
	}

	s.AssertNil(s.Containers.NginxProxy.Start())
	s.AssertNil(s.Containers.NginxServerTransient.Start())
}

func (s *NginxProxySuite) TearDownTest() {
	if CurrentSpecReport().Failed() {
		s.CollectNginxLogs(s.Containers.NginxProxy)
		s.CollectNginxLogs(s.Containers.NginxServerTransient)
	}
	s.HstSuite.TearDownTest()
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
	}{
		Workers:   workers,
		LogPrefix: container.Name,
		Proxy:     s.Interfaces.Client.Peer.Ip4AddressString(),
		Server:    s.Interfaces.Server.Ip4AddressString(),
		Port:      s.proxyPort,
	}
	container.CreateConfigFromTemplate(
		"/nginx.conf",
		"./resources/nginx/nginx_proxy_mirroring.conf",
		values,
	)
}

func (s *NginxProxySuite) ProxyPort() uint16 {
	return s.proxyPort
}

func (s *NginxProxySuite) ProxyAddr() string {
	return s.Interfaces.Client.Peer.Ip4AddressString()
}

func (s *NginxProxySuite) CurlDownloadResource(uri string) {
	args := fmt.Sprintf("-w @/tmp/write_out_download --max-time %d --insecure --noproxy '*' --remote-name --output-dir /tmp %s", s.maxTimeout, uri)
	writeOut, log := s.RunCurlContainer(s.Containers.Curl, args)
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
			}, SpecTimeout(TestTimeout))
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
			}, SpecTimeout(TestTimeout))
		}
	}
})
