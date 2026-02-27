package hst

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
)

var noTopoTests = map[string][]func(s *NoTopoSuite){}
var noTopoSoloTests = map[string][]func(s *NoTopoSuite){}
var noTopoMWTests = map[string][]func(s *NoTopoSuite){}

type NoTopoSuite struct {
	HstSuite
	Interfaces struct {
		Tap *NetInterface
	}
	Containers struct {
		Vpp         *Container
		Nginx       *Container
		NginxHttp3  *Container
		NginxServer *Container
		Wrk         *Container
		Curl        *Container
		Ab          *Container
		ServerApp   *Container
		ClientApp   *Container
	}
	Ports struct {
		NginxServer    string
		NginxServerSsl string
		NginxHttp3     string
		Http           string
		CutThru        string
	}
}

func RegisterNoTopoTests(tests ...func(s *NoTopoSuite)) {
	noTopoTests[GetTestFilename()] = tests
}
func RegisterNoTopoSoloTests(tests ...func(s *NoTopoSuite)) {
	noTopoSoloTests[GetTestFilename()] = tests
}
func RegisterNoTopoMWTests(tests ...func(s *NoTopoSuite)) {
	noTopoMWTests[GetTestFilename()] = tests
}

func (s *NoTopoSuite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.LoadNetworkTopology("tap")
	s.LoadContainerTopology("single")
	s.Interfaces.Tap = s.GetInterfaceByName("htapvpp")
	s.Containers.Vpp = s.GetContainerByName("vpp")
	s.Containers.Nginx = s.GetContainerByName("nginx")
	s.Containers.NginxHttp3 = s.GetContainerByName("nginx-http3")
	s.Containers.NginxServer = s.GetTransientContainerByName("nginx-server")
	s.Containers.Wrk = s.GetContainerByName("wrk")
	s.Containers.Curl = s.GetContainerByName("curl")
	s.Containers.Ab = s.GetContainerByName("ab")
	s.Containers.ServerApp = s.GetContainerByName("server-app")
	s.Containers.ClientApp = s.GetContainerByName("client-app")
	s.Ports.Http = s.GeneratePort()
	s.Ports.NginxServer = s.GeneratePort()
	s.Ports.NginxServerSsl = s.GeneratePort()
	s.Ports.NginxHttp3 = s.GeneratePort()
	s.Ports.CutThru = s.GeneratePort()
}

func (s *NoTopoSuite) SetupTest() {
	s.HstSuite.SetupTest()

	// Setup test conditions
	var sessionConfig Stanza
	sessionConfig.
		NewStanza("session").
		Append("enable").
		Append("use-app-socket-api")

	if strings.Contains(CurrentSpecReport().LeafNodeText, "InterruptMode") {
		sessionConfig.Append("use-private-rx-mqs").Close()
		Log("**********************INTERRUPT MODE**********************")
	} else {
		sessionConfig.Close()
	}

	vpp, _ := s.Containers.Vpp.newVppInstance(s.Containers.Vpp.AllocatedCpus, sessionConfig)

	AssertNil(vpp.Start())
	AssertNil(vpp.CreateTap(s.Interfaces.Tap, false, 1), "failed to create tap interface")

	if *DryRun {
		s.LogStartedContainers()
		s.Skip("Dry run mode = true")
	}
}

func (s *NoTopoSuite) TeardownTest() {
	defer s.HstSuite.TeardownTest()
	if CurrentSpecReport().Failed() {
		CollectNginxLogs(s.Containers.NginxHttp3)
	}
}

func (s *NoTopoSuite) CreateNginxConfig(container *Container, multiThreadWorkers bool) {
	var workers uint8
	if multiThreadWorkers {
		workers = 2
	} else {
		workers = 1
	}
	values := struct {
		Workers uint8
		Port    string
	}{
		Workers: workers,
		Port:    s.Ports.NginxServer,
	}
	container.CreateConfigFromTemplate(
		"/nginx.conf",
		"./resources/nginx/nginx.conf",
		values,
	)
}

// Creates container and config.
func (s *NoTopoSuite) CreateNginxServer() {
	AssertNil(s.Containers.NginxServer.Create())
	nginxSettings := struct {
		LogPrefix string
		Address   string
		Port      string
		PortSsl   string
		Http2     string
		Timeout   int
	}{
		LogPrefix: s.Containers.NginxServer.Name,
		Address:   s.Interfaces.Tap.Ip4AddressString(),
		Port:      s.Ports.NginxServer,
		PortSsl:   s.Ports.NginxServerSsl,
		Http2:     "off",
		Timeout:   600,
	}
	s.Containers.NginxServer.CreateConfigFromTemplate(
		"/nginx.conf",
		"./resources/nginx/nginx_server.conf",
		nginxSettings,
	)
}

func (s *NoTopoSuite) AddNginxVclConfig(multiThreadWorkers bool) {
	vclFileName := s.Containers.Nginx.GetHostWorkDir() + "/vcl.conf"
	appSocketApi := fmt.Sprintf("app-socket-api %s/var/run/app_ns_sockets/default",
		s.Containers.Nginx.GetContainerWorkDir())

	var vclConf Stanza
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

func (s *NoTopoSuite) VppAddr() string {
	return s.Interfaces.Tap.Ip4AddressString()
}

func (s *NoTopoSuite) VppIfName() string {
	return s.Interfaces.Tap.Name()
}

func (s *NoTopoSuite) HostAddr() string {
	return s.Interfaces.Tap.Host.Ip4AddressString()
}

func (s *NoTopoSuite) CreateNginxHttp3Config(container *Container) {
	nginxSettings := struct {
		LogPrefix string
		Address   string
		Port      string
	}{
		LogPrefix: container.Name,
		Address:   s.VppAddr(),
		Port:      s.Ports.NginxHttp3,
	}
	container.CreateConfigFromTemplate(
		"/nginx.conf",
		"./resources/nginx/nginx_http3.conf",
		nginxSettings,
	)
}

func (s *NoTopoSuite) CreateGenericVclConfig(container *Container) {
	var vclConf Stanza
	vclFileName := container.GetHostWorkDir() + "/vcl.conf"

	appSocketApi := fmt.Sprintf("app-socket-api %s/var/run/app_ns_sockets/default",
		container.GetContainerWorkDir())
	err := vclConf.
		NewStanza("vcl").
		Append("rx-fifo-size 4000000").
		Append("tx-fifo-size 4000000").
		Append("app-scope-local").
		Append("app-scope-global").
		Append("use-mq-eventfd").
		Append(appSocketApi).Close().
		SaveToFile(vclFileName)
	AssertNil(err, fmt.Sprint(err))
}

var _ = Describe("NoTopoSuite", Ordered, ContinueOnFailure, Label("Generic"), func() {
	var s NoTopoSuite
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

	for filename, tests := range noTopoTests {
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

var _ = Describe("NoTopoSuiteSolo", Ordered, ContinueOnFailure, Serial, Label("Generic"), func() {
	var s NoTopoSuite
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

	for filename, tests := range noTopoSoloTests {
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

var _ = Describe("NoTopoMWSuite", Ordered, ContinueOnFailure, Serial, Label("Generic", "MW"), func() {
	var s NoTopoSuite
	BeforeAll(func() {
		s.SetupSuite()
	})
	BeforeEach(func() {
		s.SkipIfNotEnoguhCpus = true
	})
	AfterAll(func() {
		s.TeardownSuite()
	})
	AfterEach(func() {
		s.TeardownTest()
	})

	for filename, tests := range noTopoMWTests {
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
