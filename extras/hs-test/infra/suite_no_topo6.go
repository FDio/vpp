package hst

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
)

var noTopo6Tests = map[string][]func(s *NoTopo6Suite){}
var noTopo6SoloTests = map[string][]func(s *NoTopo6Suite){}

type NoTopo6Suite struct {
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
	}
	NginxServerPort string
}

func RegisterNoTopo6Tests(tests ...func(s *NoTopo6Suite)) {
	noTopo6Tests[getTestFilename()] = tests
}
func RegisterNoTopo6SoloTests(tests ...func(s *NoTopo6Suite)) {
	noTopo6SoloTests[getTestFilename()] = tests
}

func (s *NoTopo6Suite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.LoadNetworkTopology("tap6")
	s.LoadContainerTopology("single")
	s.Interfaces.Tap = s.GetInterfaceByName("htaphost")
	s.Containers.Vpp = s.GetContainerByName("vpp")
	s.Containers.Nginx = s.GetContainerByName("nginx")
	s.Containers.NginxHttp3 = s.GetContainerByName("nginx-http3")
	s.Containers.NginxServer = s.GetTransientContainerByName("nginx-server")
	s.Containers.Wrk = s.GetContainerByName("wrk")
	s.Containers.Curl = s.GetContainerByName("curl")
	s.Containers.Ab = s.GetContainerByName("ab")
}

func (s *NoTopo6Suite) SetupTest() {
	s.HstSuite.SetupTest()

	// Setup test conditions
	var sessionConfig Stanza
	sessionConfig.
		NewStanza("session").
		Append("enable").
		Append("use-app-socket-api")

	if strings.Contains(CurrentSpecReport().LeafNodeText, "InterruptMode") {
		sessionConfig.Append("use-private-rx-mqs").Close()
		s.Log("**********************INTERRUPT MODE**********************")
	} else {
		sessionConfig.Close()
	}

	vpp, _ := s.Containers.Vpp.newVppInstance(s.Containers.Vpp.AllocatedCpus, sessionConfig)

	s.AssertNil(vpp.Start())
	s.AssertNil(vpp.CreateTap6(s.Interfaces.Tap, 1, 1), "failed to create tap interface")

	if *DryRun {
		s.LogStartedContainers()
		s.Skip("Dry run mode = true")
	}
}

func (s *NoTopo6Suite) TearDownTest() {
	if CurrentSpecReport().Failed() {
		s.CollectNginxLogs(s.Containers.NginxHttp3)
	}
	s.HstSuite.TearDownTest()
}

func (s *NoTopo6Suite) CreateNginxConfig(container *Container, multiThreadWorkers bool) {
	var workers uint8
	if multiThreadWorkers {
		workers = 2
	} else {
		workers = 1
	}
	values := struct {
		Workers uint8
	}{
		Workers: workers,
	}
	container.CreateConfigFromTemplate(
		"/nginx.conf",
		"./resources/nginx/nginx.conf",
		values,
	)
}

// Creates container and config.
func (s *NoTopo6Suite) CreateNginxServer() {
	s.AssertNil(s.Containers.NginxServer.Create())
	s.NginxServerPort = s.GetPortFromPpid()
	nginxSettings := struct {
		LogPrefix string
		Address   string
		Port      string
		Timeout   int
	}{
		LogPrefix: s.Containers.NginxServer.Name,
		Address:   "[" + s.Interfaces.Tap.Ip6AddressString() + "]",
		Port:      s.NginxServerPort,
		Timeout:   600,
	}
	s.Containers.NginxServer.CreateConfigFromTemplate(
		"/nginx.conf",
		"./resources/nginx/nginx_server.conf",
		nginxSettings,
	)
}

func (s *NoTopo6Suite) AddNginxVclConfig(multiThreadWorkers bool) {
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
	s.AssertNil(err, fmt.Sprint(err))
}

func (s *NoTopo6Suite) VppAddr() string {
	return s.Interfaces.Tap.Peer.Ip6AddressString()
}

func (s *NoTopo6Suite) VppIfName() string {
	return s.Interfaces.Tap.Peer.Name()
}

func (s *NoTopo6Suite) HostAddr() string {
	return s.Interfaces.Tap.Ip6AddressString()
}

func (s *NoTopo6Suite) CreateNginxHttp3Config(container *Container) {
	nginxSettings := struct {
		LogPrefix string
	}{
		LogPrefix: container.Name,
	}
	container.CreateConfigFromTemplate(
		"/nginx.conf",
		"./resources/nginx/nginx_http3.conf",
		nginxSettings,
	)
}

var _ = Describe("NoTopo6Suite", Ordered, ContinueOnFailure, Label("IPv6"), func() {
	var s NoTopo6Suite
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

	for filename, tests := range noTopo6Tests {
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

var _ = Describe("NoTopoSuiteSolo", Ordered, ContinueOnFailure, Serial, Label("IPv6"), func() {
	var s NoTopo6Suite
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

	for filename, tests := range noTopo6SoloTests {
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
