package hst

import (
	"reflect"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
)

var http1Tests = map[string][]func(s *Http1Suite){}
var http1SoloTests = map[string][]func(s *Http1Suite){}
var http1MWTests = map[string][]func(s *Http1Suite){}

type Http1Suite struct {
	HstSuite
	Interfaces struct {
		Tap *NetInterface
	}
	Containers struct {
		Vpp         *Container
		NginxServer *Container
		Wrk         *Container
	}
	Ports struct {
		NginxServer    string
		NginxServerSsl string
		Http           string
	}
}

func RegisterHttp1Tests(tests ...func(s *Http1Suite)) {
	http1Tests[GetTestFilename()] = tests
}
func RegisterHttp1SoloTests(tests ...func(s *Http1Suite)) {
	http1SoloTests[GetTestFilename()] = tests
}
func RegisterHttp1MWTests(tests ...func(s *Http1Suite)) {
	http1MWTests[GetTestFilename()] = tests
}

func (s *Http1Suite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.LoadNetworkTopology("tap")
	s.LoadContainerTopology("single")
	s.Interfaces.Tap = s.GetInterfaceByName("htapvpp")
	s.Containers.Vpp = s.GetContainerByName("vpp")
	s.Containers.NginxServer = s.GetTransientContainerByName("nginx-server")
	s.Containers.Wrk = s.GetContainerByName("wrk")
	s.Ports.Http = s.GeneratePort()
	s.Ports.NginxServer = s.GeneratePort()
	s.Ports.NginxServerSsl = s.GeneratePort()
}

func (s *Http1Suite) SetupTest() {
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

func (s *Http1Suite) TeardownTest() {
	defer s.HstSuite.TeardownTest()
	vpp := s.Containers.Vpp.VppInstance
	if CurrentSpecReport().Failed() {
		Log(vpp.Vppctl("show session verbose 2"))
		Log(vpp.Vppctl("show error"))
		Log(vpp.Vppctl("show http stats"))
	}
}

// Creates container and config.
func (s *Http1Suite) CreateNginxServer() {
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
		Address:   s.Interfaces.Tap.Host.Ip4AddressString(),
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

func (s *Http1Suite) VppAddr() string {
	return s.Interfaces.Tap.Ip4AddressString()
}

func (s *Http1Suite) VppIfName() string {
	return s.Interfaces.Tap.Name()
}

func (s *Http1Suite) HostAddr() string {
	return s.Interfaces.Tap.Host.Ip4AddressString()
}

var _ = Describe("Http1Suite", Ordered, ContinueOnFailure, Label("HTTP", "HTTP1"), func() {
	var s Http1Suite
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

	for filename, tests := range http1Tests {
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

var _ = Describe("Http1SuiteSolo", Ordered, ContinueOnFailure, Serial, Label("HTTP", "HTTP1"), func() {
	var s Http1Suite
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

	for filename, tests := range http1SoloTests {
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

var _ = Describe("Http1MWSuite", Ordered, ContinueOnFailure, Serial, Label("HTTP", "HTTP1", "MW"), func() {
	var s Http1Suite
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

	for filename, tests := range http1MWTests {
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
