package hst

import (
	"reflect"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
)

var h3Tests = map[string][]func(s *Http3Suite){}
var h3SoloTests = map[string][]func(s *Http3Suite){}
var h3MWTests = map[string][]func(s *Http3Suite){}

type Http3Suite struct {
	HstSuite
	Interfaces struct {
		Tap *NetInterface
	}
	Containers struct {
		Vpp   *Container
		Curl  *Container
		Nginx *Container
	}
	Ports struct {
		Port1 string
		Port2 string
	}
}

func RegisterH3Tests(tests ...func(s *Http3Suite)) {
	h3Tests[GetTestFilename()] = tests
}
func RegisterH3SoloTests(tests ...func(s *Http3Suite)) {
	h3SoloTests[GetTestFilename()] = tests
}
func RegisterH3MWTests(tests ...func(s *Http3Suite)) {
	h3MWTests[GetTestFilename()] = tests
}

func (s *Http3Suite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.LoadNetworkTopology("tap")
	s.LoadContainerTopology("http3")
	s.Interfaces.Tap = s.GetInterfaceByName("htapvpp")
	s.Containers.Vpp = s.GetContainerByName("vpp")
	s.Containers.Curl = s.GetContainerByName("curl")
	s.Containers.Nginx = s.GetContainerByName("nginx")
	s.Ports.Port1 = s.GeneratePort()
	s.Ports.Port2 = s.GeneratePort()
}

func (s *Http3Suite) SetupTest() {
	s.HstSuite.SetupTest()

	// Setup test conditions
	var sessionConfig Stanza
	sessionConfig.NewStanza("session").Append("enable").Append("use-app-socket-api").Close()
	var memoryConfig Stanza
	memoryConfig.NewStanza("memory").Append("main-heap-size 2G").Close()

	vpp, _ := s.Containers.Vpp.newVppInstance(s.Containers.Vpp.AllocatedCpus, memoryConfig, sessionConfig)

	AssertNil(vpp.Start())
	AssertNil(vpp.CreateTap(s.Interfaces.Tap, false, 1), "failed to create tap interface")

	if *DryRun {
		s.LogStartedContainers()
		s.Skip("Dry run mode = true")
	}
}

func (s *Http3Suite) TeardownTest() {
	defer s.HstSuite.TeardownTest()
	vpp := s.Containers.Vpp.VppInstance
	if CurrentSpecReport().Failed() {
		Log(vpp.Vppctl("show session verbose 2"))
		Log(vpp.Vppctl("show error"))
		Log(vpp.Vppctl("show http stats"))
		Log(vpp.Vppctl("show quic"))
		CollectNginxLogs(s.Containers.Nginx)
	}
}

func (s *Http3Suite) StartNginx() {
	AssertNil(s.Containers.Nginx.Create())
	nginxSettings := struct {
		LogPrefix string
		Address   string
		PortSsl   string
		Port      string
	}{
		LogPrefix: s.Containers.Nginx.Name,
		Address:   s.HostAddr(),
		PortSsl:   s.Ports.Port1,
		Port:      s.Ports.Port2,
	}
	s.Containers.Nginx.CreateConfigFromTemplate(
		"/nginx.conf",
		"./resources/nginx/nginx_masque.conf",
		nginxSettings,
	)
	AssertNil(s.Containers.Nginx.Start())
}

func (s *Http3Suite) VppAddr() string {
	return s.Interfaces.Tap.Ip4AddressString()
}

func (s *Http3Suite) HostAddr() string {
	return s.Interfaces.Tap.Host.Ip4AddressString()
}

var _ = Describe("Http3Suite", Ordered, ContinueOnFailure, Label("HTTP", "HTTP3"), func() {
	var s Http3Suite
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

	for filename, tests := range h3Tests {
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

var _ = Describe("Http3SoloSuite", Ordered, ContinueOnFailure, Serial, Label("HTTP", "HTTP3", "Solo"), func() {
	var s Http3Suite
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

	for filename, tests := range h3SoloTests {
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

var _ = Describe("Http3MWSuite", Ordered, ContinueOnFailure, Serial, Label("HTTP", "HTTP3", "MW"), func() {
	var s Http3Suite
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

	for filename, tests := range h3MWTests {
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
