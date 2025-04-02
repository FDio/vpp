package hst

import (
	"reflect"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
)

var h2Tests = map[string][]func(s *H2Suite){}

type H2Suite struct {
	HstSuite
	Interfaces struct {
		Tap *NetInterface
	}
	Containers struct {
		Vpp  *Container
		Curl *Container
	}
}

func RegisterH2Tests(tests ...func(s *H2Suite)) {
	h2Tests[getTestFilename()] = tests
}

func (s *H2Suite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.LoadNetworkTopology("tap")
	s.LoadContainerTopology("single")
	s.Interfaces.Tap = s.GetInterfaceByName("htaphost")
	s.Containers.Vpp = s.GetContainerByName("vpp")
	s.Containers.Curl = s.GetContainerByName("curl")
}

func (s *H2Suite) SetupTest() {
	s.HstSuite.SetupTest()

	// Setup test conditions
	var sessionConfig Stanza
	sessionConfig.NewStanza("session").Append("enable").Append("use-app-socket-api")

	vpp, _ := s.Containers.Vpp.newVppInstance(s.Containers.Vpp.AllocatedCpus, sessionConfig)

	s.AssertNil(vpp.Start())
	s.AssertNil(vpp.CreateTap(s.Interfaces.Tap, 1, 1), "failed to create tap interface")

	if *DryRun {
		s.LogStartedContainers()
		s.Skip("Dry run mode = true")
	}
}

func (s *H2Suite) TearDownTest() {
	s.HstSuite.TearDownTest()
}

func (s *H2Suite) VppAddr() string {
	return s.Interfaces.Tap.Peer.Ip4AddressString()
}

var _ = PDescribe("Http2Suite", Ordered, ContinueOnFailure, func() {
	var s H2Suite
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

	for filename, tests := range h2Tests {
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
