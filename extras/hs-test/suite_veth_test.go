package main

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
)

// These correspond to names used in yaml config
const (
	serverInterfaceName = "srv"
	clientInterfaceName = "cln"
)

var vethTests = []func(s *VethsSuite){}
var vethSoloTests = []func(s *VethsSuite){}

type VethsSuite struct {
	HstSuite
}

func registerVethTests(tests ...func(s *VethsSuite)) {
	vethTests = append(vethTests, tests...)
}
func registerSoloVethTests(tests ...func(s *VethsSuite)) {
	vethSoloTests = append(vethSoloTests, tests...)
}

func (s *VethsSuite) SetupSuite() {
	time.Sleep(1 * time.Second)
	s.HstSuite.SetupSuite()
	s.configureNetworkTopology("2peerVeth")
	s.loadContainerTopology("2peerVeth")
}

func (s *VethsSuite) SetupTest() {
	s.HstSuite.SetupTest()

	// Setup test conditions
	var sessionConfig Stanza
	sessionConfig.
		newStanza("session").
		append("enable").
		append("use-app-socket-api").close()

	// ... For server
	serverContainer := s.getContainerByName("server-vpp")

	cpus := s.AllocateCpus()
	serverVpp, err := serverContainer.newVppInstance(cpus, sessionConfig)
	s.assertNotNil(serverVpp, fmt.Sprint(err))

	s.setupServerVpp()

	// ... For client
	clientContainer := s.getContainerByName("client-vpp")

	cpus = s.AllocateCpus()
	clientVpp, err := clientContainer.newVppInstance(cpus, sessionConfig)
	s.assertNotNil(clientVpp, fmt.Sprint(err))

	s.setupClientVpp()
}

func (s *VethsSuite) setupServerVpp() {
	serverVpp := s.getContainerByName("server-vpp").vppInstance
	s.assertNil(serverVpp.start())

	serverVeth := s.getInterfaceByName(serverInterfaceName)
	idx, err := serverVpp.createAfPacket(serverVeth)
	s.assertNil(err, fmt.Sprint(err))
	s.assertNotEqual(0, idx)
}

func (s *VethsSuite) setupClientVpp() {
	clientVpp := s.getContainerByName("client-vpp").vppInstance
	s.assertNil(clientVpp.start())

	clientVeth := s.getInterfaceByName(clientInterfaceName)
	idx, err := clientVpp.createAfPacket(clientVeth)
	s.assertNil(err, fmt.Sprint(err))
	s.assertNotEqual(0, idx)
}

var _ = Describe("VethsSuite", Ordered, ContinueOnFailure, func() {
	var s VethsSuite
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

	// https://onsi.github.io/ginkgo/#dynamically-generating-specs
	for _, test := range vethTests {
		test := test
		pc := reflect.ValueOf(test).Pointer()
		funcValue := runtime.FuncForPC(pc)
		It(strings.Split(funcValue.Name(), ".")[2], func(ctx SpecContext) {
			test(&s)
		}, SpecTimeout(time.Minute*5))
	}
})

var _ = Describe("VethsSuiteSolo", Ordered, ContinueOnFailure, Serial, func() {
	var s VethsSuite
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

	// https://onsi.github.io/ginkgo/#dynamically-generating-specs
	for _, test := range vethSoloTests {
		test := test
		pc := reflect.ValueOf(test).Pointer()
		funcValue := runtime.FuncForPC(pc)
		It(strings.Split(funcValue.Name(), ".")[2], Label("SOLO"), func(ctx SpecContext) {
			test(&s)
		}, SpecTimeout(time.Minute*5))
	}
})
