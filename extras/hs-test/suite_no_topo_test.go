package main

import (
	"reflect"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
)

const (
	singleTopoContainerVpp   = "vpp"
	singleTopoContainerNginx = "nginx"
	tapInterfaceName         = "htaphost"
)

var noTopoTests = []func(s *NoTopoSuite){}
var noTopoSoloTests = []func(s *NoTopoSuite){}

type NoTopoSuite struct {
	HstSuite
}

func registerNoTopoTests(tests ...func(s *NoTopoSuite)) {
	noTopoTests = append(noTopoTests, tests...)
}
func registerNoTopoSoloTests(tests ...func(s *NoTopoSuite)) {
	noTopoSoloTests = append(noTopoSoloTests, tests...)
}

func (s *NoTopoSuite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.loadNetworkTopology("tap")
	s.loadContainerTopology("single")
}

func (s *NoTopoSuite) SetupTest() {
	s.HstSuite.SetupTest()

	// Setup test conditions
	var sessionConfig Stanza
	sessionConfig.
		newStanza("session").
		append("enable").
		append("use-app-socket-api").close()

	cpus := s.AllocateCpus()
	container := s.getContainerByName(singleTopoContainerVpp)
	vpp, _ := container.newVppInstance(cpus, sessionConfig)
	s.assertNil(vpp.start())

	tapInterface := s.getInterfaceByName(tapInterfaceName)

	s.assertNil(vpp.createTap(tapInterface), "failed to create tap interface")
}

var _ = Describe("NoTopoSuite", Ordered, ContinueOnFailure, func() {
	var s NoTopoSuite
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

	for _, test := range noTopoTests {
		test := test
		pc := reflect.ValueOf(test).Pointer()
		funcValue := runtime.FuncForPC(pc)
		testName := strings.Split(funcValue.Name(), ".")[2]
		It(testName, func(ctx SpecContext) {
			s.log(testName + ": BEGIN")
			test(&s)
		}, SpecTimeout(suiteTimeout))
	}
})

var _ = Describe("NoTopoSuiteSolo", Ordered, ContinueOnFailure, Serial, func() {
	var s NoTopoSuite
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

	for _, test := range noTopoSoloTests {
		test := test
		pc := reflect.ValueOf(test).Pointer()
		funcValue := runtime.FuncForPC(pc)
		testName := strings.Split(funcValue.Name(), ".")[2]
		It(testName, Label("SOLO"), func(ctx SpecContext) {
			s.log(testName + ": BEGIN")
			test(&s)
		}, SpecTimeout(suiteTimeout))
	}
})
