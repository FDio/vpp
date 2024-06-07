package main

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
)

// These correspond to names used in yaml config
const (
	clientInterface = "hclnvpp"
	serverInterface = "hsrvvpp"
)

var nsTests = map[string][]func(s *NsSuite){}
var nsSoloTests = map[string][]func(s *NsSuite){}

type NsSuite struct {
	HstSuite
}

func registerNsTests(tests ...func(s *NsSuite)) {
	nsTests[getTestFilename()] = tests
}
func registerNsSoloTests(tests ...func(s *NsSuite)) {
	nsSoloTests[getTestFilename()] = tests
}

func (s *NsSuite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.configureNetworkTopology("ns")
	s.loadContainerTopology("ns")
}

func (s *NsSuite) SetupTest() {
	s.HstSuite.SetupTest()

	// Setup test conditions
	var sessionConfig Stanza
	sessionConfig.
		newStanza("session").
		append("enable").
		append("use-app-socket-api").
		append("evt_qs_memfd_seg").
		append("event-queue-length 100000").close()

	container := s.getContainerByName("vpp")
	vpp, _ := container.newVppInstance(container.allocatedCpus, sessionConfig)
	s.assertNil(vpp.start())

	idx, err := vpp.createAfPacket(s.getInterfaceByName(serverInterface))
	s.assertNil(err, fmt.Sprint(err))
	s.assertNotEqual(0, idx)

	idx, err = vpp.createAfPacket(s.getInterfaceByName(clientInterface))
	s.assertNil(err, fmt.Sprint(err))
	s.assertNotEqual(0, idx)

	container.exec("chmod 777 -R %s", container.getContainerWorkDir())
}

var _ = Describe("NsSuite", Ordered, ContinueOnFailure, func() {
	var s NsSuite
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

	for filename, tests := range nsTests {
		for _, test := range tests {
			test := test
			pc := reflect.ValueOf(test).Pointer()
			funcValue := runtime.FuncForPC(pc)
			testName := filename + "/" + strings.Split(funcValue.Name(), ".")[2]
			It(testName, func(ctx SpecContext) {
				s.log(testName + ": BEGIN")
				test(&s)
			}, SpecTimeout(suiteTimeout))
		}
	}
})

var _ = Describe("NsSuiteSolo", Ordered, ContinueOnFailure, Serial, func() {
	var s NsSuite
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

	for filename, tests := range nsSoloTests {
		for _, test := range tests {
			test := test
			pc := reflect.ValueOf(test).Pointer()
			funcValue := runtime.FuncForPC(pc)
			testName := filename + "/" + strings.Split(funcValue.Name(), ".")[2]
			It(testName, Label("SOLO"), func(ctx SpecContext) {
				s.log(testName + ": BEGIN")
				test(&s)
			}, SpecTimeout(suiteTimeout))
		}
	}
})
