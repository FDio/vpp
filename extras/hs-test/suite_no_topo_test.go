package main

import (
	"path/filepath"
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

var noTopoTests = map[string][]func(s *NoTopoSuite){}
var noTopoSoloTests = map[string][]func(s *NoTopoSuite){}

type NoTopoSuite struct {
	HstSuite
}

func registerNoTopoTests(tests ...func(s *NoTopoSuite)) {
	_, file, _, _ := runtime.Caller(1)
	file = filepath.Base(file)
	noTopoTests[file] = tests
}
func registerNoTopoSoloTests(tests ...func(s *NoTopoSuite)) {
	_, file, _, _ := runtime.Caller(1)
	file = filepath.Base(file)
	noTopoSoloTests[file] = tests
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

	container := s.getContainerByName(singleTopoContainerVpp)
	vpp, _ := container.newVppInstance(container.allocatedCpus, sessionConfig)
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

	for filename, tests := range noTopoTests {
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

	for filename, tests := range noTopoSoloTests {
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
