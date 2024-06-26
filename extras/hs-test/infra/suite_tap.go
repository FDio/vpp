package hst

import (
	"reflect"
	"runtime"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
)

type TapSuite struct {
	HstSuite
}

var tapTests = map[string][]func(s *TapSuite){}
var tapSoloTests = map[string][]func(s *TapSuite){}

func RegisterTapTests(tests ...func(s *TapSuite)) {
	tapTests[getTestFilename()] = tests
}
func RegisterTapSoloTests(tests ...func(s *TapSuite)) {
	tapSoloTests[getTestFilename()] = tests
}

func (s *TapSuite) SetupSuite() {
	time.Sleep(1 * time.Second)
	s.HstSuite.SetupSuite()
	s.ConfigureNetworkTopology("tap")
	s.LoadContainerTopology("single")
}

func (s *TapSuite) SetupTest() {
	s.HstSuite.SetupTest()
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

	vppContainer := s.GetContainerByName("vpp")
	vpp, _ := vppContainer.newVppInstance(vppContainer.AllocatedCpus, sessionConfig)
	s.AssertNil(vpp.Start())
}

var _ = Describe("TapSuite", Ordered, ContinueOnFailure, func() {
	var s TapSuite
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

	for filename, tests := range tapTests {
		for _, test := range tests {
			test := test
			pc := reflect.ValueOf(test).Pointer()
			funcValue := runtime.FuncForPC(pc)
			testName := filename + "/" + strings.Split(funcValue.Name(), ".")[2]
			It(testName, func(ctx SpecContext) {
				s.Log(testName + ": BEGIN")
				test(&s)
			}, SpecTimeout(SuiteTimeout))
		}
	}
})

var _ = Describe("TapSuiteSolo", Ordered, ContinueOnFailure, Serial, func() {
	var s TapSuite
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

	for filename, tests := range tapSoloTests {
		for _, test := range tests {
			test := test
			pc := reflect.ValueOf(test).Pointer()
			funcValue := runtime.FuncForPC(pc)
			testName := filename + "/" + strings.Split(funcValue.Name(), ".")[2]
			It(testName, Label("SOLO"), func(ctx SpecContext) {
				s.Log(testName + ": BEGIN")
				test(&s)
			}, SpecTimeout(SuiteTimeout))
		}
	}
})
