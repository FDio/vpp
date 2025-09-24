package kube_test

import (
	"reflect"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
)

type LargeMtuSuite struct {
	KubeSuite
}

var largeMtuTests = map[string][]func(s *LargeMtuSuite){}

func RegisterLargeMtuTests(tests ...func(s *LargeMtuSuite)) {
	largeMtuTests[GetTestFilename()] = tests
}

func (s *LargeMtuSuite) SetupSuite() {
	s.KubeSuite.SetupSuite()
	s.SetMtuAndRestart("mtu: 0", "tcp { mtu 8960 }\n    cpu { workers 0 }")
}

var _ = Describe("LargeMtuSuite", Ordered, ContinueOnFailure, Label("Large MTU"), func() {
	var s LargeMtuSuite
	BeforeAll(func() {
		s.SkipIfBareMetalCluster()
		s.SetupSuite()
	})
	BeforeEach(func() {
		s.SetupTest()
	})
	AfterEach(func() {
		s.SkipIfBareMetalCluster()
		s.TeardownTest()
	})
	AfterAll(func() {
		s.SkipIfBareMetalCluster()
		s.TeardownSuite()
	})

	for filename, tests := range largeMtuTests {
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
