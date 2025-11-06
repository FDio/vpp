package kube_test

import (
	"reflect"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
)

type FelixSuite struct {
	KubeSuite
}

var felixTests = map[string][]func(s *FelixSuite){}

func RegisterFelixTests(tests ...func(s *FelixSuite)) {
	felixTests[GetTestFilename()] = tests
}

func (s *FelixSuite) SetupSuite() {
	s.KubeSuite.SetupSuite()
}

var _ = Describe("FelixSuite", Ordered, ContinueOnFailure, Label("Felix"), func() {
	var s FelixSuite
	BeforeAll(func() {
		s.SetupSuite()
	})
	BeforeEach(func() {
		s.SetupTest()
	})
	AfterEach(func() {
		s.TeardownTest()
	})
	AfterAll(func() {
		s.TeardownSuite()
	})

	for filename, tests := range felixTests {
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
