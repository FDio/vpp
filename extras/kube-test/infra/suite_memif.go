package kube_test

import (
	"reflect"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
)

type MemifSuite struct {
	KubeSuite
}

var memifTests = map[string][]func(s *MemifSuite){}

func RegisterMemifTests(tests ...func(s *MemifSuite)) {
	memifTests[GetTestFilename()] = tests
}

func (s *MemifSuite) SetupSuite() {
	s.KubeSuite.SetupSuite()
	s.ReconfigureAndRestart("mtu: 0", "tcp { mtu 1460 }\n    cpu { workers 0 }", true)
}

var _ = Describe("MemifSuite", Ordered, ContinueOnFailure, Label("Memif"), func() {
	var s MemifSuite
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

	for filename, tests := range memifTests {
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
