package hst_kind

import (
	"reflect"
	"runtime"
	"strings"

	. "fd.io/hs-test/infra/common"
	. "github.com/onsi/ginkgo/v2"
)

type LargeMtuSuite struct {
	KindSuite
}

var largeMtuTests = map[string][]func(s *LargeMtuSuite){}

func RegisterLargeMtuTests(tests ...func(s *LargeMtuSuite)) {
	largeMtuTests[GetTestFilename()] = tests
}

func (s *LargeMtuSuite) SetupSuite() {
	s.KindSuite.SetupSuite()
	s.SetMtuAndRestart("mtu: 8960", "tcp { mtu 8960 }", "latest")
}

var _ = Describe("LargeMtuSuite", Ordered, ContinueOnFailure, Label("Perf"), func() {
	var s LargeMtuSuite
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
