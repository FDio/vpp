package hst

import (
	"fmt"
	. "github.com/onsi/ginkgo/v2"
	"reflect"
	"runtime"
	"strings"
)

var cpuPinningTests = map[string][]func(s *CpuPinningSuite){}

type CpuPinningSuite struct {
	HstSuite
}

func RegisterCpuPinningTests(tests ...func(s *CpuPinningSuite)) {
	cpuPinningTests[getTestFilename()] = tests
}

func (s *CpuPinningSuite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.LoadNetworkTopology("tap")
	s.LoadContainerTopology("singleCpuPinning")
}

func (s *CpuPinningSuite) SetupTest() {
	s.HstSuite.SetupTest()

	// Setup VPP instance in each container with default CPU configuration
	container := s.GetContainerByName(SingleTopoContainerVpp)
	vpp, err := container.newVppInstance(container.AllocatedCpus)
	s.AssertNotNil(vpp, fmt.Sprint(err))

}

var _ = Describe("CpuPinningSuite", Ordered, ContinueOnFailure, func() {
	var s CpuPinningSuite
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
	for filename, tests := range cpuPinningTests {
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
