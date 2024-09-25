package hst

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
)

var cpuPinningTests = map[string][]func(s *CpuPinningSuite){}
var cpuPinningSoloTests = map[string][]func(s *CpuPinningSuite){}

type CpuPinningSuite struct {
	HstSuite
	previousMaxContainerCount int
}

func RegisterCpuPinningTests(tests ...func(s *CpuPinningSuite)) {
	cpuPinningTests[getTestFilename()] = tests
}

func RegisterCpuPinningSoloTests(tests ...func(s *CpuPinningSuite)) {
	cpuPinningSoloTests[getTestFilename()] = tests
}

func (s *CpuPinningSuite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.LoadNetworkTopology("tap")
	s.LoadContainerTopology("singleCpuPinning")
}

func (s *CpuPinningSuite) SetupTest() {
	// Skip if we cannot allocate 3 CPUs for test container
	s.previousMaxContainerCount = s.CpuAllocator.maxContainerCount
	s.CpuCount = 3
	s.CpuAllocator.maxContainerCount = 1
	s.SkipIfNotEnoughAvailableCpus()

	s.HstSuite.SetupTest()
	container := s.GetContainerByName(SingleTopoContainerVpp)
	vpp, err := container.newVppInstance(container.AllocatedCpus)
	s.AssertNotNil(vpp, fmt.Sprint(err))

	if *DryRun {
		s.LogStartedContainers()
		s.Skip("Dry run mode = true")
	}
}

func (s *CpuPinningSuite) TearDownTest() {
	// reset vars
	s.CpuCount = *NConfiguredCpus
	s.CpuAllocator.maxContainerCount = s.previousMaxContainerCount
	s.HstSuite.TearDownTest()

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

var _ = Describe("CpuPinningSuiteSolo", Ordered, ContinueOnFailure, Serial, func() {
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

	for filename, tests := range cpuPinningSoloTests {
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
