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
	Interfaces struct {
		Tap *NetInterface
	}
	Containers struct {
		Vpp *Container
	}
}

func RegisterCpuPinningTests(tests ...func(s *CpuPinningSuite)) {
	cpuPinningTests[GetTestFilename()] = tests
}

func RegisterCpuPinningSoloTests(tests ...func(s *CpuPinningSuite)) {
	cpuPinningSoloTests[GetTestFilename()] = tests
}

func (s *CpuPinningSuite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.LoadNetworkTopology("tap")
	s.LoadContainerTopology("singleCpuPinning")
	s.Interfaces.Tap = s.GetInterfaceByName("htapvpp")
	s.Containers.Vpp = s.GetContainerByName("vpp")
}

func (s *CpuPinningSuite) SetupTest() {
	// Skip if we cannot allocate 3 CPUs for test container
	s.CpusPerVppContainer = 3
	s.SkipIfNotEnoguhCpus = true

	s.HstSuite.SetupTest()
	vpp, err := s.Containers.Vpp.newVppInstance(s.Containers.Vpp.AllocatedCpus)
	AssertNotNil(vpp, fmt.Sprint(err))

	if *DryRun {
		s.LogStartedContainers()
		s.Skip("Dry run mode = true")
	}
}

func (s *CpuPinningSuite) TeardownTest() {
	defer s.HstSuite.TeardownTest()
	// reset vars
	s.CpusPerContainer = *NConfiguredCpus
}

var _ = Describe("CpuPinningSuite", Ordered, ContinueOnFailure, Label("CpuPinning"), func() {
	var s CpuPinningSuite
	BeforeAll(func() {
		s.SetupSuite()
	})
	BeforeEach(func() {
		s.SetupTest()
	})
	AfterAll(func() {
		s.TeardownSuite()

	})
	AfterEach(func() {
		s.TeardownTest()
	})

	// https://onsi.github.io/ginkgo/#dynamically-generating-specs
	for filename, tests := range cpuPinningTests {
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

var _ = Describe("CpuPinningSuiteSolo", Ordered, ContinueOnFailure, Serial, Label("CpuPinning"), func() {
	var s CpuPinningSuite
	BeforeAll(func() {
		s.SetupSuite()
	})
	BeforeEach(func() {
		s.SetupTest()
	})
	AfterAll(func() {
		s.TeardownSuite()
	})
	AfterEach(func() {
		s.TeardownTest()
	})

	for filename, tests := range cpuPinningSoloTests {
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
