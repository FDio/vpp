package hst

import (
	"reflect"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
)

var vperfTests = map[string][]func(s *VperfSuite){}
var vperfSoloTests = map[string][]func(s *VperfSuite){}
var vperfMWTests = map[string][]func(s *VperfSuite){}

type VperfSuite struct {
	TapSuite
}

func RegisterVperfTests(tests ...func(s *VperfSuite)) {
	vperfTests[GetTestFilename()] = tests
}
func RegisterSoloVperfTests(tests ...func(s *VperfSuite)) {
	vperfSoloTests[GetTestFilename()] = tests
}
func RegisterVperfMWTests(tests ...func(s *VperfSuite)) {
	vperfMWTests[GetTestFilename()] = tests
}

var _ = Describe("VperfSuite", Ordered, ContinueOnFailure, Label("Tap", "Vperf"), func() {
	var s VperfSuite
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
	for filename, tests := range vperfTests {
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

var _ = Describe("VperfSuiteSolo", Ordered, ContinueOnFailure, Serial, Label("Tap", "Vperf"), func() {
	var s VperfSuite
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
	for filename, tests := range vperfSoloTests {
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

var _ = DescribeMWSuite("VperfSuiteMW", []string{"Tap", "Vperf", "MW"}, func() {
	var s VperfSuite
	BeforeAll(func() {
		s.SetupSuite()
	})
	BeforeEach(func() {
		s.SkipIfNotEnoughCpus = true
	})
	AfterAll(func() {
		s.TeardownSuite()
	})
	AfterEach(func() {
		s.TeardownTest()
	})

	// https://onsi.github.io/ginkgo/#dynamically-generating-specs
	for filename, tests := range vperfMWTests {
		for _, test := range tests {
			test := test
			pc := reflect.ValueOf(test).Pointer()
			funcValue := runtime.FuncForPC(pc)
			funcName := strings.Split(funcValue.Name(), ".")[2]
			testName := filename + "/" + funcName
			labels := []string{"SOLO", "VPP Multi-Worker"}
			switch funcName {
			case "VperfBuiltinHttp1CpsMWTest",
				"VperfBuiltinHttp2CpsMWTest",
				"VperfBuiltinHttp3CpsMWTest",
				"VperfBuiltinHttp2ConnectUdpBackpressureMWTest":
				labels = MWWideLabels(labels...)
			}
			It(testName, Label(labels...), func(ctx SpecContext) {
				Log("[* TEST BEGIN]: " + testName)
				test(&s)
			}, SpecTimeout(TestTimeout))
		}
	}
})
