package hst

import (
	"reflect"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
)

var echoTests = map[string][]func(s *EchoSuite){}
var echoSoloTests = map[string][]func(s *EchoSuite){}
var echoMWTests = map[string][]func(s *EchoSuite){}

type EchoSuite struct {
	VethsSuite
}

func RegisterEchoTests(tests ...func(s *EchoSuite)) {
	echoTests[GetTestFilename()] = tests
}
func RegisterSoloEchoTests(tests ...func(s *EchoSuite)) {
	echoSoloTests[GetTestFilename()] = tests
}
func RegisterEchoMWTests(tests ...func(s *EchoSuite)) {
	echoMWTests[GetTestFilename()] = tests
}

var _ = Describe("EchoSuite", Ordered, ContinueOnFailure, Label("Veth", "Echo"), func() {
	var s EchoSuite
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
	for filename, tests := range echoTests {
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

var _ = Describe("EchoSuiteSolo", Ordered, ContinueOnFailure, Serial, Label("Veth", "Echo"), func() {
	var s EchoSuite
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
	for filename, tests := range echoSoloTests {
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

var _ = DescribeMWSuite("EchoSuiteMW", []string{"Veth", "Echo", "MW"}, func() {
	var s EchoSuite
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
	for filename, tests := range echoMWTests {
		for _, test := range tests {
			test := test
			pc := reflect.ValueOf(test).Pointer()
			funcValue := runtime.FuncForPC(pc)
			funcName := strings.Split(funcValue.Name(), ".")[2]
			testName := filename + "/" + funcName
			labels := []string{"SOLO", "VPP Multi-Worker"}
			switch funcName {
			case "EchoBuiltinHttp1CpsMWTest",
				"EchoBuiltinHttp2CpsMWTest",
				"EchoBuiltinHttp3CpsMWTest",
				"EchoBuiltinHttp2ConnectUdpBackpressureMWTest":
				labels = MWWideLabels(labels...)
			}
			It(testName, Label(labels...), func(ctx SpecContext) {
				Log("[* TEST BEGIN]: " + testName)
				test(&s)
			}, SpecTimeout(TestTimeout))
		}
	}
})
