package hst

import (
	"reflect"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
)

var vclTests = map[string][]func(s *VclSuite){}
var vclMWTests = map[string][]func(s *VclSuite){}

type VclSuite struct {
	TapSuite
}

func RegisterVclTests(tests ...func(s *VclSuite)) {
	vclTests[GetTestFilename()] = tests
}

func RegisterVclMWTests(tests ...func(s *VclSuite)) {
	vclMWTests[GetTestFilename()] = tests
}

var _ = Describe("VclSuite", Ordered, ContinueOnFailure, Label("Tap", "Vcl"), func() {
	var s VclSuite
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

	for filename, tests := range vclTests {
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

var _ = DescribeMWSuite("VclSuiteMW", MWWideLabels("Tap", "Vcl", "MW"), func() {
	var s VclSuite
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

	for filename, tests := range vclMWTests {
		for _, test := range tests {
			test := test
			pc := reflect.ValueOf(test).Pointer()
			funcValue := runtime.FuncForPC(pc)
			testName := filename + "/" + strings.Split(funcValue.Name(), ".")[2]
			It(testName, Label("SOLO", "VPP Multi-Worker"), func(ctx SpecContext) {
				Log("[* TEST BEGIN]: " + testName)
				test(&s)
			}, SpecTimeout(TestTimeout))
		}
	}
})
