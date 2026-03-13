package hst

import (
	"reflect"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
)

var httpStaticSrvTests = map[string][]func(s *HttpStaticSrvSuite){}
var httpStaticSrvSoloTests = map[string][]func(s *HttpStaticSrvSuite){}
var httpStaticSrvMWTests = map[string][]func(s *HttpStaticSrvSuite){}

type HttpStaticSrvSuite struct {
	Http1Suite
}

func RegisterHttpStaticSrvTests(tests ...func(s *HttpStaticSrvSuite)) {
	httpStaticSrvTests[GetTestFilename()] = tests
}
func RegisterHttpStaticSrvSoloTests(tests ...func(s *HttpStaticSrvSuite)) {
	httpStaticSrvSoloTests[GetTestFilename()] = tests
}
func RegisterHttpStaticSrvMWTests(tests ...func(s *HttpStaticSrvSuite)) {
	httpStaticSrvMWTests[GetTestFilename()] = tests
}

var _ = Describe("HttpStaticSrvSuite", Ordered, ContinueOnFailure, Label("HTTP", "Static Server"), func() {
	var s HttpStaticSrvSuite
	BeforeAll(func() {
		s.Http1Suite.SetupSuite()
	})
	BeforeEach(func() {
		s.Http1Suite.SetupTest()
	})
	AfterAll(func() {
		s.Http1Suite.TeardownSuite()
	})
	AfterEach(func() {
		s.Http1Suite.TeardownTest()
	})

	for filename, tests := range httpStaticSrvTests {
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

var _ = Describe("HttpStaticSrvSuiteSolo", Ordered, ContinueOnFailure, Serial, Label("HTTP", "Static Server"), func() {
	var s HttpStaticSrvSuite
	BeforeAll(func() {
		s.Http1Suite.SetupSuite()
	})
	BeforeEach(func() {
		s.Http1Suite.SetupTest()
	})
	AfterAll(func() {
		s.Http1Suite.TeardownSuite()
	})
	AfterEach(func() {
		s.Http1Suite.TeardownTest()
	})

	for filename, tests := range httpStaticSrvSoloTests {
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

var _ = Describe("HttpStaticSrvMWSuite", Ordered, ContinueOnFailure, Serial, Label("HTTP", "Static Server", "MW"), func() {
	var s HttpStaticSrvSuite
	BeforeAll(func() {
		s.Http1Suite.SetupSuite()
	})
	BeforeEach(func() {
		s.Http1Suite.SkipIfNotEnoguhCpus = true
	})
	AfterAll(func() {
		s.Http1Suite.TeardownSuite()
	})
	AfterEach(func() {
		s.Http1Suite.TeardownTest()
	})

	for filename, tests := range httpStaticSrvMWTests {
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
