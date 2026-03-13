package hst

import (
	"reflect"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
)

var http1StaticSrvTests = map[string][]func(s *Http1StaticSrvSuite){}
var http1StaticSrvSoloTests = map[string][]func(s *Http1StaticSrvSuite){}
var http1StaticSrvMWTests = map[string][]func(s *Http1StaticSrvSuite){}

type Http1StaticSrvSuite struct {
	Http1Suite
}

func RegisterHttp1StaticSrvTests(tests ...func(s *Http1StaticSrvSuite)) {
	http1StaticSrvTests[GetTestFilename()] = tests
}
func RegisterHttp1StaticSrvSoloTests(tests ...func(s *Http1StaticSrvSuite)) {
	http1StaticSrvSoloTests[GetTestFilename()] = tests
}
func RegisterHttp1StaticSrvMWTests(tests ...func(s *Http1StaticSrvSuite)) {
	http1StaticSrvMWTests[GetTestFilename()] = tests
}

var _ = Describe("Http1StaticSrvSuite", Ordered, ContinueOnFailure, Label("HTTP", "HTTP1", "Static Server"), func() {
	var s Http1StaticSrvSuite
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

	for filename, tests := range http1StaticSrvTests {
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

var _ = Describe("Http1StaticSrvSuiteSolo", Ordered, ContinueOnFailure, Serial, Label("HTTP", "HTTP1", "Static Server"), func() {
	var s Http1StaticSrvSuite
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

	for filename, tests := range http1StaticSrvSoloTests {
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

var _ = Describe("Http1StaticSrvMWSuite", Ordered, ContinueOnFailure, Serial, Label("HTTP", "HTTP1", "Static Server", "MW"), func() {
	var s Http1StaticSrvSuite
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

	for filename, tests := range http1StaticSrvMWTests {
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
