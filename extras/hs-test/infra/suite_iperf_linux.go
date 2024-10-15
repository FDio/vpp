package hst

import (
	"reflect"
	"runtime"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
)

type IperfSuite struct {
	HstSuite
}

const (
	ServerIperfContainerName string = "server"
	ServerIperfInterfaceName string = "hstsrv"
	ClientIperfContainerName string = "client"
	ClientIperfInterfaceName string = "hstcln"
)

var iperfTests = map[string][]func(s *IperfSuite){}
var iperfSoloTests = map[string][]func(s *IperfSuite){}

func RegisterIperfTests(tests ...func(s *IperfSuite)) {
	iperfTests[getTestFilename()] = tests
}
func RegisterIperfSoloTests(tests ...func(s *IperfSuite)) {
	iperfSoloTests[getTestFilename()] = tests
}

func (s *IperfSuite) SetupSuite() {
	time.Sleep(1 * time.Second)
	s.HstSuite.SetupSuite()
	s.ConfigureNetworkTopology("2taps")
	s.LoadContainerTopology("2containers")
}

var _ = Describe("IperfSuite", Ordered, ContinueOnFailure, func() {
	var s IperfSuite
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

	for filename, tests := range iperfTests {
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

var _ = Describe("IperfSuiteSolo", Ordered, ContinueOnFailure, Serial, func() {
	var s IperfSuite
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

	for filename, tests := range iperfSoloTests {
		for _, test := range tests {
			test := test
			pc := reflect.ValueOf(test).Pointer()
			funcValue := runtime.FuncForPC(pc)
			testName := filename + "/" + strings.Split(funcValue.Name(), ".")[2]
			It(testName, Label("SOLO"), func(ctx SpecContext) {
				s.Log(testName + ": BEGIN")
				test(&s)
			}, SpecTimeout(TestTimeout))
		}
	}
})
