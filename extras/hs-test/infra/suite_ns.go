package hst

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
)

// These correspond to names used in yaml config
const (
	ClientInterface = "hclnvpp"
	ServerInterface = "hsrvvpp"
)

var nsTests = map[string][]func(s *NsSuite){}
var nsSoloTests = map[string][]func(s *NsSuite){}

type NsSuite struct {
	HstSuite
}

func RegisterNsTests(tests ...func(s *NsSuite)) {
	nsTests[getTestFilename()] = tests
}
func RegisterNsSoloTests(tests ...func(s *NsSuite)) {
	nsSoloTests[getTestFilename()] = tests
}

func (s *NsSuite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.ConfigureNetworkTopology("ns")
	s.LoadContainerTopology("ns")
}

func (s *NsSuite) SetupTest() {
	s.HstSuite.SetupTest()

	// Setup test conditions
	var sessionConfig Stanza
	sessionConfig.
		NewStanza("session").
		Append("enable").
		Append("use-app-socket-api").
		Append("evt_qs_memfd_seg").
		Append("event-queue-length 100000")

	if strings.Contains(CurrentSpecReport().LeafNodeText, "InterruptMode") {
		sessionConfig.Append("use-private-rx-mqs").Close()
	} else {
		sessionConfig.Close()
	}

	container := s.GetContainerByName("vpp")
	vpp, _ := container.newVppInstance(container.AllocatedCpus, sessionConfig)
	s.AssertNil(vpp.Start())

	idx, err := vpp.createAfPacket(s.GetInterfaceByName(ServerInterface))
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertNotEqual(0, idx)

	idx, err = vpp.createAfPacket(s.GetInterfaceByName(ClientInterface))
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertNotEqual(0, idx)

	container.Exec("chmod 777 -R %s", container.GetContainerWorkDir())
}

var _ = Describe("NsSuite", Ordered, ContinueOnFailure, func() {
	var s NsSuite
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

	for filename, tests := range nsTests {
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

var _ = Describe("NsSuiteSolo", Ordered, ContinueOnFailure, Serial, func() {
	var s NsSuite
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

	for filename, tests := range nsSoloTests {
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
