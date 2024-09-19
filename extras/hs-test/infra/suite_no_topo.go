package hst

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
)

const (
	SingleTopoContainerVpp   = "vpp"
	SingleTopoContainerNginx = "nginx"
	TapInterfaceName         = "htaphost"
)

var noTopoTests = map[string][]func(s *NoTopoSuite){}
var noTopoSoloTests = map[string][]func(s *NoTopoSuite){}

type NoTopoSuite struct {
	HstSuite
	multiThreaded bool
}

func RegisterNoTopoTests(tests ...func(s *NoTopoSuite)) {
	noTopoTests[getTestFilename()] = tests
}
func RegisterNoTopoSoloTests(tests ...func(s *NoTopoSuite)) {
	noTopoSoloTests[getTestFilename()] = tests
}

func (s *NoTopoSuite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.LoadNetworkTopology("tap")
	s.LoadContainerTopology("single")
}

func (s *NoTopoSuite) SetupTest() {
	if strings.Contains(CurrentSpecReport().LeafNodeText, "MultiThread") {
		s.Log("**********************MULTI-THREAD TEST (2 CPUS)**********************")
		s.multiThreaded = true
		s.CpuCount = 2
		s.SkipIfNotEnoughAvailableCpus()
	} else {
		s.multiThreaded = false
	}
	s.HstSuite.SetupTest()

	// Setup test conditions
	var sessionConfig Stanza
	sessionConfig.
		NewStanza("session").
		Append("enable").
		Append("use-app-socket-api")

	if strings.Contains(CurrentSpecReport().LeafNodeText, "InterruptMode") {
		sessionConfig.Append("use-private-rx-mqs").Close()
		s.Log("**********************INTERRUPT MODE**********************")
	} else {
		sessionConfig.Close()
	}

	container := s.GetContainerByName(SingleTopoContainerVpp)
	vpp, _ := container.newVppInstance(container.AllocatedCpus, sessionConfig)
	s.AssertNil(vpp.Start())

	tapInterface := s.GetInterfaceByName(TapInterfaceName)

	s.AssertNil(vpp.createTap(tapInterface), "failed to create tap interface")
}

func (s *NoTopoSuite) TearDownTest() {
	s.CpuCount = *NConfiguredCpus
	s.HstSuite.TearDownTest()
}

func (s *NoTopoSuite) AddNginxVclConfig() {
	nginxCont := s.GetContainerByName(SingleTopoContainerNginx)

	vclFileName := nginxCont.GetHostWorkDir() + "/vcl.conf"

	appSocketApi := fmt.Sprintf("app-socket-api %s/var/run/app_ns_sockets/default",
		nginxCont.GetContainerWorkDir())

	var vclConf Stanza
	vclConf.
		NewStanza("vcl").
		Append("heapsize 64M").
		Append("rx-fifo-size 4000000").
		Append("tx-fifo-size 4000000").
		Append("segment-size 4000000000").
		Append("add-segment-size 4000000000").
		Append("event-queue-size 100000").
		Append("use-mq-eventfd").
		Append(appSocketApi)
	if s.multiThreaded {
		vclConf.Append("multi-thread-workers")
	}

	err := vclConf.Close().SaveToFile(vclFileName)
	s.AssertNil(err, fmt.Sprint(err))
}

func (s *NoTopoSuite) VppAddr() string {
	return s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
}

func (s *NoTopoSuite) VppIfName() string {
	return s.GetInterfaceByName(TapInterfaceName).Peer.Name()
}

func (s *NoTopoSuite) HostAddr() string {
	return s.GetInterfaceByName(TapInterfaceName).Ip4AddressString()
}

var _ = Describe("NoTopoSuite", Ordered, ContinueOnFailure, func() {
	var s NoTopoSuite
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

	for filename, tests := range noTopoTests {
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

var _ = Describe("NoTopoSuiteSolo", Ordered, ContinueOnFailure, Serial, func() {
	var s NoTopoSuite
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

	for filename, tests := range noTopoSoloTests {
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
