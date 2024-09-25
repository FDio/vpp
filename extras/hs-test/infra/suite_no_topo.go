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

	if *DryRun {
		vpp.CreateVppConfig()
		tapInterface := s.GetInterfaceByName(TapInterfaceName)
		for name := range s.Containers {
			s.Log("\033[36mdocker start %s && docker exec -it %s bash", name, name)
		}
		s.Log("vpp -c /tmp/vpp/etc/vpp/startup.conf\n")
		s.Log("vppctl -s /tmp/vpp/var/run/vpp/cli.sock\n")
		startupConfig := fmt.Sprintf(
			"create tap id 0 host-if-name %s\n"+
				"set int ip addr tap0 %s\n"+
				"set int state tap0 up\n",
			tapInterface.name,
			tapInterface.Peer.Ip4Address,
		)

		container.CreateFileInWorkDir("vpp-config.conf", startupConfig)
		s.Log("This config will be loaded on VPP startup:\n%s", startupConfig)
		s.Log("sudo ip addr add %s dev %s\033[0m", tapInterface.Ip4Address, tapInterface.name)
		s.Skip("Dry run mode = true")
	}

	s.AssertNil(vpp.Start())
	tapInterface := s.GetInterfaceByName(TapInterfaceName)
	s.AssertNil(vpp.createTap(tapInterface), "failed to create tap interface")
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
