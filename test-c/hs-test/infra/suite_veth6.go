package hst

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
)

var veth6Tests = map[string][]func(s *Veths6Suite){}
var veth6SoloTests = map[string][]func(s *Veths6Suite){}

type Veths6Suite struct {
	HstSuite
	Interfaces struct {
		Server *NetInterface
		Client *NetInterface
	}
	Containers struct {
		ServerVpp *Container
		ClientVpp *Container
		ServerApp *Container
		ClientApp *Container
	}
	Ports struct {
		Port1 string
	}
}

func RegisterVeth6Tests(tests ...func(s *Veths6Suite)) {
	veth6Tests[GetTestFilename()] = tests
}
func RegisterSoloVeth6Tests(tests ...func(s *Veths6Suite)) {
	veth6SoloTests[GetTestFilename()] = tests
}

func (s *Veths6Suite) SetupSuite() {
	time.Sleep(1 * time.Second)
	s.HstSuite.SetupSuite()
	s.ConfigureNetworkTopology("2peerVeth6")
	s.LoadContainerTopology("2peerVeth")
	s.Interfaces.Client = s.GetInterfaceByName("cln")
	s.Interfaces.Server = s.GetInterfaceByName("srv")
	s.Containers.ServerVpp = s.GetContainerByName("server-vpp")
	s.Containers.ClientVpp = s.GetContainerByName("client-vpp")
	s.Containers.ServerApp = s.GetContainerByName("server-app")
	s.Containers.ClientApp = s.GetContainerByName("client-app")
	s.Ports.Port1 = s.GeneratePort()
}

func (s *Veths6Suite) SetupTest() {
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

	// ... For server
	serverVpp, err := s.Containers.ServerVpp.newVppInstance(s.Containers.ServerVpp.AllocatedCpus, sessionConfig)
	s.AssertNotNil(serverVpp, fmt.Sprint(err))

	// ... For client
	clientVpp, err := s.Containers.ClientVpp.newVppInstance(s.Containers.ClientVpp.AllocatedCpus, sessionConfig)
	s.AssertNotNil(clientVpp, fmt.Sprint(err))

	s.SetupServerVpp()
	s.SetupClientVpp()
	if *DryRun {
		s.LogStartedContainers()
		s.Skip("Dry run mode = true")
	}
}

func (s *Veths6Suite) SetupServerVpp() {
	serverVpp := s.Containers.ServerVpp.VppInstance
	s.AssertNil(serverVpp.Start())

	numCpus := uint16(len(s.Containers.ServerVpp.AllocatedCpus))
	numWorkers := uint16(max(numCpus-1, 1))
	idx, err := serverVpp.createAfPacket(s.Interfaces.Server, true, WithNumRxQueues(numWorkers), WithNumTxQueues(numCpus))
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertNotEqual(0, idx)
}

func (s *Veths6Suite) SetupClientVpp() {
	clientVpp := s.GetContainerByName("client-vpp").VppInstance
	s.AssertNil(clientVpp.Start())

	numCpus := uint16(len(s.Containers.ClientVpp.AllocatedCpus))
	numWorkers := uint16(max(numCpus-1, 1))
	idx, err := clientVpp.createAfPacket(s.Interfaces.Client, true, WithNumRxQueues(numWorkers), WithNumTxQueues(numCpus))
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertNotEqual(0, idx)
}

var _ = Describe("Veths6Suite", Ordered, ContinueOnFailure, Label("Veth", "IPv6"), func() {
	var s Veths6Suite
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
	for filename, tests := range veth6Tests {
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

var _ = Describe("Veths6SuiteSolo", Ordered, ContinueOnFailure, Serial, Label("Veth", "IPv6"), func() {
	var s Veths6Suite
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
	for filename, tests := range veth6SoloTests {
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
