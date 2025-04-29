package hst

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
)

var vethTests = map[string][]func(s *VethsSuite){}
var vethSoloTests = map[string][]func(s *VethsSuite){}

type VethsSuite struct {
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
}

func RegisterVethTests(tests ...func(s *VethsSuite)) {
	vethTests[getTestFilename()] = tests
}
func RegisterSoloVethTests(tests ...func(s *VethsSuite)) {
	vethSoloTests[getTestFilename()] = tests
}

func (s *VethsSuite) SetupSuite() {
	time.Sleep(1 * time.Second)
	s.HstSuite.SetupSuite()
	s.ConfigureNetworkTopology("2peerVeth")
	s.LoadContainerTopology("2peerVeth")
	s.Interfaces.Client = s.GetInterfaceByName("cln")
	s.Interfaces.Server = s.GetInterfaceByName("srv")
	s.Containers.ServerVpp = s.GetContainerByName("server-vpp")
	s.Containers.ClientVpp = s.GetContainerByName("client-vpp")
	s.Containers.ServerApp = s.GetContainerByName("server-app")
	s.Containers.ClientApp = s.GetContainerByName("client-app")
}

func (s *VethsSuite) SetupTest() {
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
	s.setupClientVpp()
	if *DryRun {
		s.LogStartedContainers()
		s.Skip("Dry run mode = true")
	}
}

func (s *VethsSuite) SetupServerVpp() {
	serverVpp := s.Containers.ServerVpp.VppInstance
	s.AssertNil(serverVpp.Start())

	idx, err := serverVpp.createAfPacket(s.Interfaces.Server, false)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertNotEqual(0, idx)
}

func (s *VethsSuite) setupClientVpp() {
	clientVpp := s.GetContainerByName("client-vpp").VppInstance
	s.AssertNil(clientVpp.Start())

	idx, err := clientVpp.createAfPacket(s.Interfaces.Client, false)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertNotEqual(0, idx)
}

var _ = Describe("VethsSuite", Ordered, ContinueOnFailure, func() {
	var s VethsSuite
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

	// https://onsi.github.io/ginkgo/#dynamically-generating-specs
	for filename, tests := range vethTests {
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

var _ = Describe("VethsSuiteSolo", Ordered, ContinueOnFailure, Serial, func() {
	var s VethsSuite
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

	// https://onsi.github.io/ginkgo/#dynamically-generating-specs
	for filename, tests := range vethSoloTests {
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
