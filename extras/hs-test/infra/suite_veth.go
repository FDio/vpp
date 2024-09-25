package hst

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
)

// These correspond to names used in yaml config
const (
	ServerInterfaceName = "srv"
	ClientInterfaceName = "cln"
)

var vethTests = map[string][]func(s *VethsSuite){}
var vethSoloTests = map[string][]func(s *VethsSuite){}

type VethsSuite struct {
	HstSuite
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
	serverContainer := s.GetContainerByName("server-vpp")

	serverVpp, err := serverContainer.newVppInstance(serverContainer.AllocatedCpus, sessionConfig)
	s.AssertNotNil(serverVpp, fmt.Sprint(err))

	// ... For client
	clientContainer := s.GetContainerByName("client-vpp")

	clientVpp, err := clientContainer.newVppInstance(clientContainer.AllocatedCpus, sessionConfig)
	s.AssertNotNil(clientVpp, fmt.Sprint(err))

	if *DryRun {
		s.LogStartedContainers()
		serverVpp.CreateVppConfig()
		clientVpp.CreateVppConfig()
		serverVeth := s.GetInterfaceByName(ServerInterfaceName)
		clientVeth := s.GetInterfaceByName(ClientInterfaceName)
		serverVeth.Ip4Address, _ = serverVeth.Ip4AddrAllocator.NewIp4InterfaceAddress(serverVeth.Peer.NetworkNumber)
		clientVeth.Ip4Address, _ = clientVeth.Ip4AddrAllocator.NewIp4InterfaceAddress(clientVeth.Peer.NetworkNumber)

		serverStartupConfig := fmt.Sprintf(
			"create host-interface name %s\n"+
				"set int state host-%s up\n"+
				"set int ip addr host-%s %s\n",
			serverVeth.Name(),
			serverVeth.Name(),
			serverVeth.Name(), serverVeth.Ip4Address,
		)
		s.AssertNil(serverContainer.CreateFileInWorkDir("vpp-config.conf", serverStartupConfig),
			"cannot create file")
		s.Log("\n%s* This *SERVER* config will be loaded on VPP startup:\n%s", Colors.grn, serverStartupConfig)

		clientStartupConfig := fmt.Sprintf(
			"create host-interface name %s\n"+
				"set int state host-%s up\n"+
				"set int ip addr host-%s %s\n",
			clientVeth.Name(),
			clientVeth.Name(),
			clientVeth.Name(), clientVeth.Ip4Address,
		)
		s.AssertNil(clientContainer.CreateFileInWorkDir("vpp-config.conf", clientStartupConfig),
			"cannot create file")
		s.Log("* This *CLIENT* config will be loaded on VPP startup:\n%s%s", clientStartupConfig, Colors.rst)

		s.Skip("Dry run mode = true")
	}
	s.SetupServerVpp()
	s.setupClientVpp()

}

func (s *VethsSuite) SetupServerVpp() {
	serverVpp := s.GetContainerByName("server-vpp").VppInstance
	s.AssertNil(serverVpp.Start())

	serverVeth := s.GetInterfaceByName(ServerInterfaceName)
	idx, err := serverVpp.createAfPacket(serverVeth)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertNotEqual(0, idx)
}

func (s *VethsSuite) setupClientVpp() {
	clientVpp := s.GetContainerByName("client-vpp").VppInstance
	s.AssertNil(clientVpp.Start())

	clientVeth := s.GetInterfaceByName(ClientInterfaceName)
	idx, err := clientVpp.createAfPacket(clientVeth)
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
			}, SpecTimeout(SuiteTimeout))
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
			}, SpecTimeout(SuiteTimeout))
		}
	}
})
