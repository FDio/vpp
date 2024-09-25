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
	ServerLdpInterfaceName = "srv"
	ClientLdpInterfaceName = "cln"
)

var ldpTests = map[string][]func(s *LdpSuite){}
var ldpSoloTests = map[string][]func(s *LdpSuite){}

type LdpSuite struct {
	HstSuite
}

func RegisterLdpTests(tests ...func(s *LdpSuite)) {
	ldpTests[getTestFilename()] = tests
}
func RegisterSoloLdpTests(tests ...func(s *LdpSuite)) {
	ldpSoloTests[getTestFilename()] = tests
}

func (s *LdpSuite) SetupSuite() {
	time.Sleep(1 * time.Second)
	s.HstSuite.SetupSuite()
	s.ConfigureNetworkTopology("2peerVeth")
	s.LoadContainerTopology("2peerVethLdp")
}

func (s *LdpSuite) SetupTest() {
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

	serverContainer.AddEnvVar("VCL_CONFIG", serverContainer.GetContainerWorkDir()+"/vcl.conf")
	clientContainer.AddEnvVar("VCL_CONFIG", clientContainer.GetContainerWorkDir()+"/vcl.conf")

	for _, container := range s.StartedContainers {
		container.AddEnvVar("LD_PRELOAD", "/usr/lib/libvcl_ldpreload.so")
		container.AddEnvVar("LDP_DEBUG", "0")
		container.AddEnvVar("VCL_DEBUG", "0")
	}

	s.CreateVclConfig(serverContainer)
	s.CreateVclConfig(clientContainer)

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
			serverVeth.Name(), serverVeth.Ip4Address)
		s.Log("\n%s* LD_PRELOAD and VCL_CONFIG server/client paths:", Colors.grn)
		s.Log("LD_PRELOAD=/usr/lib/libvcl_ldpreload.so")
		s.Log("VCL_CONFIG=%s/vcl.conf", serverContainer.GetContainerWorkDir())
		s.Log("VCL_CONFIG=%s/vcl.conf\n", clientContainer.GetContainerWorkDir())

		s.AssertNil(serverContainer.CreateFileInWorkDir("vpp-config.conf", serverStartupConfig),
			"cannot create file")
		s.Log("* This *SERVER* config will be loaded on VPP startup:\n%s", serverStartupConfig)

		clientStartupConfig := fmt.Sprintf(
			"create host-interface name %s\n"+
				"set int state host-%s up\n"+
				"set int ip addr host-%s %s\n",
			clientVeth.Name(),
			clientVeth.Name(),
			clientVeth.Name(), clientVeth.Ip4Address)
		s.AssertNil(clientContainer.CreateFileInWorkDir("vpp-config.conf", clientStartupConfig),
			"cannot create file")
		s.Log("* This *CLIENT* config will be loaded on VPP startup:\n%s%s", clientStartupConfig, Colors.rst)

		s.Skip("Dry run mode = true")
	}
	s.SetupServerVpp(serverContainer)
	s.setupClientVpp(clientContainer)
}

func (s *LdpSuite) TearDownTest() {
	for _, container := range s.StartedContainers {
		delete(container.EnvVars, "LD_PRELOAD")
		delete(container.EnvVars, "VCL_CONFIG")
	}
	s.HstSuite.TearDownTest()

}

func (s *LdpSuite) CreateVclConfig(container *Container) {
	var vclConf Stanza
	vclFileName := container.GetHostWorkDir() + "/vcl.conf"

	appSocketApi := fmt.Sprintf("app-socket-api %s/var/run/app_ns_sockets/default",
		container.GetContainerWorkDir())
	err := vclConf.
		NewStanza("vcl").
		Append("rx-fifo-size 4000000").
		Append("tx-fifo-size 4000000").
		Append("app-scope-local").
		Append("app-scope-global").
		Append("use-mq-eventfd").
		Append(appSocketApi).Close().
		SaveToFile(vclFileName)
	s.AssertNil(err, fmt.Sprint(err))
}

func (s *LdpSuite) SetupServerVpp(serverContainer *Container) {
	serverVpp := serverContainer.VppInstance
	s.AssertNil(serverVpp.Start())

	serverVeth := s.GetInterfaceByName(ServerInterfaceName)
	idx, err := serverVpp.createAfPacket(serverVeth)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertNotEqual(0, idx)
}

func (s *LdpSuite) setupClientVpp(clientContainer *Container) {
	clientVpp := clientContainer.VppInstance
	s.AssertNil(clientVpp.Start())

	clientVeth := s.GetInterfaceByName(ClientInterfaceName)
	idx, err := clientVpp.createAfPacket(clientVeth)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertNotEqual(0, idx)
}

var _ = Describe("LdpSuite", Ordered, ContinueOnFailure, func() {
	var s LdpSuite
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
	for filename, tests := range ldpTests {
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

var _ = Describe("LdpSuiteSolo", Ordered, ContinueOnFailure, Serial, func() {
	var s LdpSuite
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
	for filename, tests := range ldpSoloTests {
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
