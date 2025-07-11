package hst

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"time"

	. "fd.io/hs-test/infra/common"
	. "github.com/onsi/ginkgo/v2"
)

var ldpTests = map[string][]func(s *LdpSuite){}
var ldpSoloTests = map[string][]func(s *LdpSuite){}
var ldpMWTests = map[string][]func(s *LdpSuite){}

type LdpSuite struct {
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

func RegisterLdpTests(tests ...func(s *LdpSuite)) {
	ldpTests[GetTestFilename()] = tests
}
func RegisterSoloLdpTests(tests ...func(s *LdpSuite)) {
	ldpSoloTests[GetTestFilename()] = tests
}
func RegisterLdpMWTests(tests ...func(s *LdpSuite)) {
	ldpMWTests[GetTestFilename()] = tests
}

func (s *LdpSuite) SetupSuite() {
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
	s.Ports.Port1 = s.GeneratePort()
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
	serverVpp, err := s.Containers.ServerVpp.newVppInstance(s.Containers.ServerVpp.AllocatedCpus, sessionConfig)
	s.AssertNotNil(serverVpp, fmt.Sprint(err))

	// ... For client
	clientVpp, err := s.Containers.ClientVpp.newVppInstance(s.Containers.ClientVpp.AllocatedCpus, sessionConfig)
	s.AssertNotNil(clientVpp, fmt.Sprint(err))

	for _, container := range s.StartedContainers {
		container.AddEnvVar("VCL_CONFIG", container.GetContainerWorkDir()+"/vcl.conf")
		container.AddEnvVar("LD_PRELOAD", "/usr/lib/libvcl_ldpreload.so")
		container.AddEnvVar("LDP_DEBUG", "0")
		container.AddEnvVar("VCL_DEBUG", "0")
	}

	s.CreateVclConfig(s.Containers.ServerApp)
	s.CreateVclConfig(s.Containers.ClientApp)
	s.SetupServerVpp(s.Containers.ServerVpp)
	s.setupClientVpp(s.Containers.ClientVpp)

	if *DryRun {
		s.LogStartedContainers()
		s.Log("\n%s* LD_PRELOAD and VCL_CONFIG server/client paths:", Colors.grn)
		s.Log("LD_PRELOAD=/usr/lib/libvcl_ldpreload.so")
		s.Log("VCL_CONFIG=%s/vcl.conf", s.Containers.ServerVpp.GetContainerWorkDir())
		s.Log("VCL_CONFIG=%s/vcl.conf%s\n", s.Containers.ClientVpp.GetContainerWorkDir(), Colors.rst)
		s.Skip("Dry run mode = true")
	}
}

func (s *LdpSuite) TeardownTest() {
	defer s.HstSuite.TeardownTest()
	if CurrentSpecReport().Failed() {
		s.CollectIperfLogs(s.Containers.ServerApp)
		s.CollectRedisServerLogs(s.Containers.ServerApp)
		s.Log(s.Containers.ServerVpp.VppInstance.Vppctl("show error"))
		s.Log(s.Containers.ClientVpp.VppInstance.Vppctl("show error"))
	}

	for _, container := range s.StartedContainers {
		delete(container.EnvVars, "LD_PRELOAD")
		delete(container.EnvVars, "VCL_CONFIG")
	}
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

	numCpus := uint16(len(serverContainer.AllocatedCpus))
	numWorkers := uint16(max(numCpus-1, 1))
	idx, err := serverVpp.createAfPacket(s.Interfaces.Server, false, WithNumRxQueues(numWorkers), WithNumTxQueues(numCpus))
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertNotEqual(0, idx)
}

func (s *LdpSuite) setupClientVpp(clientContainer *Container) {
	clientVpp := clientContainer.VppInstance
	s.AssertNil(clientVpp.Start())

	numCpus := uint16(len(clientContainer.AllocatedCpus))
	numWorkers := uint16(max(numCpus-1, 1))
	idx, err := clientVpp.createAfPacket(s.Interfaces.Client, false, WithNumRxQueues(numWorkers), WithNumTxQueues(numCpus))
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
		s.TeardownSuite()

	})
	AfterEach(func() {
		s.TeardownTest()
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
			}, SpecTimeout(TestTimeout))
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
		s.TeardownSuite()
	})
	AfterEach(func() {
		s.TeardownTest()
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
			}, SpecTimeout(TestTimeout))
		}
	}
})

var _ = Describe("LdpMWSuite", Ordered, ContinueOnFailure, Serial, func() {
	var s LdpSuite
	BeforeAll(func() {
		s.SetupSuite()
	})
	BeforeEach(func() {
		s.SkipIfNotEnoguhCpus = true
	})
	AfterAll(func() {
		s.TeardownSuite()
	})
	AfterEach(func() {
		s.TeardownTest()
	})

	// https://onsi.github.io/ginkgo/#dynamically-generating-specs
	for filename, tests := range ldpMWTests {
		for _, test := range tests {
			test := test
			pc := reflect.ValueOf(test).Pointer()
			funcValue := runtime.FuncForPC(pc)
			testName := filename + "/" + strings.Split(funcValue.Name(), ".")[2]
			It(testName, Label("SOLO", "VPP Multi-Worker"), func(ctx SpecContext) {
				s.Log(testName + ": BEGIN")
				test(&s)
			}, SpecTimeout(TestTimeout))
		}
	}
})
