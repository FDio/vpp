package hst

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
)

var ldpTests = map[string][]func(s *LdpSuite){}
var ldpSoloTests = map[string][]func(s *LdpSuite){}

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
	s.Interfaces.Client = s.GetInterfaceByName("cln")
	s.Interfaces.Server = s.GetInterfaceByName("srv")
	s.Containers.ServerVpp = s.GetContainerByName("server-vpp")
	s.Containers.ClientVpp = s.GetContainerByName("client-vpp")
	s.Containers.ServerApp = s.GetContainerByName("server-app")
	s.Containers.ClientApp = s.GetContainerByName("client-app")
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

	s.Containers.ServerVpp.AddEnvVar("VCL_CONFIG", s.Containers.ServerVpp.GetContainerWorkDir()+"/vcl.conf")
	s.Containers.ClientVpp.AddEnvVar("VCL_CONFIG", s.Containers.ClientVpp.GetContainerWorkDir()+"/vcl.conf")

	for _, container := range s.StartedContainers {
		container.AddEnvVar("LD_PRELOAD", "/usr/lib/libvcl_ldpreload.so")
		container.AddEnvVar("LDP_DEBUG", "0")
		container.AddEnvVar("VCL_DEBUG", "0")
	}

	s.CreateVclConfig(s.Containers.ServerVpp)
	s.CreateVclConfig(s.Containers.ClientVpp)
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

func (s *LdpSuite) TearDownTest() {
	if CurrentSpecReport().Failed() {
		s.CollectIperfLogs(s.Containers.ServerVpp)
		s.CollectRedisServerLogs(s.Containers.ServerVpp)
	}

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

	idx, err := serverVpp.createAfPacket(s.Interfaces.Server, true)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertNotEqual(0, idx)
}

func (s *LdpSuite) setupClientVpp(clientContainer *Container) {
	clientVpp := clientContainer.VppInstance
	s.AssertNil(clientVpp.Start())

	idx, err := clientVpp.createAfPacket(s.Interfaces.Client, true)
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
			}, SpecTimeout(TestTimeout))
		}
	}
})
