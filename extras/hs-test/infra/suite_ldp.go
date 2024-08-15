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

	s.SetupServerVpp()

	// ... For client
	clientContainer := s.GetContainerByName("client-vpp")

	clientVpp, err := clientContainer.newVppInstance(clientContainer.AllocatedCpus, sessionConfig)
	s.AssertNotNil(clientVpp, fmt.Sprint(err))

	s.setupClientVpp()

	serverContainer.AddEnvVar("VCL_CONFIG", serverContainer.GetContainerWorkDir()+"/vcl_srv.conf")
	clientContainer.AddEnvVar("VCL_CONFIG", clientContainer.GetContainerWorkDir()+"/vcl_cln.conf")

	for _, container := range s.StartedContainers {
		container.AddEnvVar("LD_PRELOAD", "/usr/lib/libvcl_ldpreload.so")
		container.AddEnvVar("LDP_DEBUG", "0")
		container.AddEnvVar("VCL_DEBUG", "0")
	}
}

func (s *LdpSuite) TearDownTest() {
	for _, container := range s.StartedContainers {
		delete(container.EnvVars, "LD_PRELOAD")
		delete(container.EnvVars, "VCL_CONFIG")
	}
	s.HstSuite.TearDownTest()

}

func (s *LdpSuite) SetupServerVpp() {
	var srvVclConf Stanza
	serverContainer := s.GetContainerByName("server-vpp")
	serverVclFileName := serverContainer.GetHostWorkDir() + "/vcl_srv.conf"
	serverVpp := serverContainer.VppInstance
	s.AssertNil(serverVpp.Start())

	serverVeth := s.GetInterfaceByName(ServerInterfaceName)
	idx, err := serverVpp.createAfPacket(serverVeth)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertNotEqual(0, idx)

	serverAppSocketApi := fmt.Sprintf("app-socket-api %s/var/run/app_ns_sockets/default",
		serverContainer.GetContainerWorkDir())
	err = srvVclConf.
		NewStanza("vcl").
		Append("rx-fifo-size 4000000").
		Append("tx-fifo-size 4000000").
		Append("app-scope-local").
		Append("app-scope-global").
		Append("use-mq-eventfd").
		Append(serverAppSocketApi).Close().
		SaveToFile(serverVclFileName)
	s.AssertNil(err, fmt.Sprint(err))
}

func (s *LdpSuite) setupClientVpp() {
	var clnVclConf Stanza
	clientContainer := s.GetContainerByName("client-vpp")
	clientVclFileName := clientContainer.GetHostWorkDir() + "/vcl_cln.conf"
	clientVpp := clientContainer.VppInstance
	s.AssertNil(clientVpp.Start())

	clientVeth := s.GetInterfaceByName(ClientInterfaceName)
	idx, err := clientVpp.createAfPacket(clientVeth)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertNotEqual(0, idx)

	clientAppSocketApi := fmt.Sprintf("app-socket-api %s/var/run/app_ns_sockets/default",
		clientContainer.GetContainerWorkDir())
	err = clnVclConf.
		NewStanza("vcl").
		Append("rx-fifo-size 4000000").
		Append("tx-fifo-size 4000000").
		Append("app-scope-local").
		Append("app-scope-global").
		Append("use-mq-eventfd").
		Append(clientAppSocketApi).Close().
		SaveToFile(clientVclFileName)
	s.AssertNil(err, fmt.Sprint(err))
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
