package hst

import (
	"fmt"
	"os/exec"
	"reflect"
	"runtime"
	"strings"

	. "fd.io/hs-test/infra/common"
	. "github.com/onsi/ginkgo/v2"
)

type HsiSuite struct {
	HstSuite
	maxTimeout int
	Interfaces struct {
		Client *NetInterface
		Server *NetInterface
	}
	Containers struct {
		Vpp                  *Container
		NginxServerTransient *Container
	}
	Ports struct {
		Server    uint16
		ServerSsl uint16
	}
	NetNamespaces struct {
		Client string
	}
}

var hsiTests = map[string][]func(s *HsiSuite){}
var hsiSoloTests = map[string][]func(s *HsiSuite){}
var hsiMWTests = map[string][]func(s *HsiSuite){}

func RegisterHsiTests(tests ...func(s *HsiSuite)) {
	hsiTests[GetTestFilename()] = tests
}

func RegisterHsiSoloTests(tests ...func(s *HsiSuite)) {
	hsiSoloTests[GetTestFilename()] = tests
}

func RegisterHsiMWTests(tests ...func(s *HsiSuite)) {
	hsiMWTests[GetTestFilename()] = tests
}

func (s *HsiSuite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.ConfigureNetworkTopology("ns")
	s.LoadContainerTopology("single")
	s.Ports.Server = s.GeneratePortAsInt()
	s.Ports.ServerSsl = s.GeneratePortAsInt()

	if *IsVppDebug {
		s.maxTimeout = 600
	} else {
		s.maxTimeout = 60
	}
	s.Interfaces.Client = s.GetInterfaceByName("hclnvpp")
	s.Interfaces.Server = s.GetInterfaceByName("hsrvvpp")
	s.NetNamespaces.Client = s.GetNetNamespaceByName("cln")
	s.Containers.NginxServerTransient = s.GetTransientContainerByName("nginx-server")
	s.Containers.Vpp = s.GetContainerByName("vpp")
}

func (s *HsiSuite) SetupTest() {
	s.HstSuite.SetupTest()

	vpp, err := s.Containers.Vpp.newVppInstance(s.Containers.Vpp.AllocatedCpus)
	s.AssertNotNil(vpp, fmt.Sprint(err))

	s.AssertNil(vpp.Start())
	idx, err := vpp.createAfPacket(s.Interfaces.Client, false)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertNotEqual(0, idx)
	idx, err = vpp.createAfPacket(s.Interfaces.Server, false)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertNotEqual(0, idx)

	s.Log(vpp.Vppctl("set interface feature host-" + s.Interfaces.Client.Name() + " hsi4-in arc ip4-unicast"))
	s.Log(vpp.Vppctl("set interface feature host-" + s.Interfaces.Server.Name() + " hsi4-in arc ip4-unicast"))

	// let the host know howto get to the server
	cmd := exec.Command("ip", "netns", "exec", s.NetNamespaces.Client, "ip", "route", "add",
		s.ServerAddr(), "via", s.Interfaces.Client.Ip4AddressString())
	s.Log(cmd.String())
	_, err = cmd.CombinedOutput()
	s.AssertNil(err, fmt.Sprint(err))

	if *DryRun {
		s.LogStartedContainers()
		s.Skip("Dry run mode = true")
	}
}

func (s *HsiSuite) TeardownTest() {
	defer s.HstSuite.TeardownTest()
	vpp := s.Containers.Vpp.VppInstance
	if CurrentSpecReport().Failed() {
		s.Log(vpp.Vppctl("show session verbose 2"))
		s.Log(vpp.Vppctl("show error"))
		s.CollectNginxLogs(s.Containers.NginxServerTransient)
	}
}

func (s *HsiSuite) SetupNginxServer() {
	s.AssertNil(s.Containers.NginxServerTransient.Create())
	nginxSettings := struct {
		LogPrefix string
		Address   string
		Port      uint16
		PortSsl   uint16
		Http2     string
		Timeout   int
	}{
		LogPrefix: s.Containers.NginxServerTransient.Name,
		Address:   s.ServerAddr(),
		Port:      s.Ports.Server,
		PortSsl:   s.Ports.ServerSsl,
		Http2:     "off",
		Timeout:   s.maxTimeout,
	}
	s.Containers.NginxServerTransient.CreateConfigFromTemplate(
		"/nginx.conf",
		"./resources/nginx/nginx_server.conf",
		nginxSettings,
	)
	s.AssertNil(s.Containers.NginxServerTransient.Start())
}

func (s *HsiSuite) ServerAddr() string {
	return s.Interfaces.Server.Peer.Ip4AddressString()
}

var _ = Describe("HsiSuite", Ordered, ContinueOnFailure, func() {
	var s HsiSuite
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

	for filename, tests := range hsiTests {
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

var _ = Describe("HsiSoloSuite", Ordered, ContinueOnFailure, Serial, func() {
	var s HsiSuite
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

	for filename, tests := range hsiSoloTests {
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

var _ = Describe("HsiMWSuite", Ordered, ContinueOnFailure, Serial, func() {
	var s HsiSuite
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

	for filename, tests := range hsiMWTests {
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
