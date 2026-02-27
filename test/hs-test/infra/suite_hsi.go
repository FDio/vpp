package hst

import (
	"fmt"
	"os/exec"
	"reflect"
	"runtime"
	"strings"

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
	AssertNotNil(vpp, fmt.Sprint(err))

	AssertNil(vpp.Start())
	numCpus := uint16(len(s.Containers.Vpp.AllocatedCpus))
	numWorkers := uint16(max(numCpus-1, 1))
	idx, err := vpp.createAfPacket(s.Interfaces.Client, false, WithNumRxQueues(numWorkers), WithNumTxQueues(numCpus))
	AssertNil(err, fmt.Sprint(err))
	AssertNotEqual(0, idx)
	idx, err = vpp.createAfPacket(s.Interfaces.Server, false, WithNumRxQueues(numWorkers), WithNumTxQueues(numCpus))
	AssertNil(err, fmt.Sprint(err))
	AssertNotEqual(0, idx)

	Log(vpp.Vppctl("set interface feature " + s.Interfaces.Client.VppName() + " hsi4-in arc ip4-unicast"))
	Log(vpp.Vppctl("set interface feature " + s.Interfaces.Server.VppName() + " hsi4-in arc ip4-unicast"))

	// let the host know howto get to the server
	cmd := exec.Command("ip", "netns", "exec", s.NetNamespaces.Client, "ip", "route", "add",
		s.ServerAddr(), "via", s.Interfaces.Client.Ip4AddressString())
	Log(cmd.String())
	_, err = cmd.CombinedOutput()
	AssertNil(err, fmt.Sprint(err))

	if *DryRun {
		s.LogStartedContainers()
		s.Skip("Dry run mode = true")
	}
}

func (s *HsiSuite) TeardownTest() {
	defer s.HstSuite.TeardownTest()
	vpp := s.Containers.Vpp.VppInstance
	if CurrentSpecReport().Failed() {
		Log(vpp.Vppctl("show session verbose 2"))
		Log(vpp.Vppctl("show error"))
		CollectNginxLogs(s.Containers.NginxServerTransient)
	}
}

func (s *HsiSuite) SetupNginxServer() {
	AssertNil(s.Containers.NginxServerTransient.Create())
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
	AssertNil(s.Containers.NginxServerTransient.Start())
}

func (s *HsiSuite) ServerAddr() string {
	return s.Interfaces.Server.Host.Ip4AddressString()
}

var _ = Describe("HsiSuite", Ordered, ContinueOnFailure, Label("HSI"), func() {
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
				Log("[* TEST BEGIN]: " + testName)
				test(&s)
			}, SpecTimeout(TestTimeout))
		}
	}
})

var _ = Describe("HsiSoloSuite", Ordered, ContinueOnFailure, Serial, Label("HSI"), func() {
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
			It(testName, func(ctx SpecContext) {
				Log("[* TEST BEGIN]: " + testName)
				test(&s)
			}, SpecTimeout(TestTimeout))
		}
	}
})

var _ = Describe("HsiMWSuite", Ordered, ContinueOnFailure, Serial, Label("HSI", "Solo", "MW"), func() {
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
			It(testName, func(ctx SpecContext) {
				Log("[* TEST BEGIN]: " + testName)
				test(&s)
			}, SpecTimeout(TestTimeout))
		}
	}
})
