package hst

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"runtime"
	"strings"
	"time"

	"fd.io/hs-test/h2spec_extras"

	. "github.com/onsi/ginkgo/v2"
	"github.com/summerwind/h2spec/config"
)

type VppUdpProxySuite struct {
	HstSuite
	MaxTimeout time.Duration
	Interfaces struct {
		Client *NetInterface
		Server *NetInterface
	}
	Containers struct {
		VppProxy *Container
	}
	Ports struct {
		Proxy  int
		Server int
	}
}

var vppUdpProxyTests = map[string][]func(s *VppUdpProxySuite){}
var vppUdpProxySoloTests = map[string][]func(s *VppUdpProxySuite){}
var vppUdpProxyMWTests = map[string][]func(s *VppUdpProxySuite){}

func RegisterVppUdpProxyTests(tests ...func(s *VppUdpProxySuite)) {
	vppUdpProxyTests[GetTestFilename()] = tests
}

func RegisterVppUdpProxySoloTests(tests ...func(s *VppUdpProxySuite)) {
	vppUdpProxySoloTests[GetTestFilename()] = tests
}
func RegisterVppUdpProxyMWTests(tests ...func(s *VppUdpProxySuite)) {
	vppUdpProxyMWTests[GetTestFilename()] = tests
}

func (s *VppUdpProxySuite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.LoadNetworkTopology("2taps")
	s.LoadContainerTopology("single")
	s.Interfaces.Client = s.GetInterfaceByName("hstcln")
	s.Interfaces.Server = s.GetInterfaceByName("hstsrv")
	s.Containers.VppProxy = s.GetContainerByName("vpp")
	s.Ports.Proxy = int(s.GeneratePortAsInt())
	s.Ports.Server = int(s.GeneratePortAsInt())

	if *IsVppDebug {
		s.MaxTimeout = time.Second * 600
	} else {
		s.MaxTimeout = time.Second * 2
	}
}

func (s *VppUdpProxySuite) SetupTest() {
	s.HstSuite.SetupTest()

	// VPP proxy
	var memoryConfig Stanza
	memoryConfig.NewStanza("memory").Append("main-heap-size 2G")
	vpp, err := s.Containers.VppProxy.newVppInstance(s.Containers.VppProxy.AllocatedCpus, memoryConfig)
	AssertNotNil(vpp, fmt.Sprint(err))

	AssertNil(vpp.Start())
	AssertNil(vpp.CreateTap(s.Interfaces.Client, false, 1))
	AssertNil(vpp.CreateTap(s.Interfaces.Server, false, 2))

	arp := fmt.Sprintf("set ip neighbor %s %s %s",
		s.Interfaces.Server.Name(),
		s.Interfaces.Server.Host.Ip4AddressString(),
		s.Interfaces.Server.Host.HwAddress)
	vpp.Vppctl(arp)
	arp = fmt.Sprintf("set ip neighbor %s %s %s",
		s.Interfaces.Client.Name(),
		s.Interfaces.Client.Host.Ip4AddressString(),
		s.Interfaces.Client.Host.HwAddress)
	vpp.Vppctl(arp)

	if *DryRun {
		s.LogStartedContainers()
		s.Skip("Dry run mode = true")
	}
}

func (s *VppUdpProxySuite) TeardownTest() {
	defer s.HstSuite.TeardownTest()
	vpp := s.Containers.VppProxy.VppInstance
	if CurrentSpecReport().Failed() {
		Log(vpp.Vppctl("show session verbose 2"))
		Log(vpp.Vppctl("show error"))
	}
}

func (s *VppUdpProxySuite) VppProxyAddr() string {
	return s.Interfaces.Client.Ip4AddressString()
}

func (s *VppUdpProxySuite) ServerAddr() string {
	return s.Interfaces.Server.Host.Ip4AddressString()
}

func (s *VppUdpProxySuite) ClientAddr() string {
	return s.Interfaces.Client.Host.Ip4AddressString()
}

func (s *VppUdpProxySuite) ClientSendReceive(toSend []byte, rcvBuffer []byte) (int, error) {
	proxiedConn, err := net.DialUDP("udp",
		&net.UDPAddr{IP: net.ParseIP(s.ClientAddr()), Port: 0},
		&net.UDPAddr{IP: net.ParseIP(s.VppProxyAddr()), Port: s.Ports.Proxy})
	if err != nil {
		return 0, err
	}
	defer proxiedConn.Close()

	err = proxiedConn.SetDeadline(time.Now().Add(time.Second * 5))
	if err != nil {
		return 0, err
	}

	_, err = proxiedConn.Write(toSend)
	if err != nil {
		return 0, err
	}

	n, _, err := proxiedConn.ReadFrom(rcvBuffer)
	if err != nil {
		return 0, err
	}
	return n, nil
}

var _ = Describe("VppUdpProxySuite", Ordered, ContinueOnFailure, Label("Proxy", "UDP", "UDPproxy", "VPPproxy"), func() {
	var s VppUdpProxySuite
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

	for filename, tests := range vppUdpProxyTests {
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

var _ = Describe("VppUdpProxySuiteSolo", Ordered, ContinueOnFailure, Serial, Label("Proxy", "UDP", "UDPproxy", "VPPproxy"), func() {
	var s VppUdpProxySuite
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

	for filename, tests := range vppUdpProxySoloTests {
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

var _ = Describe("VppUdpProxyMWSuite", Ordered, ContinueOnFailure, Serial, Label("Proxy", "UDP", "UDPproxy", "VPPproxy", "MW"), func() {
	var s VppUdpProxySuite
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

	for filename, tests := range vppUdpProxyMWTests {
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

var _ = Describe("H2SpecUdpProxySuite", Ordered, ContinueOnFailure, Label("HTTP", "HTTP2", "UDP", "Proxy", "UDPproxy"), func() {
	var s VppUdpProxySuite
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

	testCases := []struct {
		desc string
	}{
		{desc: "extras/3/1"},
		{desc: "extras/3/2"},
		{desc: "extras/3.1/1"},
		{desc: "extras/3.1/2"},
		{desc: "extras/3.1/3"},
		{desc: "extras/3.1/4"},
		{desc: "extras/3.1/5"},
	}

	for _, test := range testCases {
		test := test
		testName := "proxy_test.go/h2spec_" + strings.ReplaceAll(test.desc, "/", "_")
		It(testName, func(ctx SpecContext) {
			Log("[* TEST BEGIN]: " + testName)
			vppProxy := s.Containers.VppProxy.VppInstance
			remoteServerConn := StartUdpEchoServer(s.ServerAddr(), s.Ports.Server)
			defer remoteServerConn.Close()
			// this one will open TCP tunnel too
			if strings.Contains(test.desc, "extras/3.1/5") {
				remoteTcpServerConn := StartTcpEchoServer(s.ServerAddr(), s.Ports.Server)
				defer remoteTcpServerConn.Close()
			}
			cmd := fmt.Sprintf("test proxy server fifo-size 512k server-uri https://%s/%d", s.VppProxyAddr(), s.Ports.Proxy)
			Log(vppProxy.Vppctl(cmd))
			path := fmt.Sprintf("/.well-known/masque/udp/%s/%d/", s.ServerAddr(), s.Ports.Server)
			conf := &config.Config{
				Host:         s.VppProxyAddr(),
				Port:         s.Ports.Proxy,
				Path:         path,
				Timeout:      s.MaxTimeout,
				MaxHeaderLen: 4096,
				TLS:          true,
				Insecure:     true,
				Sections:     []string{test.desc},
				Verbose:      true,
			}
			// capture h2spec output so it will be in log
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			tg := h2spec_extras.Spec()
			tg.Test(conf)

			oChan := make(chan string)
			go func() {
				var buf bytes.Buffer
				io.Copy(&buf, r)
				oChan <- buf.String()
			}()

			// restore to normal state
			w.Close()
			os.Stdout = oldStdout
			o := <-oChan
			Log(o)
			AssertEqual(0, tg.FailedCount)
		}, SpecTimeout(TestTimeout))
	}
})
