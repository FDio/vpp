package hst

import (
	"fmt"
	"net"
	"reflect"
	"runtime"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
)

const VppUdpProxyContainerName = "vpp"

type VppUdpProxySuite struct {
	HstSuite
	proxyPort  int
	serverPort int
}

var vppUdpProxyTests = map[string][]func(s *VppUdpProxySuite){}
var vppUdpProxySoloTests = map[string][]func(s *VppUdpProxySuite){}

func RegisterVppUdpProxyTests(tests ...func(s *VppUdpProxySuite)) {
	vppUdpProxyTests[getTestFilename()] = tests
}

func RegisterVppUdpProxySoloTests(tests ...func(s *VppUdpProxySuite)) {
	vppUdpProxySoloTests[getTestFilename()] = tests
}

func (s *VppUdpProxySuite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.LoadNetworkTopology("2taps")
	s.LoadContainerTopology("single")
}

func (s *VppUdpProxySuite) SetupTest() {
	s.HstSuite.SetupTest()

	// VPP proxy
	vppContainer := s.GetContainerByName(VppUdpProxyContainerName)
	vpp, err := vppContainer.newVppInstance(vppContainer.AllocatedCpus)
	s.AssertNotNil(vpp, fmt.Sprint(err))

	clientInterface := s.GetInterfaceByName(ClientTapInterfaceName)
	serverInterface := s.GetInterfaceByName(ServerTapInterfaceName)

	s.AssertNil(vpp.Start())
	s.AssertNil(vpp.CreateTap(clientInterface, 1, 1))
	s.AssertNil(vpp.CreateTap(serverInterface, 1, 2))

	s.proxyPort = 8080
	s.serverPort = 80

	arp := fmt.Sprintf("set ip neighbor %s %s %s",
		serverInterface.Peer.Name(),
		serverInterface.Ip4AddressString(),
		serverInterface.HwAddress)
	vpp.Vppctl(arp)

	if *DryRun {
		s.LogStartedContainers()
		s.Skip("Dry run mode = true")
	}
}

func (s *VppUdpProxySuite) TearDownTest() {
	vpp := s.GetContainerByName(VppUdpProxyContainerName).VppInstance
	if CurrentSpecReport().Failed() {
		s.Log(vpp.Vppctl("show session verbose 2"))
		s.Log(vpp.Vppctl("show error"))
	}
	s.HstSuite.TearDownTest()
}

func (s *VppUdpProxySuite) VppProxyAddr() string {
	return s.GetInterfaceByName(ClientTapInterfaceName).Peer.Ip4AddressString()
}

func (s *VppUdpProxySuite) ProxyPort() int {
	return s.proxyPort
}

func (s *VppUdpProxySuite) ServerAddr() string {
	return s.GetInterfaceByName(ServerTapInterfaceName).Ip4AddressString()
}

func (s *VppUdpProxySuite) ServerPort() int {
	return s.serverPort
}

func (s *VppUdpProxySuite) ClientAddr() string {
	return s.GetInterfaceByName(ClientTapInterfaceName).Ip4AddressString()
}

func (s *VppUdpProxySuite) StartEchoServer() *net.UDPConn {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(s.ServerAddr()), Port: s.ServerPort()})
	s.AssertNil(err, fmt.Sprint(err))
	go func() {
		for {
			b := make([]byte, 1500)
			n, addr, err := conn.ReadFrom(b)
			if err != nil {
				return
			}
			if _, err := conn.WriteTo(b[:n], addr); err != nil {
				return
			}
		}
	}()
	s.Log("started")
	return conn
}

func (s *VppUdpProxySuite) ClientSendReceive(toSend []byte, rcvBuffer []byte) (int, error) {
	proxiedConn, err := net.DialUDP("udp",
		&net.UDPAddr{IP: net.ParseIP(s.ClientAddr()), Port: 0},
		&net.UDPAddr{IP: net.ParseIP(s.VppProxyAddr()), Port: s.ProxyPort()})
	if err != nil {
		return 0, err
	}
	defer proxiedConn.Close()

	err = proxiedConn.SetReadDeadline(time.Now().Add(time.Second * 5))
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

var _ = Describe("VppUdpProxySuite", Ordered, ContinueOnFailure, func() {
	var s VppUdpProxySuite
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

	for filename, tests := range vppUdpProxyTests {
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

var _ = Describe("VppUdpProxySuiteSolo", Ordered, ContinueOnFailure, func() {
	var s VppUdpProxySuite
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

	for filename, tests := range vppUdpProxySoloTests {
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
