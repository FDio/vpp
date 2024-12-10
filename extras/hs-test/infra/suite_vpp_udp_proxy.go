package hst

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
)

const VppUdpProxyContainerName = "vpp"

type VppUdpProxySuite struct {
	HstSuite
	proxyPort  int
	serverPort int
	MaxTimeout time.Duration
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

	if *IsVppDebug {
		s.MaxTimeout = time.Second * 600
	} else {
		s.MaxTimeout = time.Second * 10
	}
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
	s.AssertNil(vpp.createTap(clientInterface, 1))
	s.AssertNil(vpp.createTap(serverInterface, 2))

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
	s.Log("* started udp echo server " + s.ServerAddr() + ":" + strconv.Itoa(s.ServerPort()))
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

	err = proxiedConn.SetReadDeadline(time.Now().Add(s.MaxTimeout))
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

func (s *VppUdpProxySuite) OpenConnectUdpTunnel(proxyAddress, targetUri string) (net.Conn, error) {
	req := WriteConnectUdpReq(targetUri)
	conn, err := net.DialTimeout("tcp", proxyAddress, s.MaxTimeout)
	if err != nil {
		return nil, err
	}
	err = conn.SetDeadline(time.Now().Add(s.MaxTimeout))
	if err != nil {
		return nil, err
	}

	s.Log("* Connected to proxy (" + s.VppProxyAddr() + ":" + strconv.Itoa(s.ProxyPort()) + ")")

	_, err = conn.Write(req)
	if err != nil {
		return nil, err
	}

	r := bufio.NewReader(conn)
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		return nil, err
	}
	s.Log(DumpHttpResp(resp, true))
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, errors.New("request failed")
	}
	if resp.Header.Get("Connection") != "upgrade" || resp.Header.Get("Upgrade") != "connect-udp" || resp.Header.Get("Capsule-Protocol") != "?1" {
		return nil, errors.New("invalid response")
	}

	s.Log("* CONNECT-UDP tunnel established (" + s.ServerAddr() + ":" + strconv.Itoa(s.ServerPort()) + ")")
	return conn, nil
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
