package hst

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
)

var tcpHarnessTests = map[string][]func(s *TcpHarnessSuite){}

type TcpHarnessSuite struct {
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

const (
	tcpHarnessPcapLinkTypeEthernet = 1
	tcpHarnessPcapLinkTypeRaw      = 101

	tcpHarnessEtherTypeIPv4  = 0x0800
	tcpHarnessEtherTypeDot1Q = 0x8100
	tcpHarnessEtherTypeQinQ  = 0x88a8

	tcpHarnessFlagAck = 0x10
)

type tcpHarnessPcapIPv4TCPPacket struct {
	SrcIP      net.IP
	DstIP      net.IP
	DstPort    uint16
	Seq        uint32
	Flags      uint8
	PayloadLen int
}

func (p tcpHarnessPcapIPv4TCPPacket) isAckOnly() bool {
	return p.PayloadLen == 0 && p.Flags == tcpHarnessFlagAck
}

func RegisterTcpHarnessTests(tests ...func(s *TcpHarnessSuite)) {
	tcpHarnessTests[GetTestFilename()] = tests
}

func (s *TcpHarnessSuite) GetPcapTracePath(vppName string) string {
	return filepath.Join(LogDir, GetCurrentTestName(), s.GetTestId(), vppName+".pcap")
}

func (s *TcpHarnessSuite) HasOldSeqAckOnlyProbe(vppName string, srcIP string, dstIP string, dstPort uint16) (bool, error) {
	packets, err := tcpHarnessReadPcapIPv4TCPPackets(s.GetPcapTracePath(vppName))
	if err != nil {
		return false, err
	}

	probeSeqs := make([]uint32, 0)
	maxDataSeqEnd := uint32(0)

	for _, packet := range packets {
		if packet.SrcIP.String() != srcIP || packet.DstIP.String() != dstIP || packet.DstPort != dstPort {
			continue
		}

		if packet.PayloadLen > 0 {
			seqEnd := packet.Seq + uint32(packet.PayloadLen)
			if seqEnd > maxDataSeqEnd {
				maxDataSeqEnd = seqEnd
			}
			continue
		}

		if packet.isAckOnly() {
			probeSeqs = append(probeSeqs, packet.Seq)
		}
	}

	for _, seq := range probeSeqs {
		if seq < maxDataSeqEnd {
			return true, nil
		}
	}

	return false, nil
}

func (s *TcpHarnessSuite) SetupSuite() {
	time.Sleep(1 * time.Second)
	s.HstSuite.SetupSuite()
	s.ConfigureNetworkTopology("2taps")
	s.LoadContainerTopology("2peerVeth")
	s.Interfaces.Client = s.GetInterfaceByName("hstcln")
	s.Interfaces.Server = s.GetInterfaceByName("hstsrv")
	s.Containers.ServerVpp = s.GetContainerByName("server-vpp")
	s.Containers.ClientVpp = s.GetContainerByName("client-vpp")
	s.Containers.ServerApp = s.GetContainerByName("server-app")
	s.Containers.ClientApp = s.GetContainerByName("client-app")
	s.Ports.Port1 = s.GeneratePort()
}

func (s *TcpHarnessSuite) SetupTest() {
	s.HstSuite.SetupTest()
	s.SetupAppContainers()

	var sessionConfig Stanza
	sessionConfig.
		NewStanza("session").
		Append("enable").
		Append("use-app-socket-api")

	if strings.Contains(CurrentSpecReport().LeafNodeText, "InterruptMode") {
		sessionConfig.Append("use-private-rx-mqs").Close()
		Log("**********************INTERRUPT MODE**********************")
	} else {
		sessionConfig.Close()
	}

	serverVpp, err := s.Containers.ServerVpp.newVppInstance(
		s.Containers.ServerVpp.AllocatedCpus, sessionConfig)
	AssertNotNil(serverVpp, fmt.Sprint(err))

	clientVpp, err := s.Containers.ClientVpp.newVppInstance(
		s.Containers.ClientVpp.AllocatedCpus, sessionConfig)
	AssertNotNil(clientVpp, fmt.Sprint(err))

	s.SetupServerVpp(s.Containers.ServerVpp)
	s.SetupClientVpp(s.Containers.ClientVpp)

	arp := fmt.Sprintf("set ip neighbor %s %s %s",
		s.Interfaces.Server.Name(),
		s.Interfaces.Client.Ip4AddressString(),
		s.Interfaces.Client.HwAddress)
	Log(serverVpp.Vppctl(arp))

	arp = fmt.Sprintf("set ip neighbor %s %s %s",
		s.Interfaces.Client.Name(),
		s.Interfaces.Server.Ip4AddressString(),
		s.Interfaces.Server.HwAddress)
	Log(clientVpp.Vppctl(arp))

	_, ipNet, err := net.ParseCIDR(s.Interfaces.Client.Ip4Address)
	AssertNil(err)
	route := fmt.Sprintf("ip route add %s via %s %s",
		ipNet.String(),
		s.Interfaces.Server.Host.Ip4AddressString(),
		s.Interfaces.Server.name)
	Log(serverVpp.Vppctl(route))

	_, ipNet, err = net.ParseCIDR(s.Interfaces.Server.Ip4Address)
	AssertNil(err)
	route = fmt.Sprintf("ip route add %s via %s %s",
		ipNet.String(),
		s.Interfaces.Client.Host.Ip4AddressString(),
		s.Interfaces.Client.name)
	Log(clientVpp.Vppctl(route))

	if *DryRun {
		s.LogStartedContainers()
		s.Skip("Dry run mode = true")
	}
}

func (s *TcpHarnessSuite) TeardownTest() {
	defer s.HstSuite.TeardownTest()
	if CurrentSpecReport().Failed() {
		Log(s.Containers.ServerVpp.VppInstance.Vppctl("show error verbose"))
		Log(s.Containers.ClientVpp.VppInstance.Vppctl("show error verbose"))
	}
}

func (s *TcpHarnessSuite) SetupAppContainers() {
	s.Containers.ClientApp.Run()
	s.Containers.ServerApp.Run()
}

func (s *TcpHarnessSuite) SetupServerVpp(serverContainer *Container) {
	serverVpp := serverContainer.VppInstance
	AssertNil(serverVpp.Start())

	err := serverVpp.CreateTap(s.Interfaces.Server, false, 1)
	AssertNil(err, fmt.Sprint(err))
}

func (s *TcpHarnessSuite) SetupClientVpp(clientContainer *Container) {
	clientVpp := clientContainer.VppInstance
	AssertNil(clientVpp.Start())

	err := clientVpp.CreateTap(s.Interfaces.Client, false, 2)
	AssertNil(err, fmt.Sprint(err))
}

func tcpHarnessReadPcapIPv4TCPPackets(path string) ([]tcpHarnessPcapIPv4TCPPacket, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < 24 {
		return nil, fmt.Errorf("pcap too short")
	}

	order, err := tcpHarnessPcapByteOrder(data[:4])
	if err != nil {
		return nil, err
	}

	linkType := order.Uint32(data[20:24])
	offset := 24
	packets := make([]tcpHarnessPcapIPv4TCPPacket, 0)

	for offset+16 <= len(data) {
		inclLen := int(order.Uint32(data[offset+8 : offset+12]))
		offset += 16
		if inclLen < 0 || offset+inclLen > len(data) {
			return nil, fmt.Errorf("invalid pcap record length")
		}

		pkt := data[offset : offset+inclLen]
		offset += inclLen

		packet, ok := tcpHarnessParsePcapIPv4TCPPacket(linkType, pkt)
		if ok {
			packets = append(packets, packet)
		}
	}

	return packets, nil
}

func tcpHarnessPcapByteOrder(magic []byte) (binary.ByteOrder, error) {
	switch binary.BigEndian.Uint32(magic) {
	case 0xa1b2c3d4, 0xa1b23c4d:
		return binary.BigEndian, nil
	case 0xd4c3b2a1, 0x4d3cb2a1:
		return binary.LittleEndian, nil
	default:
		return nil, fmt.Errorf("unknown pcap magic")
	}
}

func tcpHarnessPcapPayloadOffset(linkType uint32, pkt []byte) (int, bool) {
	switch linkType {
	case tcpHarnessPcapLinkTypeEthernet:
		if len(pkt) < 14 {
			return 0, false
		}

		ethType := binary.BigEndian.Uint16(pkt[12:14])
		offset := 14
		if ethType == tcpHarnessEtherTypeDot1Q || ethType == tcpHarnessEtherTypeQinQ {
			if len(pkt) < 18 {
				return 0, false
			}
			ethType = binary.BigEndian.Uint16(pkt[16:18])
			offset = 18
		}
		if ethType != tcpHarnessEtherTypeIPv4 {
			return 0, false
		}
		return offset, true
	case tcpHarnessPcapLinkTypeRaw:
		return 0, true
	default:
		return 0, false
	}
}

func tcpHarnessParsePcapIPv4TCPPacket(linkType uint32, pkt []byte) (tcpHarnessPcapIPv4TCPPacket, bool) {
	l3off, ok := tcpHarnessPcapPayloadOffset(linkType, pkt)
	if !ok || len(pkt) < l3off+20 {
		return tcpHarnessPcapIPv4TCPPacket{}, false
	}
	if pkt[l3off]>>4 != 4 {
		return tcpHarnessPcapIPv4TCPPacket{}, false
	}

	ipHdrLen := int(pkt[l3off]&0x0f) * 4
	if len(pkt) < l3off+ipHdrLen+20 || pkt[l3off+9] != 6 {
		return tcpHarnessPcapIPv4TCPPacket{}, false
	}

	totalLen := int(binary.BigEndian.Uint16(pkt[l3off+2 : l3off+4]))
	if totalLen < ipHdrLen+20 || len(pkt) < l3off+totalLen {
		return tcpHarnessPcapIPv4TCPPacket{}, false
	}

	tcpOff := l3off + ipHdrLen
	tcpHdrLen := int(pkt[tcpOff+12]>>4) * 4
	if tcpHdrLen < 20 || totalLen < ipHdrLen+tcpHdrLen {
		return tcpHarnessPcapIPv4TCPPacket{}, false
	}

	return tcpHarnessPcapIPv4TCPPacket{
		SrcIP:      net.IPv4(pkt[l3off+12], pkt[l3off+13], pkt[l3off+14], pkt[l3off+15]),
		DstIP:      net.IPv4(pkt[l3off+16], pkt[l3off+17], pkt[l3off+18], pkt[l3off+19]),
		DstPort:    binary.BigEndian.Uint16(pkt[tcpOff+2 : tcpOff+4]),
		Seq:        binary.BigEndian.Uint32(pkt[tcpOff+4 : tcpOff+8]),
		Flags:      pkt[tcpOff+13],
		PayloadLen: totalLen - ipHdrLen - tcpHdrLen,
	}, true
}

var _ = Describe("TcpHarnessSuite", Ordered, ContinueOnFailure, Label("TCP", "Harness", "CrossStack"), func() {
	var s TcpHarnessSuite
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

	for filename, tests := range tcpHarnessTests {
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
