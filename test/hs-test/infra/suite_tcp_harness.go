package hst

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
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
	TcpTestPeer struct {
		ControlSock       string
		LogPath           string
		ClientControlSock string
		ClientLogPath     string
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

type TcpTestPeerStats struct {
	Accepted   bool
	Paused     bool
	Connected  bool
	PeerClosed bool
	BytesRead  uint64
	BytesSent  uint64
}

type TcpHarnessPcapTrace struct {
	vpp       *VppInstance
	collected bool
}

type TcpTestPeerServerConfig struct {
	ListenAddr  string
	Port        string
	ControlSock string
	LogPath     string
	ReceiveBuf  uint32
	WindowClamp uint32
	PauseRead   bool
}

type TcpTestPeerClientConfig struct {
	ConnectAddr string
	Port        string
	ControlSock string
	LogPath     string
}

const (
	pcapLinkTypeEthernet = 1
	pcapLinkTypeRaw      = 101

	pcapGlobalHeaderLen = 24
	pcapRecordHeaderLen = 16

	ethernetHeaderLen     = 14
	ethernetVlanHeaderLen = 18
	etherTypeOffset       = 12
	etherTypeVlanOffset   = 16

	etherTypeIPv4  = 0x0800
	etherTypeDot1Q = 0x8100
	etherTypeQinQ  = 0x88a8

	ipv4Version                  = 4
	ipv4MinHeaderLen             = 20
	ipv4VersionIhlOffset         = 0
	ipv4TotalLenOffset           = 2
	ipv4ProtocolOffset           = 9
	ipv4SrcAddrOffset            = 12
	ipv4DstAddrOffset            = 16
	ipv4ProtocolTCP              = 6
	ipv4HeaderLenMultiplier      = 4
	ipv4VersionShift             = 4
	ipv4HeaderLenMask       byte = 0x0f

	tcpMinHeaderLen        = 20
	tcpDstPortOffset       = 2
	tcpSeqOffset           = 4
	tcpDataOffsetByte      = 12
	tcpFlagsOffset         = 13
	tcpHeaderLenShift      = 4
	tcpHeaderLenMultiplier = 4

	tcpFlagAck = 0x10
)

type PcapIPv4TCPPacket struct {
	SrcIP      net.IP
	DstIP      net.IP
	DstPort    uint16
	Seq        uint32
	Flags      uint8
	PayloadLen int
}

func (p PcapIPv4TCPPacket) IsAckOnly() bool {
	return p.PayloadLen == 0 && p.Flags == tcpFlagAck
}

func RegisterTcpHarnessTests(tests ...func(s *TcpHarnessSuite)) {
	tcpHarnessTests[GetTestFilename()] = tests
}

func (cfg TcpTestPeerServerConfig) command() string {
	args := []string{
		"tcp_test_peer server",
		fmt.Sprintf("--listen %s", cfg.ListenAddr),
		fmt.Sprintf("--port %s", cfg.Port),
		fmt.Sprintf("--control %s", cfg.ControlSock),
	}

	if cfg.ReceiveBuf != 0 {
		args = append(args, fmt.Sprintf("--rcvbuf %d", cfg.ReceiveBuf))
	}
	if cfg.WindowClamp != 0 {
		args = append(args, fmt.Sprintf("--window-clamp %d", cfg.WindowClamp))
	}
	if cfg.PauseRead {
		args = append(args, "--pause-read")
	}

	cmd := strings.Join(args, " ")
	if cfg.LogPath != "" {
		cmd += fmt.Sprintf(" > %s 2>&1", cfg.LogPath)
	}

	return cmd
}

func (cfg TcpTestPeerClientConfig) command() string {
	args := []string{
		"tcp_test_peer client",
		fmt.Sprintf("--control %s", cfg.ControlSock),
	}

	if cfg.ConnectAddr != "" {
		args = append(args, fmt.Sprintf("--connect %s", cfg.ConnectAddr))
	}
	if cfg.Port != "" {
		args = append(args, fmt.Sprintf("--port %s", cfg.Port))
	}

	cmd := strings.Join(args, " ")
	if cfg.LogPath != "" {
		cmd += fmt.Sprintf(" > %s 2>&1", cfg.LogPath)
	}

	return cmd
}

func (s *TcpHarnessSuite) StartTcpTestPeerServer(c *Container, cfg TcpTestPeerServerConfig) {
	if cfg.ControlSock == "" {
		cfg.ControlSock = s.TcpTestPeer.ControlSock
	}
	if cfg.LogPath == "" {
		cfg.LogPath = s.TcpTestPeer.LogPath
	}
	c.ExecServer(false, WrapCmdWithLineBuffering(cfg.command()))
}

func (s *TcpHarnessSuite) tcpTestPeerVclConfig(c *Container) string {
	var stanza Stanza
	stanza.NewStanza("vcl").
		Append(fmt.Sprintf("app-socket-api %s/var/run/app_ns_sockets/default", c.GetContainerWorkDir())).
		Append("app-scope-global").
		Append("app-scope-local").
		Append("use-mq-eventfd")
	return stanza.Close().ToString()
}

func (s *TcpHarnessSuite) StartTcpTestPeerClient(c *Container, cfg TcpTestPeerClientConfig) {
	if cfg.ControlSock == "" {
		cfg.ControlSock = s.TcpTestPeer.ClientControlSock
	}
	if cfg.LogPath == "" {
		cfg.LogPath = s.TcpTestPeer.ClientLogPath
	}

	c.CreateFile("/vcl.conf", s.tcpTestPeerVclConfig(c))
	c.AddEnvVar("VCL_CONFIG", "/vcl.conf")
	c.ExecServer(true, WrapCmdWithLineBuffering(cfg.command()))
}

func (s *TcpHarnessSuite) TcpTestPeerCtl(c *Container, controlSock string, command string) string {
	out, ok := s.TcpTestPeerCtlTry(c, controlSock, command)
	AssertEqual(true, ok, "failed to execute tcp_test_peer control command: %s", command)
	return out
}

func (s *TcpHarnessSuite) TcpTestPeerCtlTry(c *Container, controlSock string,
	command string) (string, bool) {
	o, err := c.Exec(false, "tcp_test_peer ctl --control %s %s", controlSock, command)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(o), true
}

func (s *TcpHarnessSuite) logTcpTestPeerLog(c *Container, path string) {
	out, err := c.Exec(false, "cat %s", path)
	if err != nil {
		Log("failed to read tcp_test_peer log %s: %v", path, err)
		return
	}

	out = strings.TrimSpace(out)
	if out == "" {
		Log("tcp_test_peer log is empty: %s", path)
		return
	}

	Log("tcp_test_peer log (%s):\n%s", path, out)
}

func (s *TcpHarnessSuite) LogTcpTestPeerLog(c *Container) {
	s.logTcpTestPeerLog(c, s.TcpTestPeer.LogPath)
}

func (s *TcpHarnessSuite) LogTcpTestPeerClientLog(c *Container) {
	s.logTcpTestPeerLog(c, s.TcpTestPeer.ClientLogPath)
}

func ParseTcpTestPeerStats(out string) TcpTestPeerStats {
	stats := TcpTestPeerStats{}

	for _, field := range strings.Fields(out) {
		parts := strings.SplitN(field, "=", 2)
		if len(parts) != 2 {
			continue
		}
		switch parts[0] {
		case "accepted":
			stats.Accepted = parts[1] == "1"
		case "paused":
			stats.Paused = parts[1] == "1"
		case "connected":
			stats.Connected = parts[1] == "1"
		case "peer_closed":
			stats.PeerClosed = parts[1] == "1"
		case "bytes_read":
			v, err := strconv.ParseUint(parts[1], 10, 64)
			AssertNil(err)
			stats.BytesRead = v
		case "bytes_sent":
			v, err := strconv.ParseUint(parts[1], 10, 64)
			AssertNil(err)
			stats.BytesSent = v
		}
	}

	return stats
}

func (s *TcpHarnessSuite) StartPcapTrace(vpp *VppInstance) *TcpHarnessPcapTrace {
	vpp.EnablePcapTrace()
	return &TcpHarnessPcapTrace{vpp: vpp}
}

func (t *TcpHarnessPcapTrace) Collect() {
	if t == nil || t.collected {
		return
	}
	t.vpp.CollectPcapTrace()
	t.collected = true
}

func (t *TcpHarnessPcapTrace) Close() {
	t.Collect()
}

func (s *TcpHarnessSuite) TcpTestPeerStatsTryGet(c *Container, controlSock string) (TcpTestPeerStats, bool) {
	out, err := c.Exec(false, "tcp_test_peer ctl --control %s stats", controlSock)
	if err != nil {
		return TcpTestPeerStats{}, false
	}
	return ParseTcpTestPeerStats(strings.TrimSpace(out)), true
}

func (s *TcpHarnessSuite) TcpTestPeerStatsGet(c *Container, controlSock string) TcpTestPeerStats {
	stats, ok := s.TcpTestPeerStatsTryGet(c, controlSock)
	AssertEqual(true, ok, "failed to query tcp_test_peer stats")
	return stats
}

func (s *TcpHarnessSuite) WaitForTcpTestPeerStats(c *Container, controlSock string,
	timeout time.Duration, check func(stats TcpTestPeerStats) bool) TcpTestPeerStats {
	deadline := time.Now().Add(timeout)
	var stats TcpTestPeerStats

	for time.Now().Before(deadline) {
		if next, ok := s.TcpTestPeerStatsTryGet(c, controlSock); ok {
			stats = next
			if check(stats) {
				return stats
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	AssertEmpty("timed out waiting for tcp_test_peer stats condition")
	return stats
}

func (s *TcpHarnessSuite) GetPcapTracePath(vppName string) string {
	return filepath.Join(LogDir, GetCurrentTestName(), s.GetTestId(), vppName+".pcap")
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
	s.TcpTestPeer.ControlSock =
		filepath.Join(s.Containers.ServerApp.GetContainerWorkDir(), "tcp_test_peer.sock")
	s.TcpTestPeer.LogPath =
		filepath.Join(s.Containers.ServerApp.GetContainerWorkDir(), "tcp_test_peer.log")
	s.TcpTestPeer.ClientControlSock =
		filepath.Join(s.Containers.ClientApp.GetContainerWorkDir(), "tcp_test_peer.sock")
	s.TcpTestPeer.ClientLogPath =
		filepath.Join(s.Containers.ClientApp.GetContainerWorkDir(), "tcp_test_peer.log")

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

func ReadPcapIPv4TCPPackets(path string) ([]PcapIPv4TCPPacket, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < pcapGlobalHeaderLen {
		return nil, fmt.Errorf("pcap too short")
	}

	order, err := pcapByteOrder(data[:4])
	if err != nil {
		return nil, err
	}

	linkType := order.Uint32(data[20:24])
	offset := pcapGlobalHeaderLen
	packets := make([]PcapIPv4TCPPacket, 0)

	for offset+pcapRecordHeaderLen <= len(data) {
		inclLen := int(order.Uint32(data[offset+8 : offset+12]))
		offset += pcapRecordHeaderLen
		if inclLen < 0 || offset+inclLen > len(data) {
			return nil, fmt.Errorf("invalid pcap record length")
		}

		pkt := data[offset : offset+inclLen]
		offset += inclLen

		packet, ok := parsePcapIPv4TCPPacket(linkType, pkt)
		if ok {
			packets = append(packets, packet)
		}
	}

	return packets, nil
}

func pcapByteOrder(magic []byte) (binary.ByteOrder, error) {
	switch binary.BigEndian.Uint32(magic) {
	case 0xa1b2c3d4, 0xa1b23c4d:
		return binary.BigEndian, nil
	case 0xd4c3b2a1, 0x4d3cb2a1:
		return binary.LittleEndian, nil
	default:
		return nil, fmt.Errorf("unknown pcap magic")
	}
}

func pcapPayloadOffset(linkType uint32, pkt []byte) (int, bool) {
	switch linkType {
	case pcapLinkTypeEthernet:
		if len(pkt) < ethernetHeaderLen {
			return 0, false
		}

		ethType := binary.BigEndian.Uint16(pkt[etherTypeOffset : etherTypeOffset+2])
		offset := ethernetHeaderLen
		if ethType == etherTypeDot1Q || ethType == etherTypeQinQ {
			if len(pkt) < ethernetVlanHeaderLen {
				return 0, false
			}
			ethType = binary.BigEndian.Uint16(pkt[etherTypeVlanOffset : etherTypeVlanOffset+2])
			offset = ethernetVlanHeaderLen
		}
		if ethType != etherTypeIPv4 {
			return 0, false
		}
		return offset, true
	case pcapLinkTypeRaw:
		return 0, true
	default:
		return 0, false
	}
}

func parsePcapIPv4TCPPacket(linkType uint32, pkt []byte) (PcapIPv4TCPPacket, bool) {
	l3off, ok := pcapPayloadOffset(linkType, pkt)
	if !ok || len(pkt) < l3off+ipv4MinHeaderLen {
		return PcapIPv4TCPPacket{}, false
	}
	if pkt[l3off+ipv4VersionIhlOffset]>>ipv4VersionShift != ipv4Version {
		return PcapIPv4TCPPacket{}, false
	}

	ipHdrLen := int(pkt[l3off+ipv4VersionIhlOffset]&ipv4HeaderLenMask) *
		ipv4HeaderLenMultiplier
	if len(pkt) < l3off+ipHdrLen+tcpMinHeaderLen ||
		pkt[l3off+ipv4ProtocolOffset] != ipv4ProtocolTCP {
		return PcapIPv4TCPPacket{}, false
	}

	totalLen := int(binary.BigEndian.Uint16(pkt[l3off+ipv4TotalLenOffset : l3off+ipv4TotalLenOffset+2]))
	if totalLen < ipHdrLen+tcpMinHeaderLen || len(pkt) < l3off+totalLen {
		return PcapIPv4TCPPacket{}, false
	}

	tcpOff := l3off + ipHdrLen
	tcpHdrLen := int(pkt[tcpOff+tcpDataOffsetByte]>>tcpHeaderLenShift) *
		tcpHeaderLenMultiplier
	if tcpHdrLen < tcpMinHeaderLen || totalLen < ipHdrLen+tcpHdrLen {
		return PcapIPv4TCPPacket{}, false
	}

	return PcapIPv4TCPPacket{
		SrcIP: net.IPv4(pkt[l3off+ipv4SrcAddrOffset], pkt[l3off+ipv4SrcAddrOffset+1],
			pkt[l3off+ipv4SrcAddrOffset+2], pkt[l3off+ipv4SrcAddrOffset+3]),
		DstIP: net.IPv4(pkt[l3off+ipv4DstAddrOffset], pkt[l3off+ipv4DstAddrOffset+1],
			pkt[l3off+ipv4DstAddrOffset+2], pkt[l3off+ipv4DstAddrOffset+3]),
		DstPort:    binary.BigEndian.Uint16(pkt[tcpOff+tcpDstPortOffset : tcpOff+tcpDstPortOffset+2]),
		Seq:        binary.BigEndian.Uint32(pkt[tcpOff+tcpSeqOffset : tcpOff+tcpSeqOffset+4]),
		Flags:      pkt[tcpOff+tcpFlagsOffset],
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
