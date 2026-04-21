package hst

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
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
	TcpTestEndpoint struct {
		ControlSock       string
		LogPath           string
		ClientControlSock string
		ClientLogPath     string
	}
	Impairments struct {
		ClientNsim  bool
		ServerNsim  bool
		ClientNetem bool
		ServerNetem bool
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

type TcpTestEndpointStats struct {
	Accepted   bool
	Paused     bool
	Connected  bool
	PeerClosed bool
	BytesRead  uint64
	BytesSent  uint64
}

type TcpTestEndpointCommandResult struct {
	Out string
	Err error
}

type TcpHarnessClientSessionStats struct {
	Output              string
	SndMss              uint64
	RtoBackoffCount     uint64
	FastRecoveryCount   uint64
	TimerRecoveryCount  uint64
	RetransmitSegsCount uint64
	SackedBytes         uint64
	LostBytes           uint64
	ScoreboardHoleCount uint64
	ReorderThreshold    uint64
	IsReneging          bool
}

type TcpHarnessPcapTrace struct {
	vpp       *VppInstance
	collected bool
}

type TcpTestEndpointServerConfig struct {
	ListenAddr  string
	Port        string
	ControlSock string
	LogPath     string
	ReceiveBuf  uint32
	WindowClamp uint32
	PauseRead   bool
}

type TcpTestEndpointClientConfig struct {
	ConnectAddr string
	Port        string
	ControlSock string
	LogPath     string
}

type TcpHarnessNsimConfig struct {
	Delay             string
	Bandwidth         string
	PacketSize        uint32
	PacketsPerDrop    uint32
	PacketsPerReorder uint32
}

type TcpHarnessNetemConfig struct {
	Delay              string
	Loss               string
	Reorder            string
	ReorderCorrelation string
}

type TcpTestEndpointCtl string

type TcpTestEndpointStat string

type TcpHarnessScenarioState struct {
	ClientPcapTrace *TcpHarnessPcapTrace
}

type TcpHarnessAction interface {
	Run(s *TcpHarnessSuite, st *TcpHarnessScenarioState)
}

type TcpHarnessActionFunc func(s *TcpHarnessSuite, st *TcpHarnessScenarioState)

type TcpHarnessSendHandle struct {
	done <-chan TcpTestEndpointCommandResult
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
	tcpSrcPortOffset       = 0
	tcpDstPortOffset       = 2
	tcpSeqOffset           = 4
	tcpAckOffset           = 8
	tcpDataOffsetByte      = 12
	tcpFlagsOffset         = 13
	tcpHeaderLenShift      = 4
	tcpHeaderLenMultiplier = 4
	tcpOptionsOffset       = 20

	tcpFlagAck = 0x10

	tcpOptionEnd          = 0
	tcpOptionNoop         = 1
	tcpOptionSack         = 5
	tcpOptionHeaderLen    = 2
	tcpOptionSackBlockLen = 8

	tcpHarnessNsimDefaultDelay      = "0.1 ms"
	tcpHarnessNsimDefaultBandwidth  = "10 gbps"
	tcpHarnessNsimDefaultPacketSize = 1460
	tcpHarnessNetemDefaultDelay     = "10ms"
	tcpHarnessPcapMaxBytesPerPkt    = 2000

	TcpTestEndpointCtlStats      TcpTestEndpointCtl = "stats"
	TcpTestEndpointCtlShutdown   TcpTestEndpointCtl = "shutdown"
	TcpTestEndpointCtlClose      TcpTestEndpointCtl = "close"
	TcpTestEndpointCtlResumeRead TcpTestEndpointCtl = "resume-read"

	TcpTestEndpointStatAccepted   TcpTestEndpointStat = "accepted"
	TcpTestEndpointStatPaused     TcpTestEndpointStat = "paused"
	TcpTestEndpointStatConnected  TcpTestEndpointStat = "connected"
	TcpTestEndpointStatPeerClosed TcpTestEndpointStat = "peer_closed"
	TcpTestEndpointStatBytesRead  TcpTestEndpointStat = "bytes_read"
	TcpTestEndpointStatBytesSent  TcpTestEndpointStat = "bytes_sent"
)

var (
	tcpHarnessClientSessionSndMssRE  = regexp.MustCompile(`\bsnd_mss (\d+)\b`)
	tcpHarnessClientSessionRtoBoffRE = regexp.MustCompile(`\brto_boff (\d+)\b`)
	tcpHarnessClientSessionFrRE      = regexp.MustCompile(`\bfr (\d+)\b`)
	tcpHarnessClientSessionTrRE      = regexp.MustCompile(`\btr (\d+)\b`)
	tcpHarnessClientSessionRxtRE     = regexp.MustCompile(`\brxt segs (\d+)\b`)
	tcpHarnessClientSessionSackedRE  = regexp.MustCompile(`\bsacked (\d+)\b`)
	tcpHarnessClientSessionLostRE    = regexp.MustCompile(`\blost (\d+)\b`)
	tcpHarnessClientSessionHolesRE   = regexp.MustCompile(`\b(\d+) holes:`)
	tcpHarnessClientSessionReordRE   = regexp.MustCompile(`\breorder (\d+)\b`)
	tcpHarnessClientSessionRenegRE   = regexp.MustCompile(`\bis_reneging (\d+)\b`)
)

func TcpTestEndpointCtlSend(bytes uint64) TcpTestEndpointCtl {
	return TcpTestEndpointCtl(fmt.Sprintf("send %d", bytes))
}

type PcapIPv4TCPPacket struct {
	Timestamp  time.Time
	SrcIP      net.IP
	DstIP      net.IP
	SrcPort    uint16
	DstPort    uint16
	Seq        uint32
	Ack        uint32
	Flags      uint8
	SackBlocks int
	PayloadLen int
}

func (p PcapIPv4TCPPacket) IsAckOnly() bool {
	return p.PayloadLen == 0 && p.Flags == tcpFlagAck
}

func IsAccepted(stats TcpTestEndpointStats) bool {
	return stats.Accepted
}

func IsPeerClosed(stats TcpTestEndpointStats) bool {
	return stats.PeerClosed
}

func BytesReadAtLeast(n uint64) func(stats TcpTestEndpointStats) bool {
	return func(stats TcpTestEndpointStats) bool {
		return stats.BytesRead >= n
	}
}

func BytesSentAtLeast(n uint64) func(stats TcpTestEndpointStats) bool {
	return func(stats TcpTestEndpointStats) bool {
		return stats.BytesSent >= n
	}
}

func BytesReadExactly(n uint64) func(stats TcpTestEndpointStats) bool {
	return func(stats TcpTestEndpointStats) bool {
		return stats.BytesRead == n
	}
}

func BytesSentExactly(n uint64) func(stats TcpTestEndpointStats) bool {
	return func(stats TcpTestEndpointStats) bool {
		return stats.BytesSent == n
	}
}

func PeerClosedAndBytesReadExactly(n uint64) func(stats TcpTestEndpointStats) bool {
	return func(stats TcpTestEndpointStats) bool {
		return stats.PeerClosed && stats.BytesRead == n
	}
}

func HasSndMss(stats TcpHarnessClientSessionStats) bool {
	return stats.SndMss > 0
}

func HasRtoBackoffAtLeast(n uint64) func(stats TcpHarnessClientSessionStats) bool {
	return func(stats TcpHarnessClientSessionStats) bool {
		return stats.RtoBackoffCount >= n
	}
}

func HasFastRecoveryOnly(minRxt uint64) func(stats TcpHarnessClientSessionStats) bool {
	return func(stats TcpHarnessClientSessionStats) bool {
		return stats.FastRecoveryCount > 0 &&
			stats.TimerRecoveryCount == 0 &&
			stats.RetransmitSegsCount >= minRxt
	}
}

func HasFastAndTimerRecovery(minRxt uint64) func(stats TcpHarnessClientSessionStats) bool {
	return func(stats TcpHarnessClientSessionStats) bool {
		return stats.FastRecoveryCount > 0 &&
			stats.TimerRecoveryCount > 0 &&
			stats.RetransmitSegsCount >= minRxt
	}
}

func HasTimerRecoveryOnly(minRxt uint64) func(stats TcpHarnessClientSessionStats) bool {
	return func(stats TcpHarnessClientSessionStats) bool {
		return stats.FastRecoveryCount == 0 &&
			stats.TimerRecoveryCount > 0 &&
			stats.RetransmitSegsCount >= minRxt
	}
}

func HasScoreboardActivity(minRxt uint64) func(stats TcpHarnessClientSessionStats) bool {
	return func(stats TcpHarnessClientSessionStats) bool {
		return stats.FastRecoveryCount > 0 &&
			stats.RetransmitSegsCount >= minRxt &&
			stats.SackedBytes > 0 &&
			(stats.ScoreboardHoleCount > 0 || stats.LostBytes > 0) &&
			!stats.IsReneging
	}
}

func (fn TcpHarnessActionFunc) Run(s *TcpHarnessSuite, st *TcpHarnessScenarioState) {
	fn(s, st)
}

func (st *TcpHarnessScenarioState) Close() {
	if st == nil {
		return
	}
	if st.ClientPcapTrace != nil {
		st.ClientPcapTrace.Close()
	}
}

func RunTcpHarnessScenarioOnState(s *TcpHarnessSuite, st *TcpHarnessScenarioState,
	actions ...TcpHarnessAction) *TcpHarnessScenarioState {
	if st == nil {
		st = &TcpHarnessScenarioState{}
	}

	for _, action := range actions {
		action.Run(s, st)
	}

	return st
}

func RunTcpHarnessScenario(s *TcpHarnessSuite, actions ...TcpHarnessAction) *TcpHarnessScenarioState {
	return RunTcpHarnessScenarioOnState(s, nil, actions...)
}

func StartClientPcap() TcpHarnessAction {
	return TcpHarnessActionFunc(func(s *TcpHarnessSuite, st *TcpHarnessScenarioState) {
		st.ClientPcapTrace = s.StartPcapTrace(s.Containers.ClientVpp.VppInstance)
	})
}

func StartTcpTestEndpointServer(cfg TcpTestEndpointServerConfig) TcpHarnessAction {
	return TcpHarnessActionFunc(func(s *TcpHarnessSuite, st *TcpHarnessScenarioState) {
		s.StartTcpTestEndpointServer(cfg)
	})
}

func StartTcpTestEndpointClient(cfg TcpTestEndpointClientConfig) TcpHarnessAction {
	return TcpHarnessActionFunc(func(s *TcpHarnessSuite, st *TcpHarnessScenarioState) {
		s.StartTcpTestEndpointClient(cfg)
	})
}

func ServerCtl(command TcpTestEndpointCtl) TcpHarnessAction {
	return TcpHarnessActionFunc(func(s *TcpHarnessSuite, st *TcpHarnessScenarioState) {
		s.TcpTestEndpointServerCtl(command)
	})
}

func GetServerStats(dst *TcpTestEndpointStats) TcpHarnessAction {
	return TcpHarnessActionFunc(func(s *TcpHarnessSuite, st *TcpHarnessScenarioState) {
		AssertNotNil(dst)
		*dst = s.TcpTestEndpointServerStatsGet()
	})
}

func WaitServerStats(timeout time.Duration, check func(stats TcpTestEndpointStats) bool,
	dst *TcpTestEndpointStats) TcpHarnessAction {
	return TcpHarnessActionFunc(func(s *TcpHarnessSuite, st *TcpHarnessScenarioState) {
		AssertNotNil(dst)
		*dst = s.WaitForTcpTestEndpointServerStats(timeout, check)
	})
}

func WaitClientStats(timeout time.Duration, check func(stats TcpTestEndpointStats) bool,
	dst *TcpTestEndpointStats) TcpHarnessAction {
	return TcpHarnessActionFunc(func(s *TcpHarnessSuite, st *TcpHarnessScenarioState) {
		AssertNotNil(dst)
		*dst = s.WaitForTcpTestEndpointClientStats(timeout, check)
	})
}

func WaitClientSessionStats(timeout time.Duration,
	check func(stats TcpHarnessClientSessionStats) bool,
	dst *TcpHarnessClientSessionStats) TcpHarnessAction {
	return TcpHarnessActionFunc(func(s *TcpHarnessSuite, st *TcpHarnessScenarioState) {
		AssertNotNil(dst)
		*dst = s.WaitForClientVppSessionStats(timeout, check)
	})
}

func StartClientSend(bytes uint64, handle *TcpHarnessSendHandle) TcpHarnessAction {
	return TcpHarnessActionFunc(func(s *TcpHarnessSuite, st *TcpHarnessScenarioState) {
		AssertNotNil(handle)
		handle.done = s.StartTcpTestEndpointClientSend(bytes)
	})
}

func WaitClientSend(handle *TcpHarnessSendHandle, timeout time.Duration,
	dst *TcpTestEndpointCommandResult) TcpHarnessAction {
	return TcpHarnessActionFunc(func(s *TcpHarnessSuite, st *TcpHarnessScenarioState) {
		AssertNotNil(handle)
		AssertNotNil(dst)
		AssertNotNil(handle.done)

		select {
		case *dst = <-handle.done:
		case <-time.After(timeout):
			AssertEmpty("timed out waiting for tcp_test_endpoint client send")
		}

		if dst.Out != "" {
			Log(dst.Out)
		}
		if dst.Err != nil {
			Log("tcp_test_endpoint client send control exited: %v", dst.Err)
		}
	})
}

func EnableClientNsim(cfg TcpHarnessNsimConfig) TcpHarnessAction {
	return TcpHarnessActionFunc(func(s *TcpHarnessSuite, st *TcpHarnessScenarioState) {
		s.EnableClientNsim(cfg)
	})
}

func DisableClientNsim() TcpHarnessAction {
	return TcpHarnessActionFunc(func(s *TcpHarnessSuite, st *TcpHarnessScenarioState) {
		s.DisableClientNsim()
	})
}

func SleepFor(duration time.Duration) TcpHarnessAction {
	return TcpHarnessActionFunc(func(s *TcpHarnessSuite, st *TcpHarnessScenarioState) {
		time.Sleep(duration)
	})
}

func CloseTcpTestEndpointClient() TcpHarnessAction {
	return TcpHarnessActionFunc(func(s *TcpHarnessSuite, st *TcpHarnessScenarioState) {
		s.CloseTcpTestEndpointClient()
	})
}

func StopClientPcap() TcpHarnessAction {
	return TcpHarnessActionFunc(func(s *TcpHarnessSuite, st *TcpHarnessScenarioState) {
		AssertNotNil(st.ClientPcapTrace)
		st.ClientPcapTrace.Collect()
	})
}

func ReadClientPcap(dst *[]PcapIPv4TCPPacket) TcpHarnessAction {
	return TcpHarnessActionFunc(func(s *TcpHarnessSuite, st *TcpHarnessScenarioState) {
		AssertNotNil(dst)
		packets, err := ReadPcapIPv4TCPPackets(s.GetPcapTracePath(s.Containers.ClientVpp.Name))
		AssertNil(err)
		*dst = packets
	})
}

func RegisterTcpHarnessTests(tests ...func(s *TcpHarnessSuite)) {
	tcpHarnessTests[GetTestFilename()] = tests
}

func (cfg TcpTestEndpointServerConfig) command() string {
	args := []string{
		"tcp_test_endpoint server",
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

func (cfg TcpTestEndpointClientConfig) command() string {
	args := []string{
		"tcp_test_endpoint client",
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

func (cfg TcpHarnessNsimConfig) withDefaults() TcpHarnessNsimConfig {
	if cfg.Delay == "" {
		cfg.Delay = tcpHarnessNsimDefaultDelay
	}
	if cfg.Bandwidth == "" {
		cfg.Bandwidth = tcpHarnessNsimDefaultBandwidth
	}
	if cfg.PacketSize == 0 {
		cfg.PacketSize = tcpHarnessNsimDefaultPacketSize
	}
	return cfg
}

func (cfg TcpHarnessNsimConfig) command() string {
	cfg = cfg.withDefaults()
	return fmt.Sprintf(
		"set nsim poll-main-thread delay %s bandwidth %s packet-size %d packets-per-drop %d packets-per-reorder %d",
		cfg.Delay, cfg.Bandwidth, cfg.PacketSize, cfg.PacketsPerDrop, cfg.PacketsPerReorder)
}

func (cfg TcpHarnessNetemConfig) args(dev string) []string {
	args := []string{"qdisc", "replace", "dev", dev, "root", "netem"}
	delay := cfg.Delay

	if delay == "" && cfg.Reorder != "" {
		delay = tcpHarnessNetemDefaultDelay
	}
	if delay != "" {
		args = append(args, "delay", delay)
	}
	if cfg.Loss != "" {
		args = append(args, "loss", cfg.Loss)
	}
	if cfg.Reorder != "" {
		args = append(args, "reorder", cfg.Reorder)
		if cfg.ReorderCorrelation != "" {
			args = append(args, cfg.ReorderCorrelation)
		}
	}

	return args
}

func (s *TcpHarnessSuite) startTcpTestEndpointServerProcess(c *Container, cfg TcpTestEndpointServerConfig) {
	if cfg.ControlSock == "" {
		cfg.ControlSock = s.TcpTestEndpoint.ControlSock
	}
	if cfg.LogPath == "" {
		cfg.LogPath = s.TcpTestEndpoint.LogPath
	}
	c.ExecServer(false, WrapCmdWithLineBuffering(cfg.command()))
}

func (s *TcpHarnessSuite) tcpTestEndpointVclConfig(c *Container) string {
	var stanza Stanza
	stanza.NewStanza("vcl").
		Append(fmt.Sprintf("app-socket-api %s/var/run/app_ns_sockets/default", c.GetContainerWorkDir())).
		Append("app-scope-global").
		Append("app-scope-local").
		Append("use-mq-eventfd")
	return stanza.Close().ToString()
}

func (s *TcpHarnessSuite) startTcpTestEndpointClientProcess(c *Container, cfg TcpTestEndpointClientConfig) {
	if cfg.ControlSock == "" {
		cfg.ControlSock = s.TcpTestEndpoint.ClientControlSock
	}
	if cfg.LogPath == "" {
		cfg.LogPath = s.TcpTestEndpoint.ClientLogPath
	}

	c.CreateFile("/vcl.conf", s.tcpTestEndpointVclConfig(c))
	c.AddEnvVar("VCL_CONFIG", "/vcl.conf")
	c.ExecServer(true, WrapCmdWithLineBuffering(cfg.command()))
}

func (s *TcpHarnessSuite) StartTcpTestEndpointServer(cfg TcpTestEndpointServerConfig) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = s.Interfaces.Server.Host.Ip4AddressString()
	}
	if cfg.Port == "" {
		cfg.Port = s.Ports.Port1
	}

	s.startTcpTestEndpointServerProcess(s.Containers.ServerApp, cfg)
	s.WaitForTcpTestEndpointServerStats(5*time.Second,
		func(stats TcpTestEndpointStats) bool {
			return !stats.Accepted && stats.Paused == cfg.PauseRead
		})
}

func (s *TcpHarnessSuite) setTcpHarnessNsim(vpp *VppInstance, intf *NetInterface,
	cfg TcpHarnessNsimConfig) {
	intfName := intf.VppName()
	if intfName == "" {
		intfName = intf.Name()
	}
	Log(vpp.Vppctl(cfg.command()))
	Log(vpp.Vppctl("nsim output-feature enable-disable " + intfName))
	Log(vpp.Vppctl("show nsim"))
}

func (s *TcpHarnessSuite) clearTcpHarnessNsim(vpp *VppInstance, intf *NetInterface) {
	if vpp == nil || intf == nil {
		return
	}
	intfName := intf.VppName()
	if intfName == "" {
		intfName = intf.Name()
	}
	Log(vpp.Vppctl("nsim output-feature enable-disable " + intfName + " disable"))
}

func (s *TcpHarnessSuite) EnableClientNsim(cfg TcpHarnessNsimConfig) {
	s.setTcpHarnessNsim(s.Containers.ClientVpp.VppInstance, s.Interfaces.Client, cfg)
	s.Impairments.ClientNsim = true
}

func (s *TcpHarnessSuite) DisableClientNsim() {
	if !s.Impairments.ClientNsim {
		return
	}
	s.clearTcpHarnessNsim(s.Containers.ClientVpp.VppInstance, s.Interfaces.Client)
	s.Impairments.ClientNsim = false
}

func (s *TcpHarnessSuite) EnableServerNsim(cfg TcpHarnessNsimConfig) {
	s.setTcpHarnessNsim(s.Containers.ServerVpp.VppInstance, s.Interfaces.Server, cfg)
	s.Impairments.ServerNsim = true
}

func (s *TcpHarnessSuite) DisableServerNsim() {
	if !s.Impairments.ServerNsim {
		return
	}
	s.clearTcpHarnessNsim(s.Containers.ServerVpp.VppInstance, s.Interfaces.Server)
	s.Impairments.ServerNsim = false
}

func (s *TcpHarnessSuite) setTcpHarnessNetem(intf *NetInterface, cfg TcpHarnessNetemConfig) {
	cmd := exec.Command("tc", cfg.args(intf.Host.Name())...)
	Log(cmd.String())
	o, err := cmd.CombinedOutput()
	AssertNil(err, string(o))
	if len(o) > 0 {
		Log(strings.TrimSpace(string(o)))
	}
}

func (s *TcpHarnessSuite) clearTcpHarnessNetem(intf *NetInterface) {
	if intf == nil {
		return
	}

	cmd := exec.Command("tc", "qdisc", "del", "dev", intf.Host.Name(), "root")
	Log(cmd.String())
	o, err := cmd.CombinedOutput()
	if err != nil && len(o) > 0 {
		Log(strings.TrimSpace(string(o)))
	}
}

func (s *TcpHarnessSuite) EnableClientNetem(cfg TcpHarnessNetemConfig) {
	s.setTcpHarnessNetem(s.Interfaces.Client, cfg)
	s.Impairments.ClientNetem = true
}

func (s *TcpHarnessSuite) DisableClientNetem() {
	if !s.Impairments.ClientNetem {
		return
	}
	s.clearTcpHarnessNetem(s.Interfaces.Client)
	s.Impairments.ClientNetem = false
}

func (s *TcpHarnessSuite) EnableServerNetem(cfg TcpHarnessNetemConfig) {
	s.setTcpHarnessNetem(s.Interfaces.Server, cfg)
	s.Impairments.ServerNetem = true
}

func (s *TcpHarnessSuite) DisableServerNetem() {
	if !s.Impairments.ServerNetem {
		return
	}
	s.clearTcpHarnessNetem(s.Interfaces.Server)
	s.Impairments.ServerNetem = false
}

func (s *TcpHarnessSuite) StartTcpTestEndpointClient(cfg TcpTestEndpointClientConfig) {
	if cfg.ConnectAddr == "" {
		cfg.ConnectAddr = s.Interfaces.Server.Host.Ip4AddressString()
	}
	if cfg.Port == "" {
		cfg.Port = s.Ports.Port1
	}

	s.startTcpTestEndpointClientProcess(s.Containers.ClientApp, cfg)
	s.WaitForTcpTestEndpointClientStats(5*time.Second,
		func(stats TcpTestEndpointStats) bool { return stats.Connected })
}

func (s *TcpHarnessSuite) TcpTestEndpointCtl(c *Container, controlSock string, command TcpTestEndpointCtl) string {
	out, ok := s.TcpTestEndpointCtlTry(c, controlSock, command)
	AssertEqual(true, ok, "failed to execute tcp_test_endpoint control command: %s", command)
	return out
}

func (s *TcpHarnessSuite) TcpTestEndpointCtlTry(c *Container, controlSock string,
	command TcpTestEndpointCtl) (string, bool) {
	o, err := c.Exec(false, "tcp_test_endpoint ctl --control %s %s", controlSock, string(command))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(o), true
}

func (s *TcpHarnessSuite) TcpTestEndpointServerCtl(command TcpTestEndpointCtl) string {
	return s.TcpTestEndpointCtl(s.Containers.ServerApp, s.TcpTestEndpoint.ControlSock, command)
}

func (s *TcpHarnessSuite) TcpTestEndpointServerCtlTry(command TcpTestEndpointCtl) (string, bool) {
	return s.TcpTestEndpointCtlTry(s.Containers.ServerApp, s.TcpTestEndpoint.ControlSock, command)
}

func (s *TcpHarnessSuite) TcpTestEndpointClientCtl(command TcpTestEndpointCtl) string {
	return s.TcpTestEndpointCtl(s.Containers.ClientApp, s.TcpTestEndpoint.ClientControlSock, command)
}

func (s *TcpHarnessSuite) TcpTestEndpointClientCtlTry(command TcpTestEndpointCtl) (string, bool) {
	return s.TcpTestEndpointCtlTry(s.Containers.ClientApp, s.TcpTestEndpoint.ClientControlSock, command)
}

func (s *TcpHarnessSuite) StartTcpTestEndpointClientSend(bytes uint64) <-chan TcpTestEndpointCommandResult {
	done := make(chan TcpTestEndpointCommandResult, 1)

	go func() {
		o, err := s.Containers.ClientApp.Exec(false, "tcp_test_endpoint ctl --control %s %s",
			s.TcpTestEndpoint.ClientControlSock, TcpTestEndpointCtlSend(bytes))
		done <- TcpTestEndpointCommandResult{Out: o, Err: err}
	}()

	return done
}

func (s *TcpHarnessSuite) CloseTcpTestEndpointClient() {
	if out, ok := s.TcpTestEndpointClientCtlTry(TcpTestEndpointCtlClose); ok {
		if out != "" {
			Log("tcp_test_endpoint client close: %s", out)
		}
	} else {
		Log("tcp_test_endpoint client close skipped: control socket is gone")
	}
}

func (s *TcpHarnessSuite) logTcpTestEndpointLog(c *Container, path string) {
	out, err := c.Exec(false, "cat %s", path)
	if err != nil {
		Log("failed to read tcp_test_endpoint log %s: %v", path, err)
		return
	}

	out = strings.TrimSpace(out)
	if out == "" {
		Log("tcp_test_endpoint log is empty: %s", path)
		return
	}

	Log("tcp_test_endpoint log (%s):\n%s", path, out)
}

func (s *TcpHarnessSuite) LogTcpTestEndpointLog(c *Container) {
	s.logTcpTestEndpointLog(c, s.TcpTestEndpoint.LogPath)
}

func (s *TcpHarnessSuite) LogTcpTestEndpointClientLog(c *Container) {
	s.logTcpTestEndpointLog(c, s.TcpTestEndpoint.ClientLogPath)
}

func (s *TcpHarnessSuite) LogTcpTestEndpointLogs() {
	s.LogTcpTestEndpointClientLog(s.Containers.ClientApp)
	s.LogTcpTestEndpointLog(s.Containers.ServerApp)
}

func ParseTcpTestEndpointStats(out string) TcpTestEndpointStats {
	stats := TcpTestEndpointStats{}

	for _, field := range strings.Fields(out) {
		parts := strings.SplitN(field, "=", 2)
		if len(parts) != 2 {
			continue
		}
		switch TcpTestEndpointStat(parts[0]) {
		case TcpTestEndpointStatAccepted:
			stats.Accepted = parts[1] == "1"
		case TcpTestEndpointStatPaused:
			stats.Paused = parts[1] == "1"
		case TcpTestEndpointStatConnected:
			stats.Connected = parts[1] == "1"
		case TcpTestEndpointStatPeerClosed:
			stats.PeerClosed = parts[1] == "1"
		case TcpTestEndpointStatBytesRead:
			v, err := strconv.ParseUint(parts[1], 10, 64)
			AssertNil(err)
			stats.BytesRead = v
		case TcpTestEndpointStatBytesSent:
			v, err := strconv.ParseUint(parts[1], 10, 64)
			AssertNil(err)
			stats.BytesSent = v
		}
	}

	return stats
}

func parseTcpHarnessClientSessionUint(output string, re *regexp.Regexp) uint64 {
	matches := re.FindStringSubmatch(output)
	if len(matches) != 2 {
		return 0
	}

	value, err := strconv.ParseUint(matches[1], 10, 64)
	AssertNil(err)
	return value
}

func ParseClientVppSessionStats(output string) TcpHarnessClientSessionStats {
	isReneging := parseTcpHarnessClientSessionUint(output, tcpHarnessClientSessionRenegRE) != 0

	return TcpHarnessClientSessionStats{
		Output:              output,
		SndMss:              parseTcpHarnessClientSessionUint(output, tcpHarnessClientSessionSndMssRE),
		RtoBackoffCount:     parseTcpHarnessClientSessionUint(output, tcpHarnessClientSessionRtoBoffRE),
		FastRecoveryCount:   parseTcpHarnessClientSessionUint(output, tcpHarnessClientSessionFrRE),
		TimerRecoveryCount:  parseTcpHarnessClientSessionUint(output, tcpHarnessClientSessionTrRE),
		RetransmitSegsCount: parseTcpHarnessClientSessionUint(output, tcpHarnessClientSessionRxtRE),
		SackedBytes:         parseTcpHarnessClientSessionUint(output, tcpHarnessClientSessionSackedRE),
		LostBytes:           parseTcpHarnessClientSessionUint(output, tcpHarnessClientSessionLostRE),
		ScoreboardHoleCount: parseTcpHarnessClientSessionUint(output, tcpHarnessClientSessionHolesRE),
		ReorderThreshold:    parseTcpHarnessClientSessionUint(output, tcpHarnessClientSessionReordRE),
		IsReneging:          isReneging,
	}
}

func (s *TcpHarnessSuite) StartPcapTrace(vpp *VppInstance) *TcpHarnessPcapTrace {
	Log(vpp.Vppctl(fmt.Sprintf(
		"pcap trace rx tx max 10000 max-bytes-per-pkt %d intfc any file vppTest.pcap",
		tcpHarnessPcapMaxBytesPerPkt)))
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

func (s *TcpHarnessSuite) TcpTestEndpointStatsTryGet(c *Container, controlSock string) (TcpTestEndpointStats, bool) {
	out, err := c.Exec(false, "tcp_test_endpoint ctl --control %s %s", controlSock, TcpTestEndpointCtlStats)
	if err != nil {
		return TcpTestEndpointStats{}, false
	}
	return ParseTcpTestEndpointStats(strings.TrimSpace(out)), true
}

func (s *TcpHarnessSuite) TcpTestEndpointStatsGet(c *Container, controlSock string) TcpTestEndpointStats {
	stats, ok := s.TcpTestEndpointStatsTryGet(c, controlSock)
	AssertEqual(true, ok, "failed to query tcp_test_endpoint stats")
	return stats
}

func (s *TcpHarnessSuite) TcpTestEndpointServerStatsGet() TcpTestEndpointStats {
	return s.TcpTestEndpointStatsGet(s.Containers.ServerApp, s.TcpTestEndpoint.ControlSock)
}

func (s *TcpHarnessSuite) TcpTestEndpointClientStatsGet() TcpTestEndpointStats {
	return s.TcpTestEndpointStatsGet(s.Containers.ClientApp, s.TcpTestEndpoint.ClientControlSock)
}

func (s *TcpHarnessSuite) WaitForTcpTestEndpointStats(c *Container, controlSock string,
	timeout time.Duration, check func(stats TcpTestEndpointStats) bool) TcpTestEndpointStats {
	deadline := time.Now().Add(timeout)
	var stats TcpTestEndpointStats

	for time.Now().Before(deadline) {
		if next, ok := s.TcpTestEndpointStatsTryGet(c, controlSock); ok {
			stats = next
			if check(stats) {
				return stats
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	AssertEmpty("timed out waiting for tcp_test_endpoint stats condition")
	return stats
}

func (s *TcpHarnessSuite) WaitForTcpTestEndpointServerStats(timeout time.Duration,
	check func(stats TcpTestEndpointStats) bool) TcpTestEndpointStats {
	return s.WaitForTcpTestEndpointStats(s.Containers.ServerApp, s.TcpTestEndpoint.ControlSock, timeout, check)
}

func (s *TcpHarnessSuite) WaitForTcpTestEndpointClientStats(timeout time.Duration,
	check func(stats TcpTestEndpointStats) bool) TcpTestEndpointStats {
	return s.WaitForTcpTestEndpointStats(s.Containers.ClientApp, s.TcpTestEndpoint.ClientControlSock, timeout, check)
}

func (s *TcpHarnessSuite) ShowClientVppSessions(verbose int) string {
	cmd := "show session"
	if verbose > 0 {
		cmd = fmt.Sprintf("%s verbose %d", cmd, verbose)
	}
	return s.Containers.ClientVpp.VppInstance.Vppctl(cmd)
}

func (s *TcpHarnessSuite) WaitForClientVppSessions(timeout time.Duration,
	check func(output string) bool) string {
	deadline := time.Now().Add(timeout)
	var output string

	for time.Now().Before(deadline) {
		output = s.ShowClientVppSessions(2)
		if check(output) {
			return output
		}
		time.Sleep(100 * time.Millisecond)
	}

	AssertEmpty("timed out waiting for client VPP session condition")
	return output
}

func (s *TcpHarnessSuite) ClientVppSessionStatsGet() TcpHarnessClientSessionStats {
	return ParseClientVppSessionStats(s.ShowClientVppSessions(2))
}

func (s *TcpHarnessSuite) WaitForClientVppSessionStats(timeout time.Duration,
	check func(stats TcpHarnessClientSessionStats) bool) TcpHarnessClientSessionStats {
	deadline := time.Now().Add(timeout)
	var stats TcpHarnessClientSessionStats

	for time.Now().Before(deadline) {
		stats = s.ClientVppSessionStatsGet()
		if check(stats) {
			return stats
		}
		time.Sleep(100 * time.Millisecond)
	}

	AssertEmpty("timed out waiting for client VPP session stats condition")
	return stats
}

func (s *TcpHarnessSuite) StopTcpTestEndpointClient() {
	if out, ok := s.TcpTestEndpointClientCtlTry(TcpTestEndpointCtlShutdown); ok {
		if out != "" {
			Log("tcp_test_endpoint client shutdown: %s", out)
		}
	} else {
		Log("tcp_test_endpoint client shutdown skipped: control socket is gone")
	}
}

func (s *TcpHarnessSuite) StopTcpTestEndpointServer() {
	if out, ok := s.TcpTestEndpointServerCtlTry(TcpTestEndpointCtlShutdown); ok {
		if out != "" {
			Log("tcp_test_endpoint server shutdown: %s", out)
		}
	} else {
		Log("tcp_test_endpoint server shutdown skipped: control socket is gone")
	}
}

func (s *TcpHarnessSuite) StopTcpTestEndpoints() {
	s.StopTcpTestEndpointClient()
	s.StopTcpTestEndpointServer()
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
	s.Impairments = struct {
		ClientNsim  bool
		ServerNsim  bool
		ClientNetem bool
		ServerNetem bool
	}{}
	s.TcpTestEndpoint.ControlSock =
		filepath.Join(s.Containers.ServerApp.GetContainerWorkDir(), "tcp_test_endpoint.sock")
	s.TcpTestEndpoint.LogPath =
		filepath.Join(s.Containers.ServerApp.GetContainerWorkDir(), "tcp_test_endpoint.log")
	s.TcpTestEndpoint.ClientControlSock =
		filepath.Join(s.Containers.ClientApp.GetContainerWorkDir(), "tcp_test_endpoint.sock")
	s.TcpTestEndpoint.ClientLogPath =
		filepath.Join(s.Containers.ClientApp.GetContainerWorkDir(), "tcp_test_endpoint.log")

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
	s.DisableClientNetem()
	s.DisableServerNetem()
	s.DisableClientNsim()
	s.DisableServerNsim()
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

	format, err := pcapByteOrder(data[:4])
	if err != nil {
		return nil, err
	}

	linkType := format.order.Uint32(data[20:24])
	offset := pcapGlobalHeaderLen
	packets := make([]PcapIPv4TCPPacket, 0)

	for offset+pcapRecordHeaderLen <= len(data) {
		tsSec := format.order.Uint32(data[offset : offset+4])
		tsFrac := format.order.Uint32(data[offset+4 : offset+8])
		inclLen := int(format.order.Uint32(data[offset+8 : offset+12]))
		offset += pcapRecordHeaderLen
		if inclLen < 0 || offset+inclLen > len(data) {
			return nil, fmt.Errorf("invalid pcap record length")
		}

		pkt := data[offset : offset+inclLen]
		offset += inclLen

		packet, ok := parsePcapIPv4TCPPacket(linkType, pkt)
		if ok {
			packet.Timestamp = format.timestamp(tsSec, tsFrac)
			packets = append(packets, packet)
		}
	}

	return packets, nil
}

type pcapFormat struct {
	order binary.ByteOrder
	nano  bool
}

func (f pcapFormat) timestamp(sec uint32, frac uint32) time.Time {
	if f.nano {
		return time.Unix(int64(sec), int64(frac))
	}
	return time.Unix(int64(sec), int64(frac)*1000)
}

func pcapByteOrder(magic []byte) (pcapFormat, error) {
	switch binary.BigEndian.Uint32(magic) {
	case 0xa1b2c3d4:
		return pcapFormat{order: binary.BigEndian}, nil
	case 0xa1b23c4d:
		return pcapFormat{order: binary.BigEndian, nano: true}, nil
	case 0xd4c3b2a1:
		return pcapFormat{order: binary.LittleEndian}, nil
	case 0x4d3cb2a1:
		return pcapFormat{order: binary.LittleEndian, nano: true}, nil
	default:
		return pcapFormat{}, fmt.Errorf("unknown pcap magic")
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

	sackBlocks := 0
	for optOff := tcpOptionsOffset; optOff < tcpHdrLen; {
		kind := pkt[tcpOff+optOff]

		switch kind {
		case tcpOptionEnd:
			optOff = tcpHdrLen
		case tcpOptionNoop:
			optOff++
		default:
			if optOff+tcpOptionHeaderLen > tcpHdrLen {
				optOff = tcpHdrLen
				break
			}

			optLen := int(pkt[tcpOff+optOff+1])
			if optLen < tcpOptionHeaderLen || optOff+optLen > tcpHdrLen {
				optOff = tcpHdrLen
				break
			}

			if kind == tcpOptionSack && optLen >= tcpOptionHeaderLen+tcpOptionSackBlockLen {
				sackBlocks = (optLen - tcpOptionHeaderLen) / tcpOptionSackBlockLen
			}
			optOff += optLen
		}
	}

	return PcapIPv4TCPPacket{
		SrcIP: net.IPv4(pkt[l3off+ipv4SrcAddrOffset], pkt[l3off+ipv4SrcAddrOffset+1],
			pkt[l3off+ipv4SrcAddrOffset+2], pkt[l3off+ipv4SrcAddrOffset+3]),
		DstIP: net.IPv4(pkt[l3off+ipv4DstAddrOffset], pkt[l3off+ipv4DstAddrOffset+1],
			pkt[l3off+ipv4DstAddrOffset+2], pkt[l3off+ipv4DstAddrOffset+3]),
		SrcPort:    binary.BigEndian.Uint16(pkt[tcpOff+tcpSrcPortOffset : tcpOff+tcpSrcPortOffset+2]),
		DstPort:    binary.BigEndian.Uint16(pkt[tcpOff+tcpDstPortOffset : tcpOff+tcpDstPortOffset+2]),
		Seq:        binary.BigEndian.Uint32(pkt[tcpOff+tcpSeqOffset : tcpOff+tcpSeqOffset+4]),
		Ack:        binary.BigEndian.Uint32(pkt[tcpOff+tcpAckOffset : tcpOff+tcpAckOffset+4]),
		Flags:      pkt[tcpOff+tcpFlagsOffset],
		SackBlocks: sackBlocks,
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
