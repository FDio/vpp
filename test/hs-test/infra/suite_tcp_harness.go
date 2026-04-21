/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

package hst

import (
	"fmt"
	"net"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	tcpharness "fd.io/hs-test/infra/tcpharness"

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
		ServerNFQueue bool
		ServerAckGate bool
		ServerScript  bool
	}
	NFQueue struct {
		Server        *tcpharness.NFQueueHelper
		ServerAckGate *tcpharness.NFQueueHelper
		ServerScript  *tcpharness.NFQueueController
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

type TcpTestEndpointCtl string

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
	tcpHarnessPcapMaxBytesPerPkt   = 2000
	tcpTestEndpointShutdownTimeout = "2s"

	TcpTestEndpointCtlStats      TcpTestEndpointCtl = "stats"
	TcpTestEndpointCtlShutdown   TcpTestEndpointCtl = "shutdown"
	TcpTestEndpointCtlClose      TcpTestEndpointCtl = "close"
	TcpTestEndpointCtlResumeRead TcpTestEndpointCtl = "resume-read"
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

func (s *TcpHarnessSuite) ClientServerFlow() tcpharness.Flow {
	port, err := strconv.ParseUint(s.Ports.Port1, 10, 16)
	AssertNil(err)
	return tcpharness.NewFlow(
		s.Interfaces.Client.Ip4AddressString(),
		s.Interfaces.Server.Host.Ip4AddressString(),
		uint16(port))
}

func IsAccepted(stats TcpTestEndpointStats) bool {
	return stats.Accepted
}

func IsPeerClosed(stats TcpTestEndpointStats) bool {
	return stats.PeerClosed
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

func (fn TcpHarnessActionFunc) Run(s *TcpHarnessSuite, st *TcpHarnessScenarioState) {
	fn(s, st)
}

func waitWithTimeout(timeout, poll time.Duration, step func() bool) bool {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if step() {
			return true
		}
		time.Sleep(poll)
	}

	return false
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
			AssertFail("timed out waiting for tcp_test_endpoint client send")
		}

		if dst.Out != "" {
			Log(dst.Out)
		}
		if dst.Err != nil {
			Log("tcp_test_endpoint client send control exited: %v", dst.Err)
		}
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

func ReadClientPcap(dst *[]tcpharness.PcapIPv4TCPPacket) TcpHarnessAction {
	return TcpHarnessActionFunc(func(s *TcpHarnessSuite, st *TcpHarnessScenarioState) {
		AssertNotNil(dst)
		packets, err := tcpharness.ReadPcapIPv4TCPPackets(s.GetPcapTracePath(s.Containers.ClientVpp.Name))
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

func (s *TcpHarnessSuite) WaitForTcpTestEndpointCtl(c *Container, controlSock string,
	command TcpTestEndpointCtl, timeout time.Duration) string {
	var out string

	if waitWithTimeout(timeout, 100*time.Millisecond, func() bool {
		var ok bool

		out, ok = s.TcpTestEndpointCtlTry(c, controlSock, command)
		return ok
	}) {
		return out
	}

	AssertFail("timed out executing tcp_test_endpoint control command: %s", command)
	return out
}

func (s *TcpHarnessSuite) tcpTestEndpointCtlTry(c *Container, controlSock string,
	command TcpTestEndpointCtl, timeout string) (string, bool) {
	cmd := "tcp_test_endpoint ctl --control %s %s"
	args := []any{controlSock, string(command)}
	if timeout != "" {
		cmd = "timeout %s " + cmd
		args = append([]any{timeout}, args...)
	}

	o, err := c.Exec(false, cmd, args...)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(o), true
}

func (s *TcpHarnessSuite) TcpTestEndpointCtlTry(c *Container, controlSock string,
	command TcpTestEndpointCtl) (string, bool) {
	return s.tcpTestEndpointCtlTry(c, controlSock, command, "")
}

func (s *TcpHarnessSuite) TcpTestEndpointServerCtl(command TcpTestEndpointCtl) string {
	return s.TcpTestEndpointCtl(s.Containers.ServerApp, s.TcpTestEndpoint.ControlSock, command)
}

func (s *TcpHarnessSuite) WaitForTcpTestEndpointServerCtl(command TcpTestEndpointCtl, timeout time.Duration) string {
	return s.WaitForTcpTestEndpointCtl(s.Containers.ServerApp, s.TcpTestEndpoint.ControlSock, command, timeout)
}

func (s *TcpHarnessSuite) TcpTestEndpointServerCtlTry(command TcpTestEndpointCtl) (string, bool) {
	return s.TcpTestEndpointCtlTry(s.Containers.ServerApp, s.TcpTestEndpoint.ControlSock, command)
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

func (s *TcpHarnessSuite) LogTcpTestEndpointLogs() {
	s.logTcpTestEndpointLog(s.Containers.ClientApp, s.TcpTestEndpoint.ClientLogPath)
	s.logTcpTestEndpointLog(s.Containers.ServerApp, s.TcpTestEndpoint.LogPath)
}

func ParseTcpTestEndpointStats(out string) TcpTestEndpointStats {
	stats := TcpTestEndpointStats{}

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
	out, ok := s.TcpTestEndpointCtlTry(c, controlSock, TcpTestEndpointCtlStats)
	if !ok {
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

func (s *TcpHarnessSuite) WaitForTcpTestEndpointStats(c *Container, controlSock string,
	timeout time.Duration, check func(stats TcpTestEndpointStats) bool) TcpTestEndpointStats {
	var (
		stats       TcpTestEndpointStats
		statsSeen   bool
		lastQueryOK bool
	)

	if waitWithTimeout(timeout, 100*time.Millisecond, func() bool {
		if next, ok := s.TcpTestEndpointStatsTryGet(c, controlSock); ok {
			stats = next
			statsSeen = true
			lastQueryOK = true
			return check(stats)
		}
		lastQueryOK = false
		return false
	}) {
		return stats
	}

	Log("last tcp_test_endpoint stats while waiting on %s: seen=%v last_query_ok=%v stats=%+v",
		controlSock, statsSeen, lastQueryOK, stats)
	s.LogTcpTestEndpointLogs()
	s.logVppTcpSessionState("server", s.Containers.ServerVpp.VppInstance)
	s.logVppTcpSessionState("client", s.Containers.ClientVpp.VppInstance)
	AssertFail(
		"timed out waiting for tcp_test_endpoint stats condition on %s; seen=%v last_query_ok=%v last_stats=%+v",
		controlSock, statsSeen, lastQueryOK, stats)
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

func (s *TcpHarnessSuite) ClientVppSessionStatsGet() TcpHarnessClientSessionStats {
	return ParseClientVppSessionStats(s.ShowClientVppSessions(2))
}

func (s *TcpHarnessSuite) WaitForClientVppSessionStats(timeout time.Duration,
	check func(stats TcpHarnessClientSessionStats) bool) TcpHarnessClientSessionStats {
	var stats TcpHarnessClientSessionStats

	if waitWithTimeout(timeout, 100*time.Millisecond, func() bool {
		stats = s.ClientVppSessionStatsGet()
		return check(stats)
	}) {
		return stats
	}

	Log("last client show session verbose 2 while waiting for session stats condition:\n%s",
		stats.Output)
	AssertFail("timed out waiting for client VPP session stats condition")
	return stats
}

func (s *TcpHarnessSuite) stopTcpTestEndpoint(role string, c *Container, controlSock string) {
	if out, ok := s.tcpTestEndpointCtlTry(c, controlSock, TcpTestEndpointCtlShutdown,
		tcpTestEndpointShutdownTimeout); ok {
		if out != "" {
			Log("tcp_test_endpoint %s shutdown: %s", role, out)
		}
	} else {
		Log("tcp_test_endpoint %s shutdown failed; terminating process", role)
		if _, err := c.Exec(false,
			"sh -c 'pids=$(pidof tcp_test_endpoint) || exit 0; kill -TERM $pids; "+
				"sleep 1; pids=$(pidof tcp_test_endpoint) || exit 0; kill -KILL $pids'"); err != nil {
			Log("tcp_test_endpoint %s termination failed: %v", role, err)
		}
	}
}

func (s *TcpHarnessSuite) StopTcpTestEndpointClient() {
	s.stopTcpTestEndpoint("client", s.Containers.ClientApp, s.TcpTestEndpoint.ClientControlSock)
}

func (s *TcpHarnessSuite) StopTcpTestEndpointServer() {
	s.stopTcpTestEndpoint("server", s.Containers.ServerApp, s.TcpTestEndpoint.ControlSock)
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
		ServerNFQueue bool
		ServerAckGate bool
		ServerScript  bool
	}{}
	s.NFQueue.Server = nil
	s.NFQueue.ServerAckGate = nil
	s.NFQueue.ServerScript = nil
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
	s.DisableServerNFQueueScript()
	s.DisableServerNFQueue()
	s.DisableServerAckGate()
	if CurrentSpecReport().Failed() {
		s.logServerNFQueueScriptFailure()
		s.logVppFailureState("server", s.Containers.ServerVpp.VppInstance)
		s.logVppFailureState("client", s.Containers.ClientVpp.VppInstance)
	}
}

func (s *TcpHarnessSuite) logVppFailureState(role string, vpp *VppInstance) {
	s.logVppTcpSessionState(role, vpp)
	Log("%s VPP show error verbose:\n%s", role, vpp.Vppctl("show error verbose"))
}

func (s *TcpHarnessSuite) logVppTcpSessionState(role string, vpp *VppInstance) {
	Log("%s VPP show session verbose 2:\n%s", role, vpp.Vppctl("show session verbose 2"))
	Log("%s VPP show tcp stats:\n%s", role, vpp.Vppctl("show tcp stats"))
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

func EnableServerNFQueue(cfg tcpharness.NFQueueConfig) TcpHarnessAction {
	return TcpHarnessActionFunc(func(s *TcpHarnessSuite, st *TcpHarnessScenarioState) {
		s.EnableServerNFQueue(cfg)
	})
}

func DisableServerNFQueue() TcpHarnessAction {
	return TcpHarnessActionFunc(func(s *TcpHarnessSuite, st *TcpHarnessScenarioState) {
		s.DisableServerNFQueue()
	})
}

func StopServerNFQueueDrops() TcpHarnessAction {
	return TcpHarnessActionFunc(func(s *TcpHarnessSuite, st *TcpHarnessScenarioState) {
		s.StopServerNFQueueDrops()
	})
}

func WaitServerNFQueueDrops(timeout time.Duration, count uint32) TcpHarnessAction {
	return TcpHarnessActionFunc(func(s *TcpHarnessSuite, st *TcpHarnessScenarioState) {
		s.WaitForServerNFQueueDrops(timeout, count)
	})
}

func WaitServerNFQueueRetransmits(timeout time.Duration, count uint32,
	stats *tcpharness.NFQueueStats) TcpHarnessAction {
	return TcpHarnessActionFunc(func(s *TcpHarnessSuite, st *TcpHarnessScenarioState) {
		current := s.WaitForServerNFQueueRetransmits(timeout, count)
		if stats != nil {
			*stats = current
		}
	})
}

func EnableServerNFQueueScript(cfg tcpharness.NFQueueScriptConfig) TcpHarnessAction {
	return TcpHarnessActionFunc(func(s *TcpHarnessSuite, st *TcpHarnessScenarioState) {
		s.EnableServerNFQueueScript(cfg)
	})
}

func DisableServerNFQueueScript() TcpHarnessAction {
	return TcpHarnessActionFunc(func(s *TcpHarnessSuite, st *TcpHarnessScenarioState) {
		s.DisableServerNFQueueScript()
	})
}

func WaitServerNFQueueScriptStats(timeout time.Duration,
	check func(tcpharness.NFQueueScriptStats) bool, stats *tcpharness.NFQueueScriptStats) TcpHarnessAction {
	return TcpHarnessActionFunc(func(s *TcpHarnessSuite, st *TcpHarnessScenarioState) {
		current := s.WaitForServerNFQueueScriptStats(timeout, check)
		if stats != nil {
			*stats = current
		}
	})
}

func WaitServerNFQueueScriptDone(timeout time.Duration, stats *tcpharness.NFQueueScriptStats,
	trace *[]tcpharness.NFQueueScriptTraceEntry) TcpHarnessAction {
	return TcpHarnessActionFunc(func(s *TcpHarnessSuite, st *TcpHarnessScenarioState) {
		current := s.WaitForServerNFQueueScriptStats(timeout, func(stats tcpharness.NFQueueScriptStats) bool {
			return stats.Stage == tcpharness.NFQueueScriptStageDone
		})
		if stats != nil {
			*stats = current
		}
		if trace != nil {
			*trace = s.ServerNFQueueScriptTraceGet()
		}
	})
}

func (s *TcpHarnessSuite) defaultServerNFQueueConfig(cfg tcpharness.NFQueueConfig) tcpharness.NFQueueConfig {
	if cfg.QueueNum == 0 {
		port, err := strconv.ParseUint(s.Ports.Port1, 10, 16)
		AssertNil(err)
		cfg.QueueNum = uint16(port)
	}
	if cfg.InputIf == "" {
		cfg.InputIf = s.Interfaces.Client.Host.Name()
	}
	if cfg.SrcIP == "" {
		cfg.SrcIP = s.Interfaces.Client.Ip4AddressString()
	}
	if cfg.DstIP == "" {
		cfg.DstIP = s.Interfaces.Server.Host.Ip4AddressString()
	}
	if cfg.DstPort == 0 {
		port, err := strconv.ParseUint(s.Ports.Port1, 10, 16)
		AssertNil(err)
		cfg.DstPort = uint16(port)
	}
	return cfg
}

func (s *TcpHarnessSuite) defaultServerAckGateConfig(cfg tcpharness.NFQueueConfig) tcpharness.NFQueueConfig {
	if cfg.QueueNum == 0 {
		port, err := strconv.ParseUint(s.Ports.Port1, 10, 16)
		AssertNil(err)
		cfg.QueueNum = uint16(port + 10000)
	}
	if cfg.OutputIf == "" {
		cfg.OutputIf = s.Interfaces.Client.Host.Name()
	}
	if cfg.SrcIP == "" {
		cfg.SrcIP = s.Interfaces.Server.Host.Ip4AddressString()
	}
	if cfg.DstIP == "" {
		cfg.DstIP = s.Interfaces.Client.Ip4AddressString()
	}
	if cfg.SrcPort == 0 {
		port, err := strconv.ParseUint(s.Ports.Port1, 10, 16)
		AssertNil(err)
		cfg.SrcPort = uint16(port)
	}
	cfg.DropAckOnlyPackets = true
	return cfg
}

func (s *TcpHarnessSuite) defaultServerNFQueueScriptConfig(
	cfg tcpharness.NFQueueScriptConfig) tcpharness.NFQueueScriptConfig {
	return cfg.WithDefaults()
}

func (s *TcpHarnessSuite) EnableServerNFQueue(cfg tcpharness.NFQueueConfig) {
	s.DisableServerNFQueue()

	cfg = s.defaultServerNFQueueConfig(cfg)
	helper, err := tcpharness.NewNFQueueHelper(cfg, Log)
	AssertNil(err)

	s.NFQueue.Server = helper
	s.Impairments.ServerNFQueue = true
}

func (s *TcpHarnessSuite) EnableServerNFQueueScript(cfg tcpharness.NFQueueScriptConfig) {
	s.DisableServerNFQueueScript()
	s.DisableServerNFQueue()
	s.DisableServerAckGate()

	scriptCfg := s.defaultServerNFQueueScriptConfig(cfg)
	ingressCfg := s.defaultServerNFQueueConfig(tcpharness.NFQueueConfig{
		DropDataPacketIndices: scriptCfg.DropDataPacketIndices(),
	})
	ackGateCfg := s.defaultServerAckGateConfig(tcpharness.NFQueueConfig{})

	controller, err := tcpharness.NewNFQueueController(scriptCfg, ingressCfg, ackGateCfg, Log)
	AssertNil(err)

	s.NFQueue.ServerScript = controller
	s.NFQueue.Server = controller.Ingress()
	s.NFQueue.ServerAckGate = controller.AckGate()
	s.Impairments.ServerScript = true
	s.Impairments.ServerNFQueue = true
	s.Impairments.ServerAckGate = true
}

func (s *TcpHarnessSuite) serverNFQueueScriptSnapshotGet() (tcpharness.NFQueueScriptStats,
	[]tcpharness.NFQueueScriptTraceEntry, error) {
	AssertNotNil(s.NFQueue.ServerScript)

	stats, statsErr := s.NFQueue.ServerScript.CurrentStats()
	trace, traceErr := s.NFQueue.ServerScript.CurrentTrace()
	if statsErr != nil {
		return stats, trace, statsErr
	}
	return stats, trace, traceErr
}

func (s *TcpHarnessSuite) ServerNFQueueScriptStatsGet() tcpharness.NFQueueScriptStats {
	stats, trace, err := s.serverNFQueueScriptSnapshotGet()
	if err != nil {
		s.LogServerNFQueueScriptSnapshot(stats, trace)
	}
	AssertNil(err)
	return stats
}

func (s *TcpHarnessSuite) ServerNFQueueScriptTraceGet() []tcpharness.NFQueueScriptTraceEntry {
	stats, trace, err := s.serverNFQueueScriptSnapshotGet()
	if err != nil {
		s.LogServerNFQueueScriptSnapshot(stats, trace)
	}
	AssertNil(err)
	return trace
}

type tcpHarnessNFQueueTraceBases struct {
	clientDataBase uint32
	serverSeqBase  uint32
	hasClientBase  bool
	hasServerBase  bool
}

func deriveTcpHarnessNFQueueTraceBases(stats tcpharness.NFQueueScriptStats,
	trace []tcpharness.NFQueueScriptTraceEntry) tcpHarnessNFQueueTraceBases {
	var bases tcpHarnessNFQueueTraceBases

	for _, segment := range stats.ResolvedSegments {
		if !bases.hasClientBase || segment.Seq < bases.clientDataBase {
			bases.clientDataBase = segment.Seq
			bases.hasClientBase = true
		}
	}

	for _, entry := range trace {
		switch entry.Kind {
		case tcpharness.NFQueueScriptTraceDataSegmentObserved,
			tcpharness.NFQueueScriptTraceOriginalDataDrop,
			tcpharness.NFQueueScriptTraceRetransmitObserved:
			if !bases.hasClientBase || entry.Seq < bases.clientDataBase {
				bases.clientDataBase = entry.Seq
				bases.hasClientBase = true
			}
		case tcpharness.NFQueueScriptTraceNaturalAckQueued,
			tcpharness.NFQueueScriptTraceNaturalAckDropped,
			tcpharness.NFQueueScriptTraceQueuedAckReplayed,
			tcpharness.NFQueueScriptTraceQueuedAckDiscarded:
			if !bases.hasServerBase || entry.Seq < bases.serverSeqBase {
				bases.serverSeqBase = entry.Seq
				bases.hasServerBase = true
			}
		}
	}

	return bases
}

func formatTcpHarnessNFQueueTraceValue(relative uint32, absolute uint32, hasBase bool) string {
	if !hasBase {
		return fmt.Sprintf("%d", absolute)
	}
	return fmt.Sprintf("%d", relative)
}

func formatTcpHarnessNFQueueTraceSeqAck(entry tcpharness.NFQueueScriptTraceEntry,
	bases tcpHarnessNFQueueTraceBases) (string, string) {
	var seqText, ackText string

	switch entry.Kind {
	case tcpharness.NFQueueScriptTraceDataSegmentObserved,
		tcpharness.NFQueueScriptTraceOriginalDataDrop,
		tcpharness.NFQueueScriptTraceRetransmitObserved:
		seqText = formatTcpHarnessNFQueueTraceValue(entry.Seq-bases.clientDataBase, entry.Seq, bases.hasClientBase)
		ackText = formatTcpHarnessNFQueueTraceValue(entry.Ack-bases.serverSeqBase, entry.Ack, bases.hasServerBase)
	case tcpharness.NFQueueScriptTraceNaturalAckQueued,
		tcpharness.NFQueueScriptTraceNaturalAckDropped,
		tcpharness.NFQueueScriptTraceQueuedAckReplayed,
		tcpharness.NFQueueScriptTraceQueuedAckDiscarded:
		seqText = formatTcpHarnessNFQueueTraceValue(entry.Seq-bases.serverSeqBase, entry.Seq, bases.hasServerBase)
		ackText = formatTcpHarnessNFQueueTraceValue(entry.Ack-bases.clientDataBase, entry.Ack, bases.hasClientBase)
	case tcpharness.NFQueueScriptTraceSyntheticAckInjected:
		seqText = "-"
		ackText = formatTcpHarnessNFQueueTraceValue(entry.Ack-bases.clientDataBase, entry.Ack, bases.hasClientBase)
	default:
		seqText = "-"
		ackText = "-"
	}

	return seqText, ackText
}

func formatTcpHarnessNFQueueTraceDetail(entry tcpharness.NFQueueScriptTraceEntry,
	bases tcpHarnessNFQueueTraceBases) string {
	if entry.Kind != tcpharness.NFQueueScriptTraceDataSegmentObserved {
		return entry.Detail
	}

	var end uint32
	var payload int
	if _, err := fmt.Sscanf(entry.Detail, "segment end=%d payload=%d", &end, &payload); err != nil {
		return entry.Detail
	}

	return fmt.Sprintf("segment end=%s payload=%d",
		formatTcpHarnessNFQueueTraceValue(end-bases.clientDataBase, end, bases.hasClientBase), payload)
}

func formatTcpHarnessNFQueueTraceKind(kind tcpharness.NFQueueScriptTraceEventKind) string {
	switch kind {
	case tcpharness.NFQueueScriptTraceDataSegmentObserved:
		return "data-seen"
	case tcpharness.NFQueueScriptTraceOriginalDataDrop:
		return "orig-drop"
	case tcpharness.NFQueueScriptTraceRetransmitObserved:
		return "retransmit"
	case tcpharness.NFQueueScriptTraceNaturalAckQueued:
		return "ack-queued"
	case tcpharness.NFQueueScriptTraceNaturalAckDropped:
		return "ack-dropped"
	case tcpharness.NFQueueScriptTraceSyntheticAckInjected:
		return "ack-injected"
	case tcpharness.NFQueueScriptTraceQueuedAckReplayed:
		return "ack-replayed"
	case tcpharness.NFQueueScriptTraceQueuedAckDiscarded:
		return "ack-discarded"
	case tcpharness.NFQueueScriptTraceStageAdvanced:
		return "stage"
	case tcpharness.NFQueueScriptTraceGateReleased:
		return "gate-release"
	default:
		return fmt.Sprintf("kind-%d", kind)
	}
}

func (s *TcpHarnessSuite) LogServerNFQueueScriptSnapshot(stats tcpharness.NFQueueScriptStats,
	trace []tcpharness.NFQueueScriptTraceEntry) {
	bases := deriveTcpHarnessNFQueueTraceBases(stats, trace)

	Log("scripted NFQUEUE stats: %+v", stats)
	if bases.hasClientBase {
		Log("scripted NFQUEUE client seq base: seq_base=%d client_iss=%d",
			bases.clientDataBase, bases.clientDataBase-1)
	} else {
		Log("scripted NFQUEUE client seq base: unavailable")
	}
	if bases.hasServerBase {
		Log("scripted NFQUEUE server seq base: seq_base=%d server_iss=%d",
			bases.serverSeqBase, bases.serverSeqBase-1)
	} else {
		Log("scripted NFQUEUE server seq base: unavailable")
	}
	for i, entry := range trace {
		seqText, ackText := formatTcpHarnessNFQueueTraceSeqAck(entry, bases)
		detail := formatTcpHarnessNFQueueTraceDetail(entry, bases)
		Log("script trace[%d]: kind=%-13s stage=%d\tseq=%-8s\tack=%-8s\tdetail=%s",
			i, formatTcpHarnessNFQueueTraceKind(entry.Kind), entry.Stage, seqText, ackText, detail)
	}
}

func (s *TcpHarnessSuite) DisableServerNFQueueScript() {
	if !s.Impairments.ServerScript || s.NFQueue.ServerScript == nil {
		return
	}
	s.NFQueue.ServerScript.Close()
	s.NFQueue.ServerScript = nil
	s.NFQueue.Server = nil
	s.NFQueue.ServerAckGate = nil
	s.Impairments.ServerScript = false
	s.Impairments.ServerNFQueue = false
	s.Impairments.ServerAckGate = false
}

func (s *TcpHarnessSuite) DisableServerNFQueue() {
	if !s.Impairments.ServerNFQueue || s.NFQueue.Server == nil {
		return
	}
	s.NFQueue.Server.Close()
	s.NFQueue.Server = nil
	s.Impairments.ServerNFQueue = false
}

func (s *TcpHarnessSuite) StopServerNFQueueDrops() {
	AssertNotNil(s.NFQueue.Server)
	s.NFQueue.Server.StopDrops()
}

func (s *TcpHarnessSuite) DisableServerAckGate() {
	if !s.Impairments.ServerAckGate || s.NFQueue.ServerAckGate == nil {
		return
	}
	s.NFQueue.ServerAckGate.Close()
	s.NFQueue.ServerAckGate = nil
	s.Impairments.ServerAckGate = false
}

func (s *TcpHarnessSuite) WaitForServerNFQueueScriptStats(timeout time.Duration,
	check func(tcpharness.NFQueueScriptStats) bool) tcpharness.NFQueueScriptStats {
	var (
		current tcpharness.NFQueueScriptStats
		trace   []tcpharness.NFQueueScriptTraceEntry
		err     error
	)

	if waitWithTimeout(timeout, 50*time.Millisecond, func() bool {
		current, trace, err = s.serverNFQueueScriptSnapshotGet()
		if err != nil {
			return true
		}
		return check(current)
	}) {
		if err == nil {
			return current
		}
		s.LogServerNFQueueScriptSnapshot(current, trace)
		AssertNil(err)
		return tcpharness.NFQueueScriptStats{}
	}

	s.LogServerNFQueueScriptSnapshot(current, trace)
	AssertFail("timed out waiting for scripted NFQUEUE stats predicate")
	return tcpharness.NFQueueScriptStats{}
}

func (s *TcpHarnessSuite) WaitForServerNFQueueDrops(timeout time.Duration, count uint32) {
	AssertNotNil(s.NFQueue.Server)

	var (
		drops uint32
		seqs  []uint32
		err   error
	)

	if waitWithTimeout(timeout, 50*time.Millisecond, func() bool {
		drops, seqs, err = s.NFQueue.Server.CurrentState()
		AssertNil(err)
		return drops >= count
	}) {
		return
	}

	Log("last NFQUEUE state: drops=%d dropped_seqs=%v", drops, seqs)
	AssertFail("timed out waiting for NFQUEUE to drop %d packets", count)
}

func (s *TcpHarnessSuite) WaitForServerNFQueueRetransmits(timeout time.Duration,
	count uint32) tcpharness.NFQueueStats {
	AssertNotNil(s.NFQueue.Server)

	var (
		stats tcpharness.NFQueueStats
		err   error
	)

	if waitWithTimeout(timeout, 50*time.Millisecond, func() bool {
		stats, err = s.NFQueue.Server.CurrentStats()
		AssertNil(err)
		return stats.RetransmitCount >= count
	}) {
		return stats
	}

	Log("last NFQUEUE stats: %+v", stats)
	AssertFail("timed out waiting for NFQUEUE to observe %d retransmits", count)
	return tcpharness.NFQueueStats{}
}

func (s *TcpHarnessSuite) logServerNFQueueScriptFailure() {
	if s.NFQueue.ServerScript == nil {
		return
	}

	stats, trace, _ := s.serverNFQueueScriptSnapshotGet()
	s.LogServerNFQueueScriptSnapshot(stats, trace)
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
