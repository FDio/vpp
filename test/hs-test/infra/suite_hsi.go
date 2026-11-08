package hst

import (
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
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
var hsiMWTests = map[string][]func(s *HsiSuite){}

func RegisterHsiTests(tests ...func(s *HsiSuite)) {
	hsiTests[GetTestFilename()] = tests
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
	AssertNil(vpp.CreateTap(s.Interfaces.Client, false, 1))
	AssertNil(vpp.CreateTap(s.Interfaces.Server, false, 2))

	// Give each TAP stable ingress ownership in multi-worker tests.
	if vpp.CpuConfig.NumWorkers >= 2 {
		for queueID := range vpp.CpuConfig.NumWorkers {
			Log(vpp.Vppctl("set interface rx-placement %s queue %d worker 0",
				s.Interfaces.Client.VppName(), queueID))
			Log(vpp.Vppctl("set interface rx-placement %s queue %d worker 1",
				s.Interfaces.Server.VppName(), queueID))
		}
	}

	Log(vpp.Vppctl("set interface feature " + s.Interfaces.Client.VppName() + " hsi4-in arc ip4-unicast"))
	Log(vpp.Vppctl("set interface feature " + s.Interfaces.Server.VppName() + " hsi4-in arc ip4-unicast"))

	s.setupVppIpv6(vpp)

	if *DryRun {
		s.LogStartedContainers()
		s.Skip("Dry run mode = true")
	}

	s.setupHostIpv6()

	// let the host know howto get to the server
	cmd := exec.Command("ip", "netns", "exec", s.NetNamespaces.Client, "ip", "route", "replace",
		s.ServerAddr(), "via", s.Interfaces.Client.Ip4AddressString())
	Log(cmd.String())
	_, err = cmd.CombinedOutput()
	AssertNil(err, fmt.Sprint(err))
}

func (s *HsiSuite) setupVppIpv6(vpp *VppInstance) {
	s.setupVppInterfaceIpv6(vpp, s.Interfaces.Client)
	s.setupVppInterfaceIpv6(vpp, s.Interfaces.Server)

	Log(vpp.Vppctl("set interface feature " + s.Interfaces.Client.VppName() + " hsi6-in arc ip6-unicast"))
	Log(vpp.Vppctl("set interface feature " + s.Interfaces.Server.VppName() + " hsi6-in arc ip6-unicast"))
}

func (s *HsiSuite) setupHostIpv6() {
	s.setupHostInterfaceIpv6(s.Interfaces.Client)
	s.setupHostInterfaceIpv6(s.Interfaces.Server)

	cmd := exec.Command("ip", "netns", "exec", s.NetNamespaces.Client, "ip", "-6", "route", "replace",
		s.ServerAddr6(), "via", s.Interfaces.Client.Ip6AddressString(), "dev",
		s.Interfaces.Client.Host.Name(), "src", s.Interfaces.Client.Host.Ip6AddressString())
	Log(cmd.String())
	output, err := cmd.CombinedOutput()
	AssertNil(err, string(output))
}

func (s *HsiSuite) setupVppInterfaceIpv6(vpp *VppInstance, intf *NetInterface) {
	var err error

	if intf.Ip6AddrAllocator == nil {
		intf.Ip6AddrAllocator = s.Ip6AddrAllocator
	}
	if intf.Host.Ip6AddrAllocator == nil {
		intf.Host.Ip6AddrAllocator = s.Ip6AddrAllocator
	}
	if intf.Ip6Address == "" {
		intf.Ip6Address, err = intf.Ip6AddrAllocator.NewIp6InterfaceAddress(intf.Host.NetworkNumber)
		AssertNil(err, fmt.Sprint(err))
	}
	if intf.Host.Ip6Address == "" {
		intf.Host.Ip6Address, err = intf.Host.Ip6AddrAllocator.NewIp6InterfaceAddress(intf.Host.NetworkNumber)
		AssertNil(err, fmt.Sprint(err))
	}

	Log(vpp.Vppctl("set interface ip address %s %s", intf.VppName(), intf.Ip6Address))
}

// setupHostInterfaceIpv6 reapplies the host-side IPv6 address, which is lost
// when the TAP is recreated. CreateTap only waits for DAD to finish on TAPs
// created as IPv6, so wait here before applications use the address.
func (s *HsiSuite) setupHostInterfaceIpv6(intf *NetInterface) {
	cmd := appendNetns([]string{"ip", "-6", "addr", "replace", intf.Host.Ip6Address, "dev",
		intf.Host.Name(), "nodad"}, intf.Host.NetworkNamespace)
	output, err := cmd.CombinedOutput()
	AssertNil(err, string(output))

	for range 50 {
		cmd = appendNetns([]string{"ip", "-6", "addr", "show", "dev",
			intf.Host.Name(), "tentative"}, intf.Host.NetworkNamespace)
		output, err = cmd.CombinedOutput()
		AssertNil(err, string(output))
		if !strings.Contains(string(output), intf.Host.Ip6AddressString()) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	AssertNotContains(string(output), intf.Host.Ip6AddressString(),
		"host IPv6 address remained tentative")
}

func (s *HsiSuite) TeardownTest() {
	defer s.HstSuite.TeardownTest()
	vpp := s.Containers.Vpp.VppInstance
	if CurrentSpecReport().Failed() {
		Log(vpp.Vppctl("show session verbose 2"))
		Log(vpp.Vppctl("show interface"))
		Log(vpp.Vppctl("show error"))
		Log(vpp.Vppctl("show tcp stats"))
		Log(vpp.Vppctl("show proxy-lite"))
		Log(vpp.Vppctl("show hsi"))
		CollectNginxLogs(s.Containers.NginxServerTransient)
	}
}

func (s *HsiSuite) setupNginxServer(listenIp6 bool) {
	AssertNil(s.Containers.NginxServerTransient.Create())
	nginxSettings := struct {
		LogPrefix string
		Address   string
		Port      uint16
		PortSsl   uint16
		Http2     string
		Timeout   int
		ListenIp6 bool
	}{
		LogPrefix: s.Containers.NginxServerTransient.Name,
		Address:   s.ServerAddr(),
		Port:      s.Ports.Server,
		PortSsl:   s.Ports.ServerSsl,
		Http2:     "off",
		Timeout:   s.maxTimeout,
		ListenIp6: listenIp6,
	}
	s.Containers.NginxServerTransient.CreateConfigFromTemplate(
		"/nginx.conf",
		"./resources/nginx/nginx_server.conf",
		nginxSettings,
	)
	AssertNil(s.Containers.NginxServerTransient.Start())
}

func (s *HsiSuite) SetupNginxServer() {
	s.setupNginxServer(false)
}

func (s *HsiSuite) SetupNginxServerIp6() {
	s.setupNginxServer(true)
}

func (s *HsiSuite) ServerAddr() string {
	return s.Interfaces.Server.Host.Ip4AddressString()
}

func (s *HsiSuite) ServerAddr6() string {
	return s.Interfaces.Server.Host.Ip6AddressString()
}

func HsiUriHost(addr string) string {
	if strings.Contains(addr, ":") {
		return "[" + addr + "]"
	}
	return addr
}

func HsiUri(proto, addr string, port uint16) string {
	return fmt.Sprintf("%s://%s:%d", proto, HsiUriHost(addr), port)
}

func HsiAnyAddr(isIp6 bool) string {
	if isIp6 {
		return "[::]"
	}
	return "0.0.0.0"
}

func (s *HsiSuite) StartProxyLite(serverURI, clientURI string, options ...string) string {
	cmd := fmt.Sprintf("proxy-lite server-uri %s client-uri %s", serverURI, clientURI)
	if len(options) > 0 {
		cmd += " " + strings.Join(options, " ")
	}
	output := s.Containers.Vpp.VppInstance.Vppctl(cmd)
	Log(output)
	return output
}

func (s *HsiSuite) StartProxyLiteTcp4(options ...string) string {
	return s.StartProxyLite(HsiUri("tcp", "0.0.0.0", s.Ports.Server),
		HsiUri("tcp", s.ServerAddr(), s.Ports.Server), options...)
}

func (s *HsiSuite) StartProxyLiteTcp6(options ...string) string {
	return s.StartProxyLite(HsiUri("tcp", "::", s.Ports.Server),
		HsiUri("tcp", s.ServerAddr6(), s.Ports.Server), options...)
}

func (s *HsiSuite) StartProxyLiteUdp4(options ...string) string {
	return s.StartProxyLite(HsiUri("udp", "0.0.0.0", s.Ports.Server),
		HsiUri("udp", s.ServerAddr(), s.Ports.Server), options...)
}

func (s *HsiSuite) StartProxyLiteUdp6(options ...string) string {
	return s.StartProxyLite(HsiUri("udp", "::", s.Ports.Server),
		HsiUri("udp", s.ServerAddr6(), s.Ports.Server), options...)
}

// BlockServerReplies keeps the target handshake pending until the client has
// queued data in proxy-lite. The returned function releases the target replies.
func (s *HsiSuite) BlockServerReplies() func() {
	serverIf := s.Interfaces.Server.Host.Name()
	output, err := exec.Command("tc", "qdisc", "add", "dev", serverIf,
		"root", "netem", "loss", "100%").CombinedOutput()
	AssertNil(err, string(output))

	blocked := true
	unblock := func() {
		if !blocked {
			return
		}
		output, err := exec.Command("tc", "qdisc", "del", "dev", serverIf, "root").CombinedOutput()
		AssertNil(err, string(output))
		blocked = false
	}
	return unblock
}

// AddClientNetem applies netem to the packets the client sends to vpp. The
// returned function removes it.
func (s *HsiSuite) AddClientNetem(args ...string) func() {
	clientIf := s.Interfaces.Client.Host.Name()
	run := func(args ...string) {
		output, err := CommandInNetns(append([]string{"tc", "qdisc"}, args...),
			s.NetNamespaces.Client).CombinedOutput()
		AssertNil(err, string(output))
	}
	run(append([]string{"add", "dev", clientIf, "root", "netem"}, args...)...)

	applied := true
	return func() {
		if !applied {
			return
		}
		run("del", "dev", clientIf, "root")
		applied = false
	}
}

// AddHostLoss drops percent of the packets the client and the target send to
// vpp. The returned function removes the loss.
func (s *HsiSuite) AddHostLoss(percent int) func() {
	loss := fmt.Sprintf("%d%%", percent)
	clientIf := s.Interfaces.Client.Host.Name()
	serverIf := s.Interfaces.Server.Host.Name()
	run := func(cmd *exec.Cmd) {
		output, err := cmd.CombinedOutput()
		AssertNil(err, string(output))
	}
	run(CommandInNetns([]string{"tc", "qdisc", "add", "dev", clientIf, "root", "netem", "loss",
		loss}, s.NetNamespaces.Client))
	run(exec.Command("tc", "qdisc", "add", "dev", serverIf, "root", "netem", "loss", loss))

	lossy := true
	return func() {
		if !lossy {
			return
		}
		run(CommandInNetns([]string{"tc", "qdisc", "del", "dev", clientIf, "root"},
			s.NetNamespaces.Client))
		run(exec.Command("tc", "qdisc", "del", "dev", serverIf, "root"))
		lossy = false
	}
}

// DropServerDataSegments drops full size TCP segments sent to the target, i.e.,
// IPv4 total length between 1024 and 2047, so handshakes and acks pass but
// data is never acked. The returned function removes the filter.
func (s *HsiSuite) DropServerDataSegments() func() {
	serverIf := s.Interfaces.Server.Host.Name()
	output, err := exec.Command("tc", "qdisc", "add", "dev", serverIf, "handle", "ffff:",
		"ingress").CombinedOutput()
	AssertNil(err, string(output))
	output, err = exec.Command("tc", "filter", "add", "dev", serverIf, "parent", "ffff:",
		"protocol", "ip", "prio", "1", "u32", "match", "ip", "protocol", "6", "0xff",
		"match", "u16", "0x0400", "0xfc00", "at", "2", "action", "drop").CombinedOutput()
	AssertNil(err, string(output))

	dropping := true
	return func() {
		if !dropping {
			return
		}
		output, err := exec.Command("tc", "qdisc", "del", "dev", serverIf, "ingress").CombinedOutput()
		AssertNil(err, string(output))
		dropping = false
	}
}

// SendServerIcmpPortUnreachable sends vpp, from the target host, an icmp port
// unreachable error for the proxy-lite udp session to the target.
func (s *HsiSuite) SendServerIcmpPortUnreachable() {
	vpp := s.Containers.Vpp.VppInstance
	vppAddr := s.Interfaces.Server.Ip4AddressString()
	session := regexp.MustCompile(regexp.QuoteMeta("[U] "+vppAddr+":") + `(\d+)` +
		regexp.QuoteMeta(fmt.Sprintf("->%s:%d", s.ServerAddr(), s.Ports.Server)))
	sessions := vpp.Vppctl("show session verbose")
	m := session.FindStringSubmatch(sessions)
	AssertNotNil(m, "proxy-lite udp session to target not found:\n"+sessions)
	lclPort, err := strconv.Atoi(m[1])
	AssertNil(err)

	// Datagram that triggered the error, ip header and first 8 bytes of udp
	orig := make([]byte, 28)
	orig[0] = 0x45
	binary.BigEndian.PutUint16(orig[2:], 28)
	orig[8] = 64
	orig[9] = 17
	copy(orig[12:16], net.ParseIP(vppAddr).To4())
	copy(orig[16:20], net.ParseIP(s.ServerAddr()).To4())
	binary.BigEndian.PutUint16(orig[20:], uint16(lclPort))
	binary.BigEndian.PutUint16(orig[22:], s.Ports.Server)
	binary.BigEndian.PutUint16(orig[24:], 8)

	msg, err := (&icmp.Message{Type: ipv4.ICMPTypeDestinationUnreachable, Code: 3,
		Body: &icmp.DstUnreach{Data: orig}}).Marshal(nil)
	AssertNil(err)
	conn, err := icmp.ListenPacket("ip4:icmp", s.ServerAddr())
	AssertNil(err)
	defer conn.Close()
	_, err = conn.WriteTo(msg, &net.IPAddr{IP: net.ParseIP(vppAddr)})
	AssertNil(err)
}

func WaitProxyLitePendingRx(vpp *VppInstance) {
	WaitProxyLitePendingRxAtLeast(vpp, 1)
}

// WaitProxyLitePendingRxAtLeast waits until a proxy-lite session has at least
// minBytes queued in its rx fifo
func WaitProxyLitePendingRxAtLeast(vpp *VppInstance, minBytes int) {
	pendingRx := regexp.MustCompile(`(?m)^\s*Rx fifo: cursize (\d+)\b`)
	var lastOutput string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		lastOutput = vpp.Vppctl("show session verbose 2")
		for _, m := range pendingRx.FindAllStringSubmatch(lastOutput, -1) {
			if n, err := strconv.Atoi(m[1]); err == nil && n >= minBytes {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	AssertFail("timed out waiting for %d bytes of proxy-lite RX data:\n%s", minBytes,
		lastOutput)
}

// WaitProxyLiteCounterAtLeast waits for a show proxy-lite counter, e.g.,
// accepted or closed, to reach want
func WaitProxyLiteCounterAtLeast(vpp *VppInstance, name string, want int) string {
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + ` (\d+)`)
	var output string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		output = vpp.Vppctl("show proxy-lite")
		if m := re.FindStringSubmatch(output); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil && n >= want {
				return output
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	AssertFail("timed out waiting for proxy-lite %s >= %d:\n%s", name, want, output)
	return output
}

// WaitProxyLiteSessionGoneWithin waits until vpp has no client, and if
// withTarget no target, proxy-lite session
func WaitProxyLiteSessionGoneWithin(s *HsiSuite, timeout time.Duration, withTarget bool) {
	vpp := s.Containers.Vpp.VppInstance
	proxyClientConn := fmt.Sprintf("[T] %s:%d->%s", s.ServerAddr(), s.Ports.Server,
		s.Interfaces.Client.Host.Ip4AddressString())
	proxyTargetConn := fmt.Sprintf("->%s:%d", s.ServerAddr(), s.Ports.Server)
	var sessions string
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		sessions = HsiShowSessions(vpp)
		if !strings.Contains(sessions, proxyClientConn) &&
			(!withTarget || !strings.Contains(sessions, proxyTargetConn)) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	AssertFail("timed out waiting for proxy-lite sessions cleanup:\n%s", sessions)
}

// HsiShowSessions returns verbose sessions of all threads. Unlike plain show
// session, it doesn't suppress threads with many sessions.
func HsiShowSessions(vpp *VppInstance) string {
	var out strings.Builder
	for thread := 0; thread <= vpp.CpuConfig.NumWorkers; thread++ {
		out.WriteString(vpp.Vppctl("show session thread %d verbose 2 force-print", thread))
		out.WriteString("\n")
	}
	return out.String()
}

// WaitProxyLitePendingRxSessions waits until at least sessions proxy-lite
// sessions have data queued in their rx fifos
func WaitProxyLitePendingRxSessions(vpp *VppInstance, sessions int) {
	pendingRx := regexp.MustCompile(`(?m)^\s*Rx fifo: cursize (\d+)\b`)
	var lastOutput string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		lastOutput = HsiShowSessions(vpp)
		pending := 0
		for _, m := range pendingRx.FindAllStringSubmatch(lastOutput, -1) {
			if n, err := strconv.Atoi(m[1]); err == nil && n > 0 {
				pending++
			}
		}
		if pending >= sessions {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	AssertFail("timed out waiting for %d proxy-lite sessions with RX data:\n%s", sessions,
		lastOutput)
}

func WaitProxyLiteTrackedCount(vpp *VppInstance, count int, cancel func()) string {
	var lastOutput string
	deadline := time.Now().Add(5 * time.Second)
	want := fmt.Sprintf("hsi tracked %d", count)
	for time.Now().Before(deadline) {
		output := vpp.Vppctl("show proxy-lite")
		if output != "" {
			lastOutput = output
		}
		if strings.Contains(output, want) {
			return output
		}
		if strings.Contains(output, "failed 1") {
			cancel()
			AssertFail("proxy-lite hsi offload failed before completion:\n%s", output)
		}
		time.Sleep(100 * time.Millisecond)
	}

	cancel()
	AssertFail("timed out waiting for proxy-lite hsi offload; last output:\n%s", lastOutput)
	return lastOutput
}

func WaitProxyLiteTracked(vpp *VppInstance, cancel func()) string {
	return WaitProxyLiteTrackedCount(vpp, 1, cancel)
}

func WaitHsiContains(vpp *VppInstance, want string) string {
	var lastOutput string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		output := vpp.Vppctl("show hsi")
		if output != "" {
			lastOutput = output
		}
		if strings.Contains(output, want) {
			return output
		}
		time.Sleep(100 * time.Millisecond)
	}

	AssertFail("timed out waiting for show hsi to contain %q; last output:\n%s", want, lastOutput)
	return lastOutput
}

func WaitHsiCounterAtLeast(vpp *VppInstance, name string, want int) string {
	return WaitHsiCounterAtLeastWithin(vpp, name, want, 10*time.Second)
}

func WaitHsiCounterAtLeastWithin(vpp *VppInstance, name string, want int,
	timeout time.Duration) string {
	var lastOutput string
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		output := vpp.Vppctl("show hsi")
		if output != "" {
			lastOutput = output
		}
		if HsiCounterValue(output, name) >= want {
			return output
		}
		time.Sleep(100 * time.Millisecond)
	}

	AssertFail("timed out waiting for show hsi counter %q >= %d; last output:\n%s", name, want, lastOutput)
	return lastOutput
}

func AssertHsiUdpDrainCompleted(vpp *VppInstance) string {
	var lastOutput string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		output := vpp.Vppctl("show hsi")
		if output != "" {
			lastOutput = output
		}
		if HsiCounterValue(output, "udp-drain-completed") >= 2 &&
			!strings.Contains(output, "udp-drain session") {
			return output
		}
		time.Sleep(100 * time.Millisecond)
	}

	AssertFail("timed out waiting for udp drain completion; last output:\n%s", lastOutput)
	return lastOutput
}

func AssertHsiUdpCleaned(vpp *VppInstance, expectedCleanupMin int) string {
	var lastOutput string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		output := vpp.Vppctl("show hsi")
		if output != "" {
			lastOutput = output
		}
		if HsiCounterValue(output, "udp-cleanup-completed") >= expectedCleanupMin &&
			!strings.Contains(output, "udp-tracked session") &&
			!strings.Contains(output, "udp-drain session") {
			return output
		}
		time.Sleep(100 * time.Millisecond)
	}

	AssertFail("timed out waiting for udp cleanup; last output:\n%s", lastOutput)
	return lastOutput
}

func AssertHsiTcpCleaned(vpp *VppInstance, expectedCleanupMin int) string {
	var lastOutput string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		output := vpp.Vppctl("show hsi")
		if output != "" {
			lastOutput = output
		}
		if HsiCounterValue(output, "tcp-cleanup-completed") >= expectedCleanupMin &&
			!strings.Contains(output, "tcp-tracked session") &&
			!strings.Contains(output, "tcp-drain session") {
			return output
		}
		time.Sleep(100 * time.Millisecond)
	}

	AssertFail("timed out waiting for tcp cleanup; last output:\n%s", lastOutput)
	return lastOutput
}

func AssertHsiNoTrackedOrDraining(hsi string) {
	AssertNotContains(hsi, "tcp-tracked session")
	AssertNotContains(hsi, "tcp-drain session")
	AssertNotContains(hsi, "udp-tracked session")
	AssertNotContains(hsi, "udp-drain session")
}

func HsiCounterValue(hsi, name string) int {
	total := 0
	for _, line := range strings.Split(hsi, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 4 || fields[2] != name {
			continue
		}
		value, err := strconv.Atoi(fields[3])
		AssertNil(err)
		total += value
	}
	return total
}

func AssertProxyLiteSessionsCleanedCount(s *HsiSuite, expectedCleanups int) {
	vpp := s.Containers.Vpp.VppInstance
	proxyClientConn := fmt.Sprintf("[T] %s:%d->%s", s.ServerAddr(), s.Ports.Server,
		s.Interfaces.Client.Host.Ip4AddressString())
	proxyTargetConn := fmt.Sprintf("->%s:%d", s.ServerAddr(), s.Ports.Server)
	for range 10 {
		sessions := HsiShowSessions(vpp)
		if !strings.Contains(sessions, proxyClientConn) &&
			!strings.Contains(sessions, proxyTargetConn) {
			break
		}
		time.Sleep(1 * time.Second)
	}

	hsi := vpp.Vppctl("show hsi")
	sessions := HsiShowSessions(vpp)
	Log(hsi)
	Log(sessions)
	AssertNotContains(sessions, proxyClientConn, "client-proxy session not cleaned up")
	AssertNotContains(sessions, proxyTargetConn, "proxy-server session not cleaned up")

	AssertEqual(expectedCleanups, HsiCounterValue(hsi, "tcp-cleanup-completed"))
	AssertNotContains(hsi, "tcp-tracked session")
	AssertNotContains(hsi, "tcp-drain session")
}

func AssertProxyLiteSessionsCleaned(s *HsiSuite) {
	AssertProxyLiteSessionsCleanedCount(s, 2)
}

func proxyLiteHsiCleanupsDone(output string, want int) bool {
	cleanups := regexp.MustCompile(`hsi cleanups (\d+)`).FindStringSubmatch(output)
	active := regexp.MustCompile(`active-sessions (\d+)`).FindStringSubmatch(output)
	return cleanups != nil && active != nil && cleanups[1] == strconv.Itoa(want) &&
		active[1] == "0"
}

// AssertProxyLiteHsiCleanups waits for proxy-lite to get exactly want hsi
// cleanup notifications, i.e., one per tracked session, and to free all its
// sessions. It then checks that no extra notification shows up.
func AssertProxyLiteHsiCleanups(vpp *VppInstance, want int) string {
	var lastOutput string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		lastOutput = vpp.Vppctl("show proxy-lite")
		if proxyLiteHsiCleanupsDone(lastOutput, want) {
			time.Sleep(500 * time.Millisecond)
			lastOutput = vpp.Vppctl("show proxy-lite")
			Log(lastOutput)
			AssertEqual(true, proxyLiteHsiCleanupsDone(lastOutput, want),
				"unexpected proxy-lite hsi cleanups:\n"+lastOutput)
			return lastOutput
		}
		time.Sleep(100 * time.Millisecond)
	}
	AssertFail("timed out waiting for %d proxy-lite hsi cleanups; last output:\n%s", want,
		lastOutput)
	return lastOutput
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

var _ = DescribeMWSuite("HsiMWSuite", []string{"HSI", "Solo", "MW"}, func() {
	var s HsiSuite
	BeforeAll(func() {
		s.SetupSuite()
	})
	BeforeEach(func() {
		s.SkipIfNotEnoughCpus = true
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
