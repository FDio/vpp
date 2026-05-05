package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	. "fd.io/hs-test/infra"
	tcpharness "fd.io/hs-test/infra/tcpharness"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterHsiTests(HsiTransparentProxyTest, HsiProxyLiteOffloadTest,
		HsiProxyLiteRepeatedOffloadTest, HsiProxyLiteDrainOffloadTest,
		HsiProxyLiteClientAbortTest, HsiTrackerTcpFinTest,
		HsiProxyLiteIpv6OffloadTest, HsiProxyLiteIpv6DrainOffloadTest,
		HsiProxyLiteUdpConnectedTest, HsiProxyLiteUdpIpv6ConnectedTest,
		HsiProxyLiteUdpDrainOffloadTest, HsiProxyLiteUdpIdleDisabledTest,
		HsiProxyLiteUdpIdleTimeoutTest, HsiProxyLiteUdpIpv6IdleTimeoutTest,
		HsiProxyLiteDrainCacheOverflowTest,
		HsiProxyLiteDrainTimeoutTest, HsiTrackerTcpHalfCloseTest,
		HsiTrackerTcpInvalidRstTest,
		HsiTrackerTcpFinDuplicateTest, HsiTrackerTcpFinRetransmitTest,
		HsiTrackerTcpOptionRewriteTest,
		HsiProxyLiteUdpDrainCacheOverflowTest,
		HsiProxyLiteUdpDrainTimeoutTest)
	RegisterHsiMWTests(HsiProxyLiteOffloadMWTest, HsiProxyLiteRepeatedOffloadMWTest,
		HsiProxyLiteDrainOffloadMWTest,
		HsiProxyLiteUdpConnectedMWTest, HsiProxyLiteUdpDrainOffloadMWTest,
		HsiProxyLiteUdpIdleTimeoutMWTest, HsiProxyLiteUdpRepeatedMigrationIdleMWTest)
}

func HsiTransparentProxyTest(s *HsiSuite) {
	s.SetupNginxServer()
	vpp := s.Containers.Vpp.VppInstance
	Log(vpp.Vppctl("set interface feature " + s.Interfaces.Client.VppName() + " hsi4-in arc ip4-unicast"))
	Log(vpp.Vppctl("set interface feature " + s.Interfaces.Server.VppName() + " hsi4-in arc ip4-unicast"))
	Log(vpp.Vppctl("test proxy server server-uri tcp://0.0.0.0:%d client-uri tcp://%s:%d",
		s.Ports.Server, s.ServerAddr(), s.Ports.Server))

	query := "httpTestFile"
	finished := make(chan error, 1)
	defer os.Remove(query)
	go func() {
		defer GinkgoRecover()
		StartWget(finished, s.ServerAddr(), strconv.Itoa(int(s.Ports.Server)), query, s.NetNamespaces.Client)
	}()
	AssertNil(<-finished)
}

func startCurlHttpRequest(uri, netNs, expectedRespCode string, timeout int, args ...string) <-chan error {
	finished := make(chan error, 1)
	go func() {
		defer GinkgoRecover()
		StartCurl(finished, uri, netNs, expectedRespCode, timeout, args)
	}()
	return finished
}

func runCurlIgnoreResult(uri, netNs string, timeout int, args ...string) string {
	c := []string{"curl", "-v", "-s", "-k", "--max-time", strconv.Itoa(timeout), "-o",
		"/dev/null", "--noproxy", "*"}
	c = append(c, args...)
	c = append(c, uri)
	cmd := CommandInNetns(c, netNs)
	Log(cmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		Log("curl exited with expected/allowed error: %v", err)
	}
	Log(string(output))
	return string(output)
}

func runHsiProxyLiteOffloadTest(s *HsiSuite) {
	s.SetupNginxServer()
	vpp := s.Containers.Vpp.VppInstance
	s.StartProxyLiteTcp4("hsi-offload")

	uri := fmt.Sprintf("http://%s:%d/64B", s.ServerAddr(), s.Ports.Server)
	finished := startCurlHttpRequest(uri, s.NetNamespaces.Client, "200 OK", 20)
	WaitProxyLiteTracked(vpp, func() {})
	AssertNil(<-finished)

	output := vpp.Vppctl("show proxy-lite")
	Log(output)
	AssertContains(output, "hsi tracked 1")
	AssertContains(output, "failed 0")

	AssertProxyLiteSessionsCleaned(s)
}

func HsiProxyLiteOffloadTest(s *HsiSuite) {
	runHsiProxyLiteOffloadTest(s)
}

func HsiProxyLiteOffloadMWTest(s *HsiSuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	runHsiProxyLiteOffloadTest(s)
}

func runHsiProxyLiteRepeatedOffloadTest(s *HsiSuite) {
	s.SetupNginxServer()
	vpp := s.Containers.Vpp.VppInstance
	s.StartProxyLiteTcp4("hsi-offload")

	for i := 1; i <= 3; i++ {
		uri := fmt.Sprintf("http://%s:%d/64B?repeat=%d", s.ServerAddr(), s.Ports.Server, i)
		finished := startCurlHttpRequest(uri, s.NetNamespaces.Client, "200 OK", 20)
		WaitProxyLiteTrackedCount(vpp, i, func() {})
		AssertNil(<-finished)
	}

	output := vpp.Vppctl("show proxy-lite")
	Log(output)
	AssertContains(output, "hsi tracked 3")
	AssertContains(output, "failed 0")

	AssertProxyLiteSessionsCleanedCount(s, 6)
}

func HsiProxyLiteRepeatedOffloadTest(s *HsiSuite) {
	runHsiProxyLiteRepeatedOffloadTest(s)
}

func HsiProxyLiteRepeatedOffloadMWTest(s *HsiSuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	runHsiProxyLiteRepeatedOffloadTest(s)
}

func HsiProxyLiteIpv6OffloadTest(s *HsiSuite) {
	s.SetupNginxServerIp6()
	vpp := s.Containers.Vpp.VppInstance
	s.StartProxyLiteTcp6("hsi-offload")

	uri := fmt.Sprintf("http://%s:%d/64B", HsiUriHost(s.ServerAddr6()), s.Ports.Server)
	finished := startCurlHttpRequest(uri, s.NetNamespaces.Client, "200 OK", 20)
	WaitProxyLiteTracked(vpp, func() {})
	AssertNil(<-finished)

	output := vpp.Vppctl("show proxy-lite")
	Log(output)
	AssertContains(output, "hsi tracked 1")
	AssertContains(output, "failed 0")

	hsi := AssertHsiTcpCleaned(vpp, 2)
	Log(hsi)
}

func runHsiProxyLiteDrainOffloadTest(s *HsiSuite) {
	s.SetupNginxServer()
	vpp := s.Containers.Vpp.VppInstance
	s.StartProxyLiteTcp4("hsi-offload", "fifo-size 4k")

	uploadFileName := MakeProxyLiteUploadFile()
	defer os.Remove(uploadFileName)

	uri := fmt.Sprintf("http://%s:%d/upload/hsi-proxy-lite-upload", s.ServerAddr(), s.Ports.Server)
	finished := startCurlHttpRequest(uri, s.NetNamespaces.Client, "201", 60,
		"-T", uploadFileName, "-H", "Expect:", "--limit-rate", "256k")

	WaitProxyLiteTracked(vpp, func() {})

	AssertNil(<-finished)

	output := vpp.Vppctl("show proxy-lite")
	Log(output)
	AssertContains(output, "hsi tracked 1")
	AssertContains(output, "failed 0")
	hsi := WaitHsiCounterAtLeast(vpp, "tcp-drain-completed", 2)
	Log(hsi)

	AssertProxyLiteSessionsCleaned(s)
}

func HsiProxyLiteDrainOffloadTest(s *HsiSuite) {
	runHsiProxyLiteDrainOffloadTest(s)
}

func HsiProxyLiteDrainOffloadMWTest(s *HsiSuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	runHsiProxyLiteDrainOffloadTest(s)
}

func HsiProxyLiteIpv6DrainOffloadTest(s *HsiSuite) {
	s.SetupNginxServerIp6()
	vpp := s.Containers.Vpp.VppInstance
	s.StartProxyLiteTcp6("hsi-offload", "fifo-size 4k")

	uploadFileName := MakeProxyLiteUploadFile()
	defer os.Remove(uploadFileName)

	uri := fmt.Sprintf("http://%s:%d/upload/hsi-proxy-lite-ipv6-upload",
		HsiUriHost(s.ServerAddr6()), s.Ports.Server)
	finished := startCurlHttpRequest(uri, s.NetNamespaces.Client, "201", 60,
		"-T", uploadFileName, "-H", "Expect:", "--limit-rate", "256k")

	WaitProxyLiteTracked(vpp, func() {})
	AssertNil(<-finished)

	hsi := WaitHsiCounterAtLeast(vpp, "tcp-drain-completed", 2)
	Log(hsi)
	hsi = AssertHsiTcpCleaned(vpp, 2)
	Log(hsi)
}

func runHsiProxyLiteUdpConnectedTest(s *HsiSuite) {
	remoteServerConn := StartUdpEchoServer(s.ServerAddr(), int(s.Ports.Server))
	defer remoteServerConn.Close()

	vpp := s.Containers.Vpp.VppInstance
	s.StartProxyLiteUdp4("hsi-offload", "fifo-size 4k")

	finished := StartHsiUdpEchoClient(s.ServerAddr(), s.Ports.Server, s.NetNamespaces.Client,
		time.Second, "hsi-udp-warm", "hsi-udp-first", "hsi-udp-second")
	WaitProxyLiteTracked(vpp, func() {})
	result := <-finished
	Log(result.Output)
	AssertNil(result.Err, result.Output)
	AssertContains(result.Output, "hsi-udp-second")

	output := vpp.Vppctl("show proxy-lite")
	Log(output)
	AssertContains(output, "hsi tracked 1")
	AssertContains(output, "failed 0")

	hsi := WaitHsiCounterAtLeast(vpp, "udp-track-accepted", 1)
	Log(hsi)
}

func HsiProxyLiteUdpConnectedTest(s *HsiSuite) {
	runHsiProxyLiteUdpConnectedTest(s)
}

func HsiProxyLiteUdpIpv6ConnectedTest(s *HsiSuite) {
	remoteServerConn := StartUdpEchoServer(s.ServerAddr6(), int(s.Ports.Server))
	defer remoteServerConn.Close()

	vpp := s.Containers.Vpp.VppInstance
	s.StartProxyLiteUdp6("hsi-offload", "fifo-size 4k")

	finished := StartHsiUdpEchoClient(s.ServerAddr6(), s.Ports.Server, s.NetNamespaces.Client,
		time.Second, "hsi-udp-ipv6-warm", "hsi-udp-ipv6-first", "hsi-udp-ipv6-second")
	WaitProxyLiteTracked(vpp, func() {})
	result := <-finished
	Log(result.Output)
	AssertNil(result.Err, result.Output)
	AssertContains(result.Output, "hsi-udp-ipv6-second")

	output := vpp.Vppctl("show proxy-lite")
	Log(output)
	AssertContains(output, "hsi tracked 1")
	AssertContains(output, "failed 0")

	hsi := WaitHsiCounterAtLeast(vpp, "udp-track-accepted", 1)
	Log(hsi)
}

func HsiProxyLiteUdpConnectedMWTest(s *HsiSuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()

	remoteServerConn := StartUdpEchoServer(s.ServerAddr(), int(s.Ports.Server))
	defer remoteServerConn.Close()

	vpp := s.Containers.Vpp.VppInstance
	s.StartProxyLiteUdp4("hsi-offload", "fifo-size 4k")

	for i := 0; i < 8; i++ {
		second := fmt.Sprintf("hsi-udp-second-%d", i)
		finished := StartHsiUdpEchoClient(s.ServerAddr(), s.Ports.Server, s.NetNamespaces.Client,
			time.Second, fmt.Sprintf("hsi-udp-warm-%d", i), fmt.Sprintf("hsi-udp-first-%d", i),
			second)
		WaitProxyLiteTrackedCount(vpp, i+1, func() {})
		result := <-finished
		Log(result.Output)
		AssertNil(result.Err, result.Output)
		AssertContains(result.Output, second)

		hsi := vpp.Vppctl("show hsi")
		if HsiCounterValue(hsi, "udp-track-migrated") > 0 {
			Log(hsi)
			return
		}
	}

	hsi := vpp.Vppctl("show hsi")
	Log(hsi)
	AssertFail("expected at least one tracked UDP migration")
}

func runHsiProxyLiteUdpDrainOffloadTest(s *HsiSuite) {
	remoteServerConn := StartUdpEchoServer(s.ServerAddr(), int(s.Ports.Server))
	defer remoteServerConn.Close()

	vpp := s.Containers.Vpp.VppInstance
	s.StartProxyLiteUdp4("hsi-offload", "fifo-size 4k")

	finished := StartHsiUdpEchoClient(s.ServerAddr(), s.Ports.Server, s.NetNamespaces.Client,
		time.Second, "hsi-udp-drain-warm", "hsi-udp-drain-first", "hsi-udp-drain-second")
	WaitProxyLiteTracked(vpp, func() {})
	result := <-finished
	Log(result.Output)
	AssertNil(result.Err, result.Output)
	AssertContains(result.Output, "hsi-udp-drain-second")

	hsi := WaitHsiCounterAtLeast(vpp, "udp-track-accepted", 1)
	Log(hsi)
	hsi = WaitHsiCounterAtLeast(vpp, "udp-drain-started", 2)
	Log(hsi)
	hsi = AssertHsiUdpDrainCompleted(vpp)
	Log(hsi)
}

func HsiProxyLiteUdpDrainOffloadTest(s *HsiSuite) {
	runHsiProxyLiteUdpDrainOffloadTest(s)
}

func HsiProxyLiteUdpDrainOffloadMWTest(s *HsiSuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	runHsiProxyLiteUdpDrainOffloadTest(s)
}

func HsiProxyLiteUdpDrainCacheOverflowTest(s *HsiSuite) {
	remoteServerConn := StartUdpEchoServer(s.ServerAddr(), int(s.Ports.Server))
	defer remoteServerConn.Close()

	vpp := s.Containers.Vpp.VppInstance
	Log(vpp.Vppctl("hsi udp drain-cache max-packets 1"))
	s.StartProxyLiteUdp4("hsi-offload-stall", "fifo-size 4k")

	finished := SendHsiUdpDatagrams(s.ServerAddr(), s.Ports.Server, s.NetNamespaces.Client,
		300*time.Millisecond, "hsi-udp-overflow-warm", "hsi-udp-overflow-1",
		"hsi-udp-overflow-2", "hsi-udp-overflow-3", "hsi-udp-overflow-4")
	WaitProxyLiteTracked(vpp, func() {})
	AssertNil((<-finished).Err)

	hsi := WaitHsiCounterAtLeast(vpp, "udp-drain-cache-overflow", 1)
	Log(hsi)
	hsi = WaitHsiCounterAtLeast(vpp, "udp-drain-cache-dropped", 1)
	Log(hsi)
	hsi = AssertHsiUdpCleaned(vpp, 2)
	Log(hsi)
}

func HsiProxyLiteUdpDrainTimeoutTest(s *HsiSuite) {
	remoteServerConn := StartUdpEchoServer(s.ServerAddr(), int(s.Ports.Server))
	defer remoteServerConn.Close()

	vpp := s.Containers.Vpp.VppInstance
	Log(vpp.Vppctl("hsi udp drain-timeout 1"))
	s.StartProxyLiteUdp4("hsi-offload-stall", "fifo-size 4k")

	finished := SendHsiUdpDatagrams(s.ServerAddr(), s.Ports.Server, s.NetNamespaces.Client,
		0, "hsi-udp-timeout-warm")
	AssertNil((<-finished).Err)
	WaitProxyLiteTracked(vpp, func() {})

	hsi := WaitHsiCounterAtLeast(vpp, "udp-drain-stalled", 1)
	Log(hsi)
	hsi = AssertHsiUdpCleaned(vpp, 2)
	Log(hsi)
}

func HsiProxyLiteUdpIdleDisabledTest(s *HsiSuite) {
	remoteServerConn := StartUdpEchoServer(s.ServerAddr(), int(s.Ports.Server))
	defer remoteServerConn.Close()

	vpp := s.Containers.Vpp.VppInstance
	Log(vpp.Vppctl("hsi udp idle-timeout 0"))
	s.StartProxyLiteUdp4("hsi-offload", "fifo-size 4k")

	finished := StartHsiUdpEchoClient(s.ServerAddr(), s.Ports.Server, s.NetNamespaces.Client,
		100*time.Millisecond, "hsi-udp-idle-disabled-warm", "hsi-udp-idle-disabled-first",
		"hsi-udp-idle-disabled-second")
	WaitProxyLiteTracked(vpp, func() {})
	result := <-finished
	Log(result.Output)
	AssertNil(result.Err, result.Output)
	AssertContains(result.Output, "hsi-udp-idle-disabled-second")

	time.Sleep(1500 * time.Millisecond)
	hsi := vpp.Vppctl("show hsi")
	Log(hsi)
	AssertEqual(0, HsiCounterValue(hsi, "udp-idle-timeout"))
	AssertEqual(0, HsiCounterValue(hsi, "udp-idle-cleanup-scheduled"))
	AssertContains(hsi, "udp-tracked session")
	AssertNotContains(hsi, "udp-drain session")
}

func runHsiProxyLiteUdpIdleTimeoutTest(s *HsiSuite) {
	remoteServerConn := StartUdpEchoServer(s.ServerAddr(), int(s.Ports.Server))
	defer remoteServerConn.Close()

	vpp := s.Containers.Vpp.VppInstance
	Log(vpp.Vppctl("hsi udp idle-timeout 1"))
	s.StartProxyLiteUdp4("hsi-offload", "fifo-size 4k")

	finished := StartHsiUdpEchoClient(s.ServerAddr(), s.Ports.Server, s.NetNamespaces.Client,
		100*time.Millisecond, "hsi-udp-idle-warm", "hsi-udp-idle-first", "hsi-udp-idle-second")
	WaitProxyLiteTracked(vpp, func() {})
	result := <-finished
	Log(result.Output)
	AssertNil(result.Err, result.Output)
	AssertContains(result.Output, "hsi-udp-idle-second")

	hsi := WaitHsiCounterAtLeast(vpp, "udp-idle-timeout", 1)
	Log(hsi)
	hsi = WaitHsiCounterAtLeast(vpp, "udp-cleanup-completed", 2)
	Log(hsi)
	AssertEqual(1, HsiCounterValue(hsi, "udp-idle-cleanup-scheduled"))
	AssertNotContains(hsi, "udp-tracked session")
}

func HsiProxyLiteUdpIdleTimeoutTest(s *HsiSuite) {
	runHsiProxyLiteUdpIdleTimeoutTest(s)
}

func HsiProxyLiteUdpIpv6IdleTimeoutTest(s *HsiSuite) {
	remoteServerConn := StartUdpEchoServer(s.ServerAddr6(), int(s.Ports.Server))
	defer remoteServerConn.Close()

	vpp := s.Containers.Vpp.VppInstance
	Log(vpp.Vppctl("hsi udp idle-timeout 1"))
	s.StartProxyLiteUdp6("hsi-offload", "fifo-size 4k")

	finished := StartHsiUdpEchoClient(s.ServerAddr6(), s.Ports.Server, s.NetNamespaces.Client,
		100*time.Millisecond, "hsi-udp-ipv6-idle-warm", "hsi-udp-ipv6-idle-first",
		"hsi-udp-ipv6-idle-second")
	WaitProxyLiteTracked(vpp, func() {})
	result := <-finished
	Log(result.Output)
	AssertNil(result.Err, result.Output)
	AssertContains(result.Output, "hsi-udp-ipv6-idle-second")

	hsi := WaitHsiCounterAtLeast(vpp, "udp-idle-timeout", 1)
	Log(hsi)
	hsi = AssertHsiUdpCleaned(vpp, 2)
	Log(hsi)
	AssertEqual(1, HsiCounterValue(hsi, "udp-idle-cleanup-scheduled"))
}

func HsiProxyLiteUdpIdleTimeoutMWTest(s *HsiSuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	runHsiProxyLiteUdpIdleTimeoutTest(s)
}

func HsiProxyLiteUdpRepeatedMigrationIdleMWTest(s *HsiSuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()

	remoteServerConn := StartUdpEchoServer(s.ServerAddr(), int(s.Ports.Server))
	defer remoteServerConn.Close()

	vpp := s.Containers.Vpp.VppInstance
	Log(vpp.Vppctl("hsi udp idle-timeout 1"))
	s.StartProxyLiteUdp4("hsi-offload", "fifo-size 4k")

	flows := 8
	for i := 0; i < flows; i++ {
		second := fmt.Sprintf("hsi-udp-mw-idle-second-%d", i)
		finished := StartHsiUdpEchoClient(s.ServerAddr(), s.Ports.Server, s.NetNamespaces.Client,
			100*time.Millisecond, fmt.Sprintf("hsi-udp-mw-idle-warm-%d", i),
			fmt.Sprintf("hsi-udp-mw-idle-first-%d", i), second)
		WaitProxyLiteTrackedCount(vpp, i+1, func() {})
		result := <-finished
		Log(result.Output)
		AssertNil(result.Err, result.Output)
		AssertContains(result.Output, second)
	}

	hsi := WaitHsiCounterAtLeast(vpp, "udp-cleanup-completed", flows*2)
	Log(hsi)
	AssertGreaterThan(HsiCounterValue(hsi, "udp-track-migrated"), 0)
	AssertNotContains(hsi, "udp-tracked session")
	AssertNotContains(hsi, "udp-drain session")
}

func HsiProxyLiteDrainCacheOverflowTest(s *HsiSuite) {
	s.SetupNginxServer()
	vpp := s.Containers.Vpp.VppInstance
	Log(vpp.Vppctl("hsi tcp drain-cache max-packets 1"))
	s.StartProxyLiteTcp4("hsi-offload", "fifo-size 4k")

	uploadFileName := MakeProxyLiteUploadFile()
	defer os.Remove(uploadFileName)

	uri := fmt.Sprintf("http://%s:%d/upload/hsi-proxy-lite-overflow", s.ServerAddr(), s.Ports.Server)
	finished := startCurlHttpRequest(uri, s.NetNamespaces.Client, "201", 10,
		"-T", uploadFileName, "-H", "Expect:", "--limit-rate", "256k")

	WaitProxyLiteTracked(vpp, func() {})

	AssertNotNil(<-finished)
	hsi := WaitHsiContains(vpp, "tcp-drain-cache-overflow 1")
	Log(hsi)
	AssertProxyLiteSessionsCleaned(s)
}

func HsiProxyLiteDrainTimeoutTest(s *HsiSuite) {
	s.SetupNginxServer()
	vpp := s.Containers.Vpp.VppInstance
	Log(vpp.Vppctl("hsi tcp drain-timeout 1"))
	s.StartProxyLiteTcp4("hsi-offload-stall", "fifo-size 4k")

	uploadFileName := MakeProxyLiteUploadFile()
	defer os.Remove(uploadFileName)

	uri := fmt.Sprintf("http://%s:%d/upload/hsi-proxy-lite-timeout", s.ServerAddr(), s.Ports.Server)
	finished := startCurlHttpRequest(uri, s.NetNamespaces.Client, "201", 20,
		"-T", uploadFileName, "-H", "Expect:", "--limit-rate", "256k")

	WaitProxyLiteTracked(vpp, func() {})

	AssertNotNil(<-finished)
	hsi := WaitHsiContains(vpp, "tcp-drain-stalled 1")
	Log(hsi)
	AssertProxyLiteSessionsCleaned(s)
}

func runHsiProxyLiteClientAbortTest(s *HsiSuite) {
	s.SetupNginxServer()
	vpp := s.Containers.Vpp.VppInstance
	s.StartProxyLiteTcp4("hsi-offload")

	uri := fmt.Sprintf("http://%s:%d/httpTestFile", s.ServerAddr(), s.Ports.Server)
	finished := startCurlHttpRequest(uri, s.NetNamespaces.Client, "200", 2,
		"--limit-rate", "1k")
	WaitProxyLiteTracked(vpp, func() {})

	AssertNotNil(<-finished)
	hsi := WaitHsiContains(vpp, "tcp-rst-cleanup 1")
	Log(hsi)
	AssertProxyLiteSessionsCleaned(s)
}

func HsiProxyLiteClientAbortTest(s *HsiSuite) {
	runHsiProxyLiteClientAbortTest(s)
}

func HsiTrackerTcpFinTest(s *HsiSuite) {
	s.SetupNginxServer()
	vpp := s.Containers.Vpp.VppInstance
	s.StartProxyLiteTcp4("hsi-offload")

	uri := fmt.Sprintf("http://%s:%d/64B", s.ServerAddr(), s.Ports.Server)
	finished := startCurlHttpRequest(uri, s.NetNamespaces.Client, "200 OK", 20)
	WaitProxyLiteTracked(vpp, func() {})
	AssertNil(<-finished)

	hsi := WaitHsiContains(vpp, "tcp-fin-cleanup 1")
	Log(hsi)
	AssertProxyLiteSessionsCleaned(s)
}

func HsiTrackerTcpHalfCloseTest(s *HsiSuite) {
	s.SetupNginxServer()
	vpp := s.Containers.Vpp.VppInstance
	s.StartProxyLiteTcp4("hsi-offload")

	readyPath, signalPath := HsiTempSignalPaths()
	defer os.Remove(readyPath)
	defer os.Remove(signalPath)

	finished := StartHsiTcpHalfCloseClient(s.ServerAddr(), s.Ports.Server, s.NetNamespaces.Client,
		readyPath, signalPath)
	WaitForFile(readyPath, 5*time.Second)
	WaitProxyLiteTracked(vpp, func() {})
	AssertNil(os.WriteFile(signalPath, []byte("go"), 0644))

	result := <-finished
	Log(result.Output)
	AssertNil(result.Err, result.Output)

	hsi := WaitHsiContains(vpp, "tcp-fin-cleanup 1")
	Log(hsi)
	AssertProxyLiteSessionsCleaned(s)
}

func HsiTrackerTcpInvalidRstTest(s *HsiSuite) {
	s.SetupNginxServer()
	vpp := s.Containers.Vpp.VppInstance
	s.StartProxyLiteTcp4("hsi-offload")

	readyPath, signalPath := HsiTempSignalPaths()
	defer os.Remove(readyPath)
	defer os.Remove(signalPath)

	finished := StartHsiTcpInvalidRstClient(s.ServerAddr(), s.Ports.Server, s.NetNamespaces.Client,
		readyPath, signalPath)
	WaitForFile(readyPath, 5*time.Second)
	WaitProxyLiteTracked(vpp, func() {})
	AssertNil(os.WriteFile(signalPath, []byte("go"), 0644))

	result := <-finished
	Log(result.Output)
	AssertNil(result.Err, result.Output)

	hsi := WaitHsiContains(vpp, "tcp-fin-cleanup 1")
	Log(hsi)
	AssertEqual(0, HsiCounterValue(hsi, "tcp-rst-cleanup"))
	AssertProxyLiteSessionsCleaned(s)
}

func runHsiTrackerTcpFinReplayTest(s *HsiSuite, replayDelay time.Duration) {
	s.SetupNginxServer()
	vpp := s.Containers.Vpp.VppInstance
	s.StartProxyLiteTcp4("hsi-offload")

	readyPath, signalPath := HsiTempSignalPaths()
	defer os.Remove(readyPath)
	defer os.Remove(signalPath)

	finished := StartHsiTcpFinReplayClient(s.ServerAddr(), s.Ports.Server, s.NetNamespaces.Client,
		s.Interfaces.Client.Host.Name(), readyPath, signalPath, replayDelay, 1)
	WaitForFile(readyPath, 5*time.Second)
	WaitProxyLiteTracked(vpp, func() {})
	AssertNil(os.WriteFile(signalPath, []byte("go"), 0644))

	result := <-finished
	Log(result.Output)
	AssertNil(result.Err, result.Output)

	hsi := WaitHsiContains(vpp, "tcp-fin-cleanup 1")
	Log(hsi)
	AssertProxyLiteSessionsCleaned(s)
}

func HsiTrackerTcpFinDuplicateTest(s *HsiSuite) {
	runHsiTrackerTcpFinReplayTest(s, 0)
}

func HsiTrackerTcpFinRetransmitTest(s *HsiSuite) {
	runHsiTrackerTcpFinReplayTest(s, 500*time.Millisecond)
}

func HsiTrackerTcpOptionRewriteTest(s *HsiSuite) {
	s.SetupNginxServer()
	vpp := s.Containers.Vpp.VppInstance
	Log(vpp.Vppctl("pcap trace rx tx max 10000 max-bytes-per-pkt 1500 intfc any file vppTest.pcap"))
	s.StartProxyLiteTcp4("hsi-offload")

	uri := fmt.Sprintf("http://%s:%d/64B", s.ServerAddr(), s.Ports.Server)
	finished := startCurlHttpRequest(uri, s.NetNamespaces.Client, "200", 20)
	WaitProxyLiteTracked(vpp, func() {})
	AssertNil(<-finished)
	Log(vpp.Vppctl("pcap trace off"))

	pcapFile, err := os.CreateTemp("", "hsi-option-rewrite-*.pcap")
	AssertNil(err)
	pcapPath := pcapFile.Name()
	AssertNil(pcapFile.Close())
	defer os.Remove(pcapPath)
	AssertNil(vpp.Container.GetFile("/tmp/vppTest.pcap", pcapPath))

	packets, err := tcpharness.ReadPcapIPv4TCPPackets(pcapPath)
	AssertNil(err)
	hasTSOpt := false
	for _, packet := range packets {
		if packet.HasTSOpt && (packet.SrcPort == s.Ports.Server || packet.DstPort == s.Ports.Server) {
			hasTSOpt = true
			break
		}
	}
	AssertEqual(true, hasTSOpt, "expected tracked flow to preserve TCP timestamp options")

	hsi := WaitHsiContains(vpp, "tcp-fin-cleanup 1")
	Log(hsi)
	AssertProxyLiteSessionsCleaned(s)
}
