package main

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterHsiSoloTests(HsiTransparentProxyTest, HsiProxyLiteOffloadTest,
		HsiProxyLiteRepeatedOffloadTest, HsiProxyLiteDrainOffloadTest, HsiProxyLiteDrainCacheOverflowTest,
		HsiProxyLiteDrainTimeoutTest, HsiProxyLiteClientAbortTest, HsiTrackerTcpFinTest,
		HsiTrackerTcpRstValidationTest, HsiProxyLiteUdpConnectedTest,
		HsiProxyLiteUdpDrainOffloadTest, HsiProxyLiteUdpDrainCacheOverflowTest,
		HsiProxyLiteUdpDrainTimeoutTest, HsiProxyLiteUdpIdleDisabledTest,
		HsiProxyLiteUdpIdleTimeoutTest)
	RegisterHsiMWTests(HsiProxyLiteOffloadMWTest, HsiProxyLiteDrainOffloadMWTest,
		HsiProxyLiteUdpConnectedMWTest, HsiProxyLiteUdpDrainOffloadMWTest,
		HsiProxyLiteUdpIdleTimeoutMWTest)
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

type udpEchoClientResult struct {
	output string
	err    error
}

func startUdpEchoClient(addr string, port uint16, netNs string, pause time.Duration,
	payloads ...string) <-chan udpEchoClientResult {
	finished := make(chan udpEchoClientResult, 1)
	script := `
import socket
import sys
import time

addr = sys.argv[1]
port = int(sys.argv[2])
pause = float(sys.argv[3])
payloads = sys.argv[4:]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(10)
for payload in payloads[:-1]:
    sock.sendto(payload.encode(), (addr, port))
    time.sleep(pause)

want = payloads[-1].encode()
sock.sendto(want, (addr, port))
while True:
    reply, _ = sock.recvfrom(2048)
    sys.stdout.write(reply.decode(errors="replace") + "\n")
    sys.stdout.flush()
    if reply == want:
        break
`
	go func() {
		defer GinkgoRecover()
		args := []string{"python3", "-c", script, addr, strconv.Itoa(int(port)),
			fmt.Sprintf("%.3f", pause.Seconds())}
		args = append(args, payloads...)
		cmd := CommandInNetns(args, netNs)
		Log(cmd)
		output, err := cmd.CombinedOutput()
		finished <- udpEchoClientResult{output: string(output), err: err}
	}()
	return finished
}

func sendUdpDatagrams(addr string, port uint16, netNs string, pause time.Duration,
	payloads ...string) <-chan udpEchoClientResult {
	finished := make(chan udpEchoClientResult, 1)
	script := `
import socket
import sys
import time

addr = sys.argv[1]
port = int(sys.argv[2])
pause = float(sys.argv[3])
payloads = sys.argv[4:]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for payload in payloads:
    sock.sendto(payload.encode(), (addr, port))
    if pause > 0:
        time.sleep(pause)
`
	go func() {
		defer GinkgoRecover()
		args := []string{"python3", "-c", script, addr, strconv.Itoa(int(port)),
			fmt.Sprintf("%.3f", pause.Seconds())}
		args = append(args, payloads...)
		cmd := CommandInNetns(args, netNs)
		Log(cmd)
		output, err := cmd.CombinedOutput()
		finished <- udpEchoClientResult{output: string(output), err: err}
	}()
	return finished
}

func waitProxyLiteTrackedCount(vpp *VppInstance, count int, cancel func()) string {
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

func waitProxyLiteTracked(vpp *VppInstance, cancel func()) string {
	return waitProxyLiteTrackedCount(vpp, 1, cancel)
}

func waitHsiContains(vpp *VppInstance, want string) string {
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

func waitHsiCounterAtLeast(vpp *VppInstance, name string, want int) string {
	var lastOutput string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		output := vpp.Vppctl("show hsi")
		if output != "" {
			lastOutput = output
		}
		if hsiCounterValue(output, name) >= want {
			return output
		}
		time.Sleep(100 * time.Millisecond)
	}

	AssertFail("timed out waiting for show hsi counter %q >= %d; last output:\n%s", name, want, lastOutput)
	return lastOutput
}

func assertHsiUdpDrainCompleted(vpp *VppInstance) string {
	var lastOutput string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		output := vpp.Vppctl("show hsi")
		if output != "" {
			lastOutput = output
		}
		if hsiCounterValue(output, "udp-drain-completed") >= 2 &&
			!strings.Contains(output, "udp-drain session") {
			return output
		}
		time.Sleep(100 * time.Millisecond)
	}

	AssertFail("timed out waiting for udp drain completion; last output:\n%s", lastOutput)
	return lastOutput
}

func assertHsiUdpCleaned(vpp *VppInstance, expectedCleanupMin int) string {
	var lastOutput string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		output := vpp.Vppctl("show hsi")
		if output != "" {
			lastOutput = output
		}
		if hsiCounterValue(output, "udp-cleanup-completed") >= expectedCleanupMin &&
			!strings.Contains(output, "udp-tracked session") &&
			!strings.Contains(output, "udp-drain session") {
			return output
		}
		time.Sleep(100 * time.Millisecond)
	}

	AssertFail("timed out waiting for udp cleanup; last output:\n%s", lastOutput)
	return lastOutput
}

func hsiCounterValue(hsi, name string) int {
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

func assertProxyLiteSessionsCleanedCount(s *HsiSuite, expectedCleanups int) {
	vpp := s.Containers.Vpp.VppInstance
	proxyClientConn := fmt.Sprintf("[T] %s:%d->%s", s.ServerAddr(), s.Ports.Server,
		s.Interfaces.Client.Host.Ip4AddressString())
	proxyTargetConn := fmt.Sprintf("->%s:%d", s.ServerAddr(), s.Ports.Server)
	for range 10 {
		sessions := vpp.Vppctl("show session verbose 2")
		if !strings.Contains(sessions, proxyClientConn) &&
			!strings.Contains(sessions, proxyTargetConn) {
			break
		}
		time.Sleep(1 * time.Second)
	}

	hsi := vpp.Vppctl("show hsi")
	sessions := vpp.Vppctl("show session verbose 2")
	Log(hsi)
	Log(sessions)
	AssertNotContains(sessions, proxyClientConn, "client-proxy session not cleaned up")
	AssertNotContains(sessions, proxyTargetConn, "proxy-server session not cleaned up")

	AssertEqual(expectedCleanups, hsiCounterValue(hsi, "tcp-cleanup-completed"))
	AssertNotContains(hsi, "tcp-tracked session")
	AssertNotContains(hsi, "tcp-drain session")
}

func assertProxyLiteSessionsCleaned(s *HsiSuite) {
	assertProxyLiteSessionsCleanedCount(s, 2)
}

func makeProxyLiteUploadFile() string {
	uploadFile, err := os.CreateTemp("", "hsi-proxy-lite-upload-*")
	AssertNil(err)
	_, err = uploadFile.Write(bytes.Repeat([]byte("0123456789abcdef"), 64*1024))
	AssertNil(err)
	AssertNil(uploadFile.Close())
	return uploadFile.Name()
}

func runHsiProxyLiteOffloadTest(s *HsiSuite) {
	s.SetupNginxServer()
	vpp := s.Containers.Vpp.VppInstance
	Log(vpp.Vppctl("proxy-lite server-uri tcp://0.0.0.0:%d client-uri tcp://%s:%d hsi-offload",
		s.Ports.Server, s.ServerAddr(), s.Ports.Server))

	uri := fmt.Sprintf("http://%s:%d/64B", s.ServerAddr(), s.Ports.Server)
	finished := startCurlHttpRequest(uri, s.NetNamespaces.Client, "200 OK", 20)
	waitProxyLiteTracked(vpp, func() {})
	AssertNil(<-finished)

	output := vpp.Vppctl("show proxy-lite")
	Log(output)
	AssertContains(output, "hsi tracked 1")
	AssertContains(output, "failed 0")

	assertProxyLiteSessionsCleaned(s)
}

func HsiProxyLiteOffloadTest(s *HsiSuite) {
	runHsiProxyLiteOffloadTest(s)
}

func HsiProxyLiteOffloadMWTest(s *HsiSuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	runHsiProxyLiteOffloadTest(s)
}

func HsiProxyLiteRepeatedOffloadTest(s *HsiSuite) {
	s.SetupNginxServer()
	vpp := s.Containers.Vpp.VppInstance
	Log(vpp.Vppctl("proxy-lite server-uri tcp://0.0.0.0:%d client-uri tcp://%s:%d hsi-offload",
		s.Ports.Server, s.ServerAddr(), s.Ports.Server))

	for i := 1; i <= 3; i++ {
		uri := fmt.Sprintf("http://%s:%d/64B?repeat=%d", s.ServerAddr(), s.Ports.Server, i)
		finished := startCurlHttpRequest(uri, s.NetNamespaces.Client, "200 OK", 20)
		waitProxyLiteTrackedCount(vpp, i, func() {})
		AssertNil(<-finished)
	}

	output := vpp.Vppctl("show proxy-lite")
	Log(output)
	AssertContains(output, "hsi tracked 3")
	AssertContains(output, "failed 0")

	assertProxyLiteSessionsCleanedCount(s, 6)
}

func runHsiProxyLiteDrainOffloadTest(s *HsiSuite) {
	s.SetupNginxServer()
	vpp := s.Containers.Vpp.VppInstance
	Log(vpp.Vppctl("proxy-lite server-uri tcp://0.0.0.0:%d client-uri tcp://%s:%d hsi-offload fifo-size 4k",
		s.Ports.Server, s.ServerAddr(), s.Ports.Server))

	uploadFileName := makeProxyLiteUploadFile()
	defer os.Remove(uploadFileName)

	uri := fmt.Sprintf("http://%s:%d/upload/hsi-proxy-lite-upload", s.ServerAddr(), s.Ports.Server)
	finished := startCurlHttpRequest(uri, s.NetNamespaces.Client, "201", 60,
		"-T", uploadFileName, "-H", "Expect:", "--limit-rate", "256k")

	waitProxyLiteTracked(vpp, func() {})

	AssertNil(<-finished)

	output := vpp.Vppctl("show proxy-lite")
	Log(output)
	AssertContains(output, "hsi tracked 1")
	AssertContains(output, "failed 0")
	hsi := waitHsiCounterAtLeast(vpp, "tcp-drain-completed", 2)
	Log(hsi)

	assertProxyLiteSessionsCleaned(s)
}

func HsiProxyLiteDrainOffloadTest(s *HsiSuite) {
	runHsiProxyLiteDrainOffloadTest(s)
}

func HsiProxyLiteDrainOffloadMWTest(s *HsiSuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	runHsiProxyLiteDrainOffloadTest(s)
}

func runHsiProxyLiteUdpConnectedTest(s *HsiSuite) {
	remoteServerConn := StartUdpEchoServer(s.ServerAddr(), int(s.Ports.Server))
	defer remoteServerConn.Close()

	vpp := s.Containers.Vpp.VppInstance
	Log(vpp.Vppctl("proxy-lite server-uri udp://0.0.0.0:%d client-uri udp://%s:%d hsi-offload fifo-size 4k",
		s.Ports.Server, s.ServerAddr(), s.Ports.Server))

	finished := startUdpEchoClient(s.ServerAddr(), s.Ports.Server, s.NetNamespaces.Client,
		time.Second, "hsi-udp-warm", "hsi-udp-first", "hsi-udp-second")
	waitProxyLiteTracked(vpp, func() {})
	result := <-finished
	Log(result.output)
	AssertNil(result.err, result.output)
	AssertContains(result.output, "hsi-udp-second")

	output := vpp.Vppctl("show proxy-lite")
	Log(output)
	AssertContains(output, "hsi tracked 1")
	AssertContains(output, "failed 0")

	hsi := waitHsiCounterAtLeast(vpp, "udp-track-accepted", 1)
	Log(hsi)
}

func HsiProxyLiteUdpConnectedTest(s *HsiSuite) {
	runHsiProxyLiteUdpConnectedTest(s)
}

func HsiProxyLiteUdpConnectedMWTest(s *HsiSuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()

	remoteServerConn := StartUdpEchoServer(s.ServerAddr(), int(s.Ports.Server))
	defer remoteServerConn.Close()

	vpp := s.Containers.Vpp.VppInstance
	Log(vpp.Vppctl("proxy-lite server-uri udp://0.0.0.0:%d client-uri udp://%s:%d hsi-offload fifo-size 4k",
		s.Ports.Server, s.ServerAddr(), s.Ports.Server))

	for i := 0; i < 8; i++ {
		second := fmt.Sprintf("hsi-udp-second-%d", i)
		finished := startUdpEchoClient(s.ServerAddr(), s.Ports.Server, s.NetNamespaces.Client,
			time.Second, fmt.Sprintf("hsi-udp-warm-%d", i), fmt.Sprintf("hsi-udp-first-%d", i),
			second)
		waitProxyLiteTrackedCount(vpp, i+1, func() {})
		result := <-finished
		Log(result.output)
		AssertNil(result.err, result.output)
		AssertContains(result.output, second)

		hsi := vpp.Vppctl("show hsi")
		if hsiCounterValue(hsi, "udp-track-migrated") > 0 {
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
	Log(vpp.Vppctl("proxy-lite server-uri udp://0.0.0.0:%d client-uri udp://%s:%d hsi-offload fifo-size 4k",
		s.Ports.Server, s.ServerAddr(), s.Ports.Server))

	finished := startUdpEchoClient(s.ServerAddr(), s.Ports.Server, s.NetNamespaces.Client,
		time.Second, "hsi-udp-drain-warm", "hsi-udp-drain-first", "hsi-udp-drain-second")
	waitProxyLiteTracked(vpp, func() {})
	result := <-finished
	Log(result.output)
	AssertNil(result.err, result.output)
	AssertContains(result.output, "hsi-udp-drain-second")

	hsi := waitHsiCounterAtLeast(vpp, "udp-track-accepted", 1)
	Log(hsi)
	hsi = waitHsiCounterAtLeast(vpp, "udp-drain-started", 2)
	Log(hsi)
	hsi = assertHsiUdpDrainCompleted(vpp)
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
	Log(vpp.Vppctl("proxy-lite server-uri udp://0.0.0.0:%d client-uri udp://%s:%d hsi-offload-stall fifo-size 4k",
		s.Ports.Server, s.ServerAddr(), s.Ports.Server))

	finished := sendUdpDatagrams(s.ServerAddr(), s.Ports.Server, s.NetNamespaces.Client,
		300*time.Millisecond, "hsi-udp-overflow-warm", "hsi-udp-overflow-1",
		"hsi-udp-overflow-2", "hsi-udp-overflow-3", "hsi-udp-overflow-4")
	waitProxyLiteTracked(vpp, func() {})
	AssertNil((<-finished).err)

	hsi := waitHsiCounterAtLeast(vpp, "udp-drain-cache-overflow", 1)
	Log(hsi)
	hsi = waitHsiCounterAtLeast(vpp, "udp-drain-cache-dropped", 1)
	Log(hsi)
	hsi = assertHsiUdpCleaned(vpp, 2)
	Log(hsi)
}

func HsiProxyLiteUdpDrainTimeoutTest(s *HsiSuite) {
	remoteServerConn := StartUdpEchoServer(s.ServerAddr(), int(s.Ports.Server))
	defer remoteServerConn.Close()

	vpp := s.Containers.Vpp.VppInstance
	Log(vpp.Vppctl("hsi udp drain-timeout 1"))
	Log(vpp.Vppctl("proxy-lite server-uri udp://0.0.0.0:%d client-uri udp://%s:%d hsi-offload-stall fifo-size 4k",
		s.Ports.Server, s.ServerAddr(), s.Ports.Server))

	finished := sendUdpDatagrams(s.ServerAddr(), s.Ports.Server, s.NetNamespaces.Client,
		0, "hsi-udp-timeout-warm")
	AssertNil((<-finished).err)
	waitProxyLiteTracked(vpp, func() {})

	hsi := waitHsiCounterAtLeast(vpp, "udp-drain-stalled", 1)
	Log(hsi)
	hsi = assertHsiUdpCleaned(vpp, 2)
	Log(hsi)
}

func HsiProxyLiteUdpIdleDisabledTest(s *HsiSuite) {
	remoteServerConn := StartUdpEchoServer(s.ServerAddr(), int(s.Ports.Server))
	defer remoteServerConn.Close()

	vpp := s.Containers.Vpp.VppInstance
	Log(vpp.Vppctl("hsi udp idle-timeout 0"))
	Log(vpp.Vppctl("proxy-lite server-uri udp://0.0.0.0:%d client-uri udp://%s:%d hsi-offload fifo-size 4k",
		s.Ports.Server, s.ServerAddr(), s.Ports.Server))

	finished := startUdpEchoClient(s.ServerAddr(), s.Ports.Server, s.NetNamespaces.Client,
		100*time.Millisecond, "hsi-udp-idle-disabled-warm", "hsi-udp-idle-disabled-first",
		"hsi-udp-idle-disabled-second")
	waitProxyLiteTracked(vpp, func() {})
	result := <-finished
	Log(result.output)
	AssertNil(result.err, result.output)
	AssertContains(result.output, "hsi-udp-idle-disabled-second")

	time.Sleep(1500 * time.Millisecond)
	hsi := vpp.Vppctl("show hsi")
	Log(hsi)
	AssertEqual(0, hsiCounterValue(hsi, "udp-idle-timeout"))
	AssertEqual(0, hsiCounterValue(hsi, "udp-idle-cleanup-scheduled"))
	AssertContains(hsi, "udp-tracked session")
	AssertNotContains(hsi, "udp-drain session")
}

func runHsiProxyLiteUdpIdleTimeoutTest(s *HsiSuite) {
	remoteServerConn := StartUdpEchoServer(s.ServerAddr(), int(s.Ports.Server))
	defer remoteServerConn.Close()

	vpp := s.Containers.Vpp.VppInstance
	Log(vpp.Vppctl("hsi udp idle-timeout 1"))
	Log(vpp.Vppctl("proxy-lite server-uri udp://0.0.0.0:%d client-uri udp://%s:%d hsi-offload fifo-size 4k",
		s.Ports.Server, s.ServerAddr(), s.Ports.Server))

	finished := startUdpEchoClient(s.ServerAddr(), s.Ports.Server, s.NetNamespaces.Client,
		100*time.Millisecond, "hsi-udp-idle-warm", "hsi-udp-idle-first", "hsi-udp-idle-second")
	waitProxyLiteTracked(vpp, func() {})
	result := <-finished
	Log(result.output)
	AssertNil(result.err, result.output)
	AssertContains(result.output, "hsi-udp-idle-second")

	hsi := waitHsiCounterAtLeast(vpp, "udp-idle-timeout", 1)
	Log(hsi)
	hsi = waitHsiCounterAtLeast(vpp, "udp-cleanup-completed", 2)
	Log(hsi)
	AssertEqual(1, hsiCounterValue(hsi, "udp-idle-cleanup-scheduled"))
	AssertNotContains(hsi, "udp-tracked session")
}

func HsiProxyLiteUdpIdleTimeoutTest(s *HsiSuite) {
	runHsiProxyLiteUdpIdleTimeoutTest(s)
}

func HsiProxyLiteUdpIdleTimeoutMWTest(s *HsiSuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	runHsiProxyLiteUdpIdleTimeoutTest(s)
}

func HsiProxyLiteDrainCacheOverflowTest(s *HsiSuite) {
	s.SetupNginxServer()
	vpp := s.Containers.Vpp.VppInstance
	Log(vpp.Vppctl("hsi tcp drain-cache max-packets 1"))
	Log(vpp.Vppctl("proxy-lite server-uri tcp://0.0.0.0:%d client-uri tcp://%s:%d hsi-offload fifo-size 4k",
		s.Ports.Server, s.ServerAddr(), s.Ports.Server))

	uploadFileName := makeProxyLiteUploadFile()
	defer os.Remove(uploadFileName)

	uri := fmt.Sprintf("http://%s:%d/upload/hsi-proxy-lite-overflow", s.ServerAddr(), s.Ports.Server)
	finished := startCurlHttpRequest(uri, s.NetNamespaces.Client, "201", 10,
		"-T", uploadFileName, "-H", "Expect:", "--limit-rate", "256k")

	waitProxyLiteTracked(vpp, func() {})

	AssertNotNil(<-finished)
	hsi := waitHsiContains(vpp, "tcp-drain-cache-overflow 1")
	Log(hsi)
	assertProxyLiteSessionsCleaned(s)
}

func HsiProxyLiteDrainTimeoutTest(s *HsiSuite) {
	s.SetupNginxServer()
	vpp := s.Containers.Vpp.VppInstance
	Log(vpp.Vppctl("hsi tcp drain-timeout 1"))
	Log(vpp.Vppctl("proxy-lite server-uri tcp://0.0.0.0:%d client-uri tcp://%s:%d hsi-offload-stall fifo-size 4k",
		s.Ports.Server, s.ServerAddr(), s.Ports.Server))

	uploadFileName := makeProxyLiteUploadFile()
	defer os.Remove(uploadFileName)

	uri := fmt.Sprintf("http://%s:%d/upload/hsi-proxy-lite-timeout", s.ServerAddr(), s.Ports.Server)
	finished := startCurlHttpRequest(uri, s.NetNamespaces.Client, "201", 20,
		"-T", uploadFileName, "-H", "Expect:", "--limit-rate", "256k")

	waitProxyLiteTracked(vpp, func() {})

	AssertNotNil(<-finished)
	hsi := waitHsiContains(vpp, "tcp-drain-stalled 1")
	Log(hsi)
	assertProxyLiteSessionsCleaned(s)
}

func runHsiProxyLiteClientAbortTest(s *HsiSuite) {
	s.SetupNginxServer()
	vpp := s.Containers.Vpp.VppInstance
	Log(vpp.Vppctl("proxy-lite server-uri tcp://0.0.0.0:%d client-uri tcp://%s:%d hsi-offload",
		s.Ports.Server, s.ServerAddr(), s.Ports.Server))

	uri := fmt.Sprintf("http://%s:%d/httpTestFile", s.ServerAddr(), s.Ports.Server)
	finished := startCurlHttpRequest(uri, s.NetNamespaces.Client, "200", 2,
		"--limit-rate", "1k")
	waitProxyLiteTracked(vpp, func() {})

	AssertNotNil(<-finished)
	hsi := waitHsiContains(vpp, "tcp-rst-cleanup 1")
	Log(hsi)
	assertProxyLiteSessionsCleaned(s)
}

func HsiProxyLiteClientAbortTest(s *HsiSuite) {
	runHsiProxyLiteClientAbortTest(s)
}

func HsiTrackerTcpFinTest(s *HsiSuite) {
	s.SetupNginxServer()
	vpp := s.Containers.Vpp.VppInstance
	Log(vpp.Vppctl("proxy-lite server-uri tcp://0.0.0.0:%d client-uri tcp://%s:%d hsi-offload",
		s.Ports.Server, s.ServerAddr(), s.Ports.Server))

	uri := fmt.Sprintf("http://%s:%d/64B", s.ServerAddr(), s.Ports.Server)
	finished := startCurlHttpRequest(uri, s.NetNamespaces.Client, "200 OK", 20)
	waitProxyLiteTracked(vpp, func() {})
	AssertNil(<-finished)

	hsi := waitHsiContains(vpp, "tcp-fin-cleanup 1")
	Log(hsi)
	assertProxyLiteSessionsCleaned(s)
}

func HsiTrackerTcpRstValidationTest(s *HsiSuite) {
	runHsiProxyLiteClientAbortTest(s)
}
