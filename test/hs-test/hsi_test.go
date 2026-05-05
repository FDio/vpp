package main

import (
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
		HsiProxyLiteRstCleanupTest, HsiProxyLiteDrainOffloadTest)
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

func startDelayedHttpRequest(serverIP string, port uint16, query, netNs string) (func() error, func(), <-chan error) {
	finished := make(chan error, 1)
	script := fmt.Sprintf(
		"set -e; exec 3<>/dev/tcp/%s/%d; read -r _; printf 'GET /%s HTTP/1.1\\r\\nHost: %s\\r\\nConnection: close\\r\\n\\r\\n' >&3; while IFS= read -r line <&3; do printf '%%s\\n' \"$line\"; [ \"$line\" = $'\\r' ] && break; done; cat <&3 >/dev/null",
		serverIP, port, query, serverIP,
	)
	cmd := CommandInNetns([]string{"timeout", "20", "bash", "-c", script}, netNs)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		finished <- err
		return func() error { return err }, func() {}, finished
	}

	go func() {
		Log(cmd)
		o, err := cmd.CombinedOutput()
		Log(string(o))
		if err != nil {
			finished <- fmt.Errorf("delayed http request failed: '%v\n\n%s'", err, o)
			return
		}
		if !strings.Contains(string(o), "200 OK") {
			finished <- fmt.Errorf("delayed http request failed: response not 200 OK")
			return
		}
		finished <- nil
	}()

	release := func() error {
		_, err := stdin.Write([]byte("\n"))
		if err != nil {
			return err
		}
		return stdin.Close()
	}
	cancel := func() {
		_ = stdin.Close()
	}
	return release, cancel, finished
}

func startSplitHttpRequest(serverIP string, port uint16, query, netNs string) (func() error, func(), <-chan error) {
	finished := make(chan error, 1)
	script := fmt.Sprintf(
		"set -e; exec 3<>/dev/tcp/%s/%d; printf 'GET /%s HTTP/1.1\\r\\nHost: %s\\r\\n' >&3; read -r _; printf 'Connection: close\\r\\n\\r\\n' >&3; while IFS= read -r line <&3; do printf '%%s\\n' \"$line\"; [ \"$line\" = $'\\r' ] && break; done; cat <&3 >/dev/null",
		serverIP, port, query, serverIP,
	)
	cmd := CommandInNetns([]string{"timeout", "20", "bash", "-c", script}, netNs)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		finished <- err
		return func() error { return err }, func() {}, finished
	}

	go func() {
		Log(cmd)
		o, err := cmd.CombinedOutput()
		Log(string(o))
		if err != nil {
			finished <- fmt.Errorf("split http request failed: '%v\n\n%s'", err, o)
			return
		}
		if !strings.Contains(string(o), "200 OK") {
			finished <- fmt.Errorf("split http request failed: response not 200 OK")
			return
		}
		finished <- nil
	}()

	release := func() error {
		_, err := stdin.Write([]byte("\n"))
		if err != nil {
			return err
		}
		return stdin.Close()
	}
	cancel := func() {
		_ = stdin.Close()
	}
	return release, cancel, finished
}

func startResetConnection(serverIP string, port uint16, netNs string) (func() error, func(), <-chan error) {
	finished := make(chan error, 1)
	script := fmt.Sprintf(
		"import socket, struct, sys\n"+
			"s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"+
			"s.connect(('%s', %d))\n"+
			"sys.stdin.buffer.read(1)\n"+
			"s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))\n"+
			"s.close()\n",
		serverIP, port,
	)
	cmd := CommandInNetns([]string{"timeout", "20", "python3", "-c", script}, netNs)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		finished <- err
		return func() error { return err }, func() {}, finished
	}

	go func() {
		Log(cmd)
		o, err := cmd.CombinedOutput()
		Log(string(o))
		if err != nil {
			finished <- fmt.Errorf("reset connection failed: '%v\n\n%s'", err, o)
			return
		}
		finished <- nil
	}()

	release := func() error {
		_, err := stdin.Write([]byte{0})
		if err != nil {
			return err
		}
		return stdin.Close()
	}
	cancel := func() {
		_ = stdin.Close()
	}
	return release, cancel, finished
}

func waitProxyLiteTracked(vpp *VppInstance, cancel func()) string {
	var lastOutput string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		output := vpp.Vppctl("show proxy-lite")
		if output != "" {
			lastOutput = output
		}
		if strings.Contains(output, "hsi tracked 1") {
			return output
		}
		if strings.Contains(output, "failed 1") || strings.Contains(output, "skipped-pending 1") {
			cancel()
			AssertFail("proxy-lite hsi offload failed before completion:\n%s", output)
		}
		time.Sleep(100 * time.Millisecond)
	}

	cancel()
	AssertFail("timed out waiting for proxy-lite hsi offload; last output:\n%s", lastOutput)
	return lastOutput
}

func assertProxyLiteSessionsCleaned(s *HsiSuite) {
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

	sessions := vpp.Vppctl("show session verbose 2")
	Log(sessions)
	AssertNotContains(sessions, proxyClientConn, "client-proxy session not cleaned up")
	AssertNotContains(sessions, proxyTargetConn, "proxy-server session not cleaned up")
}

func HsiProxyLiteOffloadTest(s *HsiSuite) {
	s.SetupNginxServer()
	vpp := s.Containers.Vpp.VppInstance
	Log(vpp.Vppctl("proxy-lite server-uri tcp://0.0.0.0:%d client-uri tcp://%s:%d hsi-offload",
		s.Ports.Server, s.ServerAddr(), s.Ports.Server))

	query := "httpTestFile"
	releaseRequest, cancelRequest, finished := startDelayedHttpRequest(
		s.ServerAddr(), s.Ports.Server, query, s.NetNamespaces.Client)

	select {
	case err := <-finished:
		AssertNil(err, "client exited before hsi tracking completed")
	default:
	}
	waitProxyLiteTracked(vpp, cancelRequest)

	AssertNil(releaseRequest(), "failed to release delayed http request")
	AssertNil(<-finished)

	output := vpp.Vppctl("show proxy-lite")
	Log(output)
	AssertContains(output, "hsi tracked 1")
	AssertContains(output, "failed 0")
	AssertContains(output, "skipped-pending 0")

	assertProxyLiteSessionsCleaned(s)
}

func HsiProxyLiteRstCleanupTest(s *HsiSuite) {
	s.SetupNginxServer()
	vpp := s.Containers.Vpp.VppInstance
	Log(vpp.Vppctl("proxy-lite server-uri tcp://0.0.0.0:%d client-uri tcp://%s:%d hsi-offload",
		s.Ports.Server, s.ServerAddr(), s.Ports.Server))

	releaseReset, cancelReset, finished := startResetConnection(
		s.ServerAddr(), s.Ports.Server, s.NetNamespaces.Client)

	waitProxyLiteTracked(vpp, cancelReset)
	AssertNil(releaseReset(), "failed to release reset connection")
	AssertNil(<-finished)

	output := vpp.Vppctl("show proxy-lite")
	Log(output)
	AssertContains(output, "hsi tracked 1")
	AssertContains(output, "failed 0")

	assertProxyLiteSessionsCleaned(s)
}

func HsiProxyLiteDrainOffloadTest(s *HsiSuite) {
	s.SetupNginxServer()
	vpp := s.Containers.Vpp.VppInstance
	Log(vpp.Vppctl("proxy-lite server-uri tcp://0.0.0.0:%d client-uri tcp://%s:%d hsi-offload-pending",
		s.Ports.Server, s.ServerAddr(), s.Ports.Server))

	query := "httpTestFile"
	releaseRequest, cancelRequest, finished := startSplitHttpRequest(
		s.ServerAddr(), s.Ports.Server, query, s.NetNamespaces.Client)

	output := waitProxyLiteTracked(vpp, cancelRequest)
	AssertContains(output, "pending 1")

	AssertNil(releaseRequest(), "failed to release split http request")
	AssertNil(<-finished)

	output = vpp.Vppctl("show proxy-lite")
	Log(output)
	AssertContains(output, "hsi tracked 1")
	AssertContains(output, "failed 0")
	AssertContains(output, "skipped-pending 0")
	AssertContains(output, "pending 1")

	assertProxyLiteSessionsCleaned(s)
}
