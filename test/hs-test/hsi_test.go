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
		HsiProxyLiteDrainOffloadTest)
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
	Log(vpp.Vppctl("proxy-lite server-uri tcp://0.0.0.0:%d client-uri tcp://%s:%d hsi-offload-pending",
		s.Ports.Server, s.ServerAddr(), s.Ports.Server))

	uri := fmt.Sprintf("http://%s:%d/64B", s.ServerAddr(), s.Ports.Server)
	finished := startCurlHttpRequest(uri, s.NetNamespaces.Client, "200 OK", 20)
	waitProxyLiteTracked(vpp, func() {})
	AssertNil(<-finished)

	output := vpp.Vppctl("show proxy-lite")
	Log(output)
	AssertContains(output, "hsi tracked 1")
	AssertContains(output, "failed 0")
	AssertContains(output, "skipped-pending 0")

	assertProxyLiteSessionsCleaned(s)
}

func HsiProxyLiteDrainOffloadTest(s *HsiSuite) {
	s.SetupNginxServer()
	vpp := s.Containers.Vpp.VppInstance
	Log(vpp.Vppctl("proxy-lite server-uri tcp://0.0.0.0:%d client-uri tcp://%s:%d hsi-offload-pending fifo-size 4k",
		s.Ports.Server, s.ServerAddr(), s.Ports.Server))

	uploadFile, err := os.CreateTemp("", "hsi-proxy-lite-upload-*")
	AssertNil(err)
	defer os.Remove(uploadFile.Name())
	_, err = uploadFile.Write(bytes.Repeat([]byte("0123456789abcdef"), 64*1024))
	AssertNil(err)
	AssertNil(uploadFile.Close())

	uri := fmt.Sprintf("http://%s:%d/upload/hsi-proxy-lite-upload", s.ServerAddr(), s.Ports.Server)
	finished := startCurlHttpRequest(uri, s.NetNamespaces.Client, "201", 60,
		"-T", uploadFile.Name(), "-H", "Expect:", "--limit-rate", "256k")

	output := waitProxyLiteTracked(vpp, func() {})
	AssertContains(output, "pending 1")

	AssertNil(<-finished)

	output = vpp.Vppctl("show proxy-lite")
	Log(output)
	AssertContains(output, "hsi tracked 1")
	AssertContains(output, "failed 0")
	AssertContains(output, "skipped-pending 0")
	AssertContains(output, "pending 1")

	assertProxyLiteSessionsCleaned(s)
}
