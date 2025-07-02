package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterH2Tests(Http2TcpGetTest, Http2TcpPostTest, Http2MultiplexingTest, Http2TlsTest, Http2ContinuationTxTest, Http2ServerMemLeakTest)
	RegisterH2MWTests(Http2MultiplexingMWTest)
}

func Http2TcpGetTest(s *Http2Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	vpp.Vppctl("http cli server listener add uri tcp://" + serverAddress)
	s.Log(vpp.Vppctl("show session verbose 2"))
	args := fmt.Sprintf("--max-time 10 --noproxy '*' --http2-prior-knowledge http://%s/show/version", serverAddress)
	writeOut, log := s.RunCurlContainer(s.Containers.Curl, args)
	s.Log(vpp.Vppctl("show session verbose 2"))
	s.AssertContains(log, "HTTP/2 200")
	s.AssertContains(writeOut, "<html>", "<html> not found in the result!")
	s.AssertContains(writeOut, "</html>", "</html> not found in the result!")

	/* test session cleanup */
	httpStreamCleanupDone := false
	tcpSessionCleanupDone := false
	for nTries := 0; nTries < 30; nTries++ {
		o := vpp.Vppctl("show session verbose 2")
		if !strings.Contains(o, "[T] "+serverAddress+"->10.") {
			tcpSessionCleanupDone = true
		}
		if !strings.Contains(o, "[H2]") {
			httpStreamCleanupDone = true
		}
		if httpStreamCleanupDone && tcpSessionCleanupDone {
			break
		}
		time.Sleep(1 * time.Second)
	}
	s.AssertEqual(true, tcpSessionCleanupDone, "TCP session not cleaned up")
	s.AssertEqual(true, httpStreamCleanupDone, "HTTP/2 stream not cleaned up")

	/* test server app stop listen */
	vpp.Vppctl("http cli server listener del uri tcp://" + serverAddress)
	o := vpp.Vppctl("show session verbose proto http")
	s.AssertNotContains(o, "LISTEN")
}

func Http2TcpPostTest(s *Http2Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers max-body-size 20m rx-buff-thresh 20m fifo-size 65k debug 2"))
	s.Log(vpp.Vppctl("test-url-handler enable"))
	args := fmt.Sprintf("--max-time 10 --noproxy '*' --data-binary @%s --http2-prior-knowledge http://%s/test3", CurlContainerTestFile, serverAddress)
	_, log := s.RunCurlContainer(s.Containers.Curl, args)
	s.AssertContains(log, "HTTP/2 200")
}

func Http2MultiplexingTest(s *Http2Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	vpp.Vppctl("http tps uri tcp://" + serverAddress + " no-zc")

	args := fmt.Sprintf("--log-file=%s -T10 -n21 -c1 -m100 http://%s/test_file_20M", s.H2loadLogFileName(s.Containers.H2load), serverAddress)
	s.Containers.H2load.ExtraRunningArgs = args
	s.Containers.H2load.Run()

	defer s.CollectH2loadLogs(s.Containers.H2load)

	o, _ := s.Containers.H2load.GetOutput()
	s.Log(o)
	s.AssertContains(o, " 0 failed")
	s.AssertContains(o, " 0 errored")
	s.AssertContains(o, " 0 timeout")
}

func Http2MultiplexingMWTest(s *Http2Suite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	vpp.Vppctl("http tps uri tcp://" + serverAddress + " no-zc")

	args := fmt.Sprintf("-T10 -n100 -c4 -r1 -m10 http://%s/test_file_20M", serverAddress)
	s.Containers.H2load.ExtraRunningArgs = args
	s.Containers.H2load.Run()

	o, _ := s.Containers.H2load.GetOutput()
	s.Log(o)
	s.AssertContains(o, " 0 failed")
	s.AssertContains(o, " 0 errored")
	s.AssertContains(o, " 0 timeout")
}

func Http2TlsTest(s *Http2Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	s.Log(vpp.Vppctl("http static server uri tls://" + serverAddress + " url-handlers debug"))

	args := fmt.Sprintf("--max-time 10 --noproxy '*' -k https://%s/version.json", serverAddress)
	writeOut, log := s.RunCurlContainer(s.Containers.Curl, args)
	s.Log(vpp.Vppctl("show session verbose 2"))
	s.AssertContains(log, "HTTP/2 200")
	s.AssertContains(log, "ALPN: server accepted h2")
	s.AssertContains(writeOut, "version")
}

func Http2ContinuationTxTest(s *Http2Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	vpp.Vppctl("http tps uri tcp://" + serverAddress + " no-zc")
	args := fmt.Sprintf("-w %%{size_header} --max-time 10 --noproxy '*' --http2-prior-knowledge http://%s/test_file_64?test_header=32k", serverAddress)
	writeOut, log := s.RunCurlContainer(s.Containers.Curl, args)
	s.AssertContains(log, "HTTP/2 200")
	s.AssertContains(log, "[64 bytes data]")
	sizeHeader, err := strconv.Atoi(strings.ReplaceAll(writeOut, "\x00", ""))
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertGreaterThan(sizeHeader, 32768)
}

func Http2ServerMemLeakTest(s *Http2Suite) {
	s.SkipUnlessLeakCheck()

	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	vpp.Vppctl("http cli server uri http://" + serverAddress)
	target := fmt.Sprintf("http://%s/show/version", serverAddress)

	/* no goVPP less noise */
	vpp.Disconnect()

	/* warmup request (FIB) */
	args := fmt.Sprintf("--max-time 10 --noproxy '*' --http2-prior-knowledge -z %s %s %s %s", target, target, target, target)
	_, log := s.RunCurlContainer(s.Containers.Curl, args)
	s.AssertContains(log, "HTTP/2 200")

	vpp.EnableMemoryTrace()
	traces1, err := vpp.GetMemoryTrace()
	s.AssertNil(err, fmt.Sprint(err))

	for i := 0; i < 10; i++ {
		time.Sleep(time.Second * 1)
		s.AssertNil(s.Containers.Curl.Start())
	}

	/* let's give it some time to clean up sessions */
	time.Sleep(time.Second * 15)

	traces2, err := vpp.GetMemoryTrace()
	s.AssertNil(err, fmt.Sprint(err))
	vpp.MemLeakCheck(traces1, traces2)
}
