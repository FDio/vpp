package main

import (
	"fmt"
	"strings"
	"time"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterH2Tests(Http2TcpGetTest, Http2TcpPostTest, Http2MultiplexingTest)
}

func Http2TcpGetTest(s *H2Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr()
	vpp.Vppctl("http cli server")
	s.Log(vpp.Vppctl("show session verbose 2"))
	args := fmt.Sprintf("--max-time 10 --noproxy '*' --http2-prior-knowledge http://%s:80/show/version", serverAddress)
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
		if !strings.Contains(o, "[T] "+serverAddress+":80->") {
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
	s.AssertEqual(true, tcpSessionCleanupDone, "TCP session not cleanup")
	s.AssertEqual(true, httpStreamCleanupDone, "HTTP/2 stream not cleanup")

	/* test server app stop listen */
	vpp.Vppctl("http cli server listener del")
	o := vpp.Vppctl("show session verbose proto http")
	s.AssertNotContains(o, "LISTEN")
}

func Http2TcpPostTest(s *H2Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr()
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers max-body-size 20m rx-buff-thresh 20m fifo-size 65k debug 2"))
	s.Log(vpp.Vppctl("test-url-handler enable"))
	args := fmt.Sprintf("--max-time 10 --noproxy '*' --data-binary @%s --http2-prior-knowledge http://%s:80/test3", CurlContainerTestFile, serverAddress)
	_, log := s.RunCurlContainer(s.Containers.Curl, args)
	s.AssertContains(log, "HTTP/2 200")
}

func Http2MultiplexingTest(s *H2Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr()
	vpp.Vppctl("http tps uri tcp://0.0.0.0/80")

	args := fmt.Sprintf("-T10 -n20 -c1 -m100 http://%s:80/test_file_10M", serverAddress)
	s.Containers.H2load.ExtraRunningArgs = args
	s.Containers.H2load.Run()

	o, _ := s.Containers.H2load.GetOutput()
	s.Log(o)
	s.AssertContains(o, "0 failed")
	s.AssertContains(o, "0 errored")
	s.AssertContains(o, "0 timeout")
}
