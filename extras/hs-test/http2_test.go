package main

import (
	"fmt"
	"strings"
	"time"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterH2Tests(Http2TcpGetTest)
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
