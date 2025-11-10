package main

import (
	"fmt"
	"strings"
	"time"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterH3Tests(Http3GetTest, Http3DownloadTest)
}

func Http3GetTest(s *Http3Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	s.Log(vpp.Vppctl("http cli server http3-enabled listener add uri https://" + serverAddress))
	s.Log(vpp.Vppctl("show session verbose 2"))
	args := fmt.Sprintf("-k --max-time 10 --noproxy '*' --http3-only https://%s/show/version", serverAddress)
	writeOut, log := s.RunCurlContainer(s.Containers.Curl, args)
	s.Log(vpp.Vppctl("show session verbose 2"))
	s.AssertContains(log, "HTTP/3 200")
	s.AssertContains(writeOut, "<html>", "<html> not found in the result!")
	s.AssertContains(writeOut, "</html>", "</html> not found in the result!")

	/* test session cleanup */
	udpCleanupDone := false
	quicCleanupDone := false
	httpCleanupDone := false
	for nTries := 0; nTries < 5; nTries++ {
		o := vpp.Vppctl("show session verbose 2")
		if !strings.Contains(o, "[U] "+serverAddress+"->10.") {
			udpCleanupDone = true
		}
		if strings.Count(o, "[Q]") == 1 {
			quicCleanupDone = true
		}
		if !strings.Contains(o, "[H3]") {
			httpCleanupDone = true
		}
		if httpCleanupDone && udpCleanupDone && quicCleanupDone {
			break
		}
		time.Sleep(1 * time.Second)
	}
	s.AssertEqual(true, udpCleanupDone, "UDP session not cleaned up")
	s.AssertEqual(true, quicCleanupDone, "QUIC not cleaned up")
	s.AssertEqual(true, httpCleanupDone, "HTTP/3 not cleaned up")
	o := vpp.Vppctl("show http stats")
	s.Log(o)
	s.AssertContains(o, "1 connections accepted")
	s.AssertContains(o, "1 application streams opened")
	s.AssertContains(o, "1 application streams closed")
	s.AssertContains(o, "4 control streams opened")
	s.AssertContains(o, "4 control streams closed")

	/* test server app stop listen */
	s.Log(vpp.Vppctl("http cli server listener del uri https://" + serverAddress))
	o = vpp.Vppctl("show session verbose")
	s.AssertNotContains(o, "LISTEN")
}

func Http3DownloadTest(s *Http3Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	s.Log(vpp.Vppctl("http tps no-zc h3 uri https://" + serverAddress))

	uri := fmt.Sprintf("https://%s/test_file_10M", serverAddress)
	args := fmt.Sprintf("-k --max-time 60 --noproxy '*' --http3-only -o /tmp/tmp.txt %s", uri)
	_, log := s.RunCurlContainer(s.Containers.Curl, args)
	s.AssertContains(log, "HTTP/3 200")
	s.AssertNotContains(log, "Operation timed out")
}
