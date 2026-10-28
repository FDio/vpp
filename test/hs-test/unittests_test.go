package main

import (
	"strings"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterNoTopoTests(HttpUnitTest, HttpUnitTestRxPublication, TcpUnitTest, UdpUnitTest, SvmUnitTest, SessionUnitTest, QuicUnitTest,
		QuicQuiclyUnitTest)
}

func runUnitTest(s *NoTopoSuite, vppCmd string) string {
	vpp := s.Containers.Vpp.VppInstance
	o := vpp.Vppctl(vppCmd)
	Log(o)
	// Match the result line, not words such as "successfully" in assertions.
	AssertContains("\n"+strings.ReplaceAll(o, "\r", "")+"\n", "\nSUCCESS\n")
	AssertNotContains(o, "unknown input")
	return o
}

func HttpUnitTest(s *NoTopoSuite) {
	AssertNotContains(s.Containers.Vpp.VppInstance.Vppctl("show session stats"), "Thread")
	runUnitTest(s, "test http all")
	runUnitTest(s, "test http rx-publication")
	AssertContains(s.Containers.Vpp.VppInstance.Vppctl("show session"), "no sessions")
}

func HttpUnitTestRxPublication(s *NoTopoSuite) {
	AssertNotContains(s.Containers.Vpp.VppInstance.Vppctl("show session stats"), "Thread")
	o := runUnitTest(s, "test http rx-publication")
	AssertContains(o, "RX test segment allocated")
	AssertContains(o, "polling consumer cannot read partial headers or metadata")
	AssertContains(o, "metadata and all staged bytes become readable together")
	// Repeating the test also exercises the already-enabled session layer.
	runUnitTest(s, "test http rx-publication")
	AssertContains(s.Containers.Vpp.VppInstance.Vppctl("show session"), "no sessions")
	for _, command := range []string{
		"test http invalid-rx-publication-test",
		"test http rx-publication invalid-rx-publication-test",
	} {
		o = s.Containers.Vpp.VppInstance.Vppctl(command)
		AssertContains(o, "unknown input")
		AssertNotContains("\n"+strings.ReplaceAll(o, "\r", "")+"\n", "\nSUCCESS\n")
	}
}

func QuicUnitTest(s *NoTopoSuite) {
	runUnitTest(s, "test quic all")
}

func QuicQuiclyUnitTest(s *NoTopoSuite) {
	runUnitTest(s, "test quicly all")
}

func TcpUnitTest(s *NoTopoSuite) {
	s.SkipIfNotCoverage()
	runUnitTest(s, "test tcp all")
}

func UdpUnitTest(s *NoTopoSuite) {
	runUnitTest(s, "test udp all")
}

func SvmUnitTest(s *NoTopoSuite) {
	s.SkipIfNotCoverage()
	runUnitTest(s, "test svm fifo all")
}

func SessionUnitTest(s *NoTopoSuite) {
	s.SkipIfNotCoverage()
	runUnitTest(s, "test session all")
}
