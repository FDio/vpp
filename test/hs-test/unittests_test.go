package main

import (
	. "fd.io/hs-test/infra"
)

func init() {
	RegisterNoTopoTests(HttpUnitTest, TcpUnitTest, UdpUnitTest, SvmUnitTest, SessionUnitTest, QuicUnitTest,
		QuicQuiclyUnitTest)
	RegisterNoTopoMWTests(HttpListenerMetadataMWTest)
}

func runUnitTest(s *NoTopoSuite, vppCmd string) {
	vpp := s.Containers.Vpp.VppInstance
	o := vpp.Vppctl(vppCmd)
	Log(o)
	AssertNotContains(o, "FAIL:")
	AssertContains(o, "SUCCESS")
}

func HttpUnitTest(s *NoTopoSuite) {
	runUnitTest(s, "test http all")
}

func HttpListenerMetadataMWTest(s *NoTopoSuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	runUnitTest(s, "test http listener-metadata")
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
