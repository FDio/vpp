package main

import (
	. "fd.io/hs-test/infra"
)

func init() {
	RegisterNoTopoTests(HttpUnitTest, TcpUnitTest, SvmUnitTest, SessionUnitTest)
}

func runUnitTest(s *NoTopoSuite, vppCmd string) {
	s.SkipIfNotCoverage()
	vpp := s.Containers.Vpp.VppInstance
	o := vpp.Vppctl(vppCmd)
	s.Log(o)
	s.AssertContains(o, "SUCCESS")
}

func HttpUnitTest(s *NoTopoSuite) {
	runUnitTest(s, "test http all")
}

func TcpUnitTest(s *NoTopoSuite) {
	runUnitTest(s, "test tcp all")
}

func SvmUnitTest(s *NoTopoSuite) {
	runUnitTest(s, "test svm fifo all")
}

func SessionUnitTest(s *NoTopoSuite) {
	runUnitTest(s, "test session all")
}
