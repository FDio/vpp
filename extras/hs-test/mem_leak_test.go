package main

import (
	. "fd.io/hs-test/infra"
	"fmt"
)

func init() {
	RegisterNoTopoSoloTests(MemLeakTest)
}

func MemLeakTest(s *NoTopoSuite) {
	s.SkipUnlessLeakCheck()
	vpp := s.GetContainerByName("vpp").VppInstance
	/* no goVPP less noise */
	vpp.Disconnect()
	vpp.EnableMemoryTrace()
	traces1, err := vpp.GetMemoryTrace()
	s.AssertNil(err, fmt.Sprint(err))
	vpp.Vppctl("test mem-leak")
	traces2, err := vpp.GetMemoryTrace()
	s.AssertNil(err, fmt.Sprint(err))
	vpp.MemLeakCheck(traces1, traces2)
}
