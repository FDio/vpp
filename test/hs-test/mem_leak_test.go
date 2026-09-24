package main

import (
	"fmt"
	"time"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterNoTopoSoloTests(MemLeakTest)
}

// Verifies the leak-check path, must always report a leak. 'test mem-leak'
// leaks from a separate thread, 'unix_cli' in the traceback would match the
// report noise filter.
func MemLeakTest(s *NoTopoSuite) {
	s.SkipUnlessLeakCheck()
	vpp := s.Containers.Vpp.VppInstance
	/* no goVPP less noise */
	vpp.Disconnect()
	vpp.EnableMemoryTrace()
	traces1, err := vpp.GetMemoryTrace()
	AssertNil(err, fmt.Sprint(err))
	vpp.Vppctl("test mem-leak")
	/* leaked from a separate thread, give it time to allocate */
	time.Sleep(time.Second * 1)
	traces2, err := vpp.GetMemoryTrace()
	AssertNil(err, fmt.Sprint(err))
	leakedBytes, _ := vpp.MemLeakCheck(traces1, traces2)
	AssertGreaterThan(leakedBytes, 0, "'test mem-leak' leak not reported")
}
