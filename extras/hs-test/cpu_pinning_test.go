package main

import (
	. "fd.io/hs-test/infra"
)

func init() {
	RegisterCpuPinningSoloTests(DefaultCpuConfigurationTest, SkipCoresTest)
}

// TODO: Add more CPU configuration tests

func DefaultCpuConfigurationTest(s *CpuPinningSuite) {
	vpp := s.Containers.Vpp.VppInstance
	s.AssertNil(vpp.Start())
}

func SkipCoresTest(s *CpuPinningSuite) {

	skipCoresConfiguration := VppCpuConfig{
		PinMainCpu:         true,
		PinWorkersCorelist: true,
		SkipCores:          1,
	}

	vpp := s.Containers.Vpp.VppInstance
	vpp.CpuConfig = skipCoresConfiguration

	s.AssertNil(vpp.Start())
}
