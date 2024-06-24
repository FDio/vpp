package main

import (
	. "fd.io/hs-test/infra"
)

func init() {
	RegisterCpuPinningSoloTests(DefaultCpuConfigurationTest, SkipCoresTest)
}

// TODO: Add more CPU configuration tests

func DefaultCpuConfigurationTest(s *CpuPinningSuite) {
	s.SkipIfNotMultiWorker(1)
	vpp := s.GetContainerByName(SingleTopoContainerVpp).VppInstance
	s.AssertNil(vpp.Start())
}

func SkipCoresTest(s *CpuPinningSuite) {
	s.SkipIfNotMultiWorker(2)

	skipCoresConfiguration := VppCpuConfig{
		PinMainCpu:         true,
		PinWorkersCorelist: true,
		SkipCores:          1,
	}

	vpp := s.GetContainerByName(SingleTopoContainerVpp).VppInstance
	vpp.CpuConfig = skipCoresConfiguration

	s.AssertNil(vpp.Start())
}
