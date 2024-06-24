package main

import (
	. "fd.io/hs-test/infra"
)

func init() {
	RegisterCpuPinningTests(DefaultCpuConfigurationTest, SkipCoresTest, SkipCoresNegativeTest)
}

// TODO: Add more CPU configuration tests

func DefaultCpuConfigurationTest(s *CpuPinningSuite) {
	vpp := s.GetContainerByName(SingleTopoContainerVpp).VppInstance
	s.AssertNil(vpp.Start())
}

func SkipCoresTest(s *CpuPinningSuite) {
	// Test requires at least 2 CPUs assigned to VPP container
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

func SkipCoresNegativeTest(s *CpuPinningSuite) {
	s.SkipIfNotMultiWorker(3)

	skipCoresConfiguration := VppCpuConfig{
		PinMainCpu:         true,
		PinWorkersCorelist: true,
		SkipCores:          100,
	}

	vpp := s.GetContainerByName(SingleTopoContainerVpp).VppInstance
	vpp.CpuConfig = skipCoresConfiguration

	s.AssertNotNil(vpp.Start())
}
