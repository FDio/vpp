package main

import (
	. "fd.io/hs-test/infra"
)

func init() {
	RegisterCpuPinningTests(DefaultCpuConfigurationTest, SkipCoresTest, TranslateAutoTest, TranslateAutoNoMainPinTest, TranslateAutoSkipCoresTest)
}

func DefaultCpuConfigurationTest(s *CpuPinningSuite) {
	vpp := s.GetContainerByName(SingleTopoContainerVpp).VppInstance
	s.AssertNil(vpp.Start())
	// o := vpp.Vppctl("show threads")
	// s.Log(o)
}

func SkipCoresTest(s *CpuPinningSuite) {
	// Test requires at least 2 CPUs assigned to VPP container
	s.SkipIfNotMultiWorker(2)

	skipCoresConfiguration := VppCpuConfig{
		PinMainCpu:         true,
		PinWorkersCorelist: true,
		TranslateCores:     false,
		SkipCores:          1,
	}

	vpp := s.GetContainerByName(SingleTopoContainerVpp).VppInstance
	vpp.CpuConfig = skipCoresConfiguration

	s.AssertNil(vpp.Start())
}

func TranslateAutoTest(s *CpuPinningSuite) {
	s.SkipIfNotMultiWorker(2)

	translateCoresConfiguration := VppCpuConfig{
		PinMainCpu:         true,
		PinWorkersCorelist: false,
		TranslateCores:     true,
		SkipCores:          0,
	}
	vpp := s.GetContainerByName(SingleTopoContainerVpp).VppInstance
	vpp.CpuConfig = translateCoresConfiguration

	s.AssertNil(vpp.Start())

}

func TranslateAutoNoMainPinTest(s *CpuPinningSuite) {
	s.SkipIfNotMultiWorker(2)

	translateCoresConfiguration := VppCpuConfig{
		PinMainCpu:         false,
		PinWorkersCorelist: false,
		TranslateCores:     true,
		SkipCores:          0,
	}
	vpp := s.GetContainerByName(SingleTopoContainerVpp).VppInstance
	vpp.CpuConfig = translateCoresConfiguration

	s.AssertNil(vpp.Start())

}

func TranslateAutoSkipCoresTest(s *CpuPinningSuite) {
	s.SkipIfNotMultiWorker(3)

	translateCoresConfiguration := VppCpuConfig{
		PinMainCpu:         true,
		PinWorkersCorelist: false,
		TranslateCores:     true,
		SkipCores:          1,
	}
	vpp := s.GetContainerByName(SingleTopoContainerVpp).VppInstance
	vpp.CpuConfig = translateCoresConfiguration

	s.AssertNil(vpp.Start())

}
