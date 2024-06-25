package main

import (
	. "fd.io/hs-test/infra"
)

func init() {
	RegisterCpuPinningSoloTests(DefaultCpuConfigurationTest, SkipCoresTest, TranslateAutoTest, TranslateAutoNoMainPinTest, TranslateAutoSkipCoresTest, TranslateNegativeAutoNoMainSet)
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
		TranslateCores:     false,
		SkipCores:          1,
	}

	vpp := s.Containers.Vpp.VppInstance
	vpp.CpuConfig = skipCoresConfiguration

	s.AssertNil(vpp.Start())
}

func TranslateAutoTest(s *CpuPinningSuite) {

	translateCoresConfiguration := VppCpuConfig{
		PinMainCpu:         true,
		PinWorkersCorelist: false,
		TranslateCores:     true,
		SkipCores:          0,
	}
	vpp := s.Containers.Vpp.VppInstance
	vpp.CpuConfig = translateCoresConfiguration

	s.AssertNil(vpp.Start())

}

func TranslateAutoNoMainPinTest(s *CpuPinningSuite) {
	translateCoresConfiguration := VppCpuConfig{
		PinMainCpu:         true, /* main-thread must always be pinned when using translate mode */
		PinWorkersCorelist: false,
		TranslateCores:     true,
		SkipCores:          0,
	}
	vpp := s.Containers.Vpp.VppInstance
	vpp.CpuConfig = translateCoresConfiguration

	s.AssertNil(vpp.Start())

}

func TranslateAutoSkipCoresTest(s *CpuPinningSuite) {
	translateCoresConfiguration := VppCpuConfig{
		PinMainCpu:         true,
		PinWorkersCorelist: false,
		TranslateCores:     true,
		SkipCores:          1,
	}
	vpp := s.Containers.Vpp.VppInstance
	vpp.CpuConfig = translateCoresConfiguration

	s.AssertNil(vpp.Start())

}

func TranslateNegativeAutoNoMainSet(s *CpuPinningSuite) {
	translateCoresConfiguration := VppCpuConfig{
		PinMainCpu:         false,
		PinWorkersCorelist: false,
		TranslateCores:     true,
		SkipCores:          0,
	}
	vpp := s.Containers.Vpp.VppInstance
	vpp.CpuConfig = translateCoresConfiguration

	s.AssertNotNil(vpp.Start()) /* should fail */

}
