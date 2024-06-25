package main

import (
	. "fd.io/hs-test/infra"
)

func init() {
	RegisterCpuPinningSoloTests(DefaultCpuConfigurationTest, SkipCoresTest, MainCpuPinTest, WorkersNoMainThreadPinningTest, CoreListWorkersNoMainThreadPinningTest, WorkersMainThreadPinningTest, CoreListWorkersMainThreadPinningTest, TranslateAutoWorkersTest, TranslateAutoCoreListWorkersTest, TranslateAutoSkipCoresTest)
}

// TODO: Add more CPU configuration tests

func DefaultCpuConfigurationTest(s *CpuPinningSuite) {
	vpp := s.Containers.Vpp.VppInstance
	s.AssertNil(vpp.Start())
}

func SkipCoresTest(s *CpuPinningSuite) {
	vppCpuConfig := VppCpuConfig{
		PinMainCpu:         true,
		PinWorkersCorelist: true,
		TranslateCores:     false,
		SkipCores:          1,
	}

	vpp := s.Containers.Vpp.VppInstance
	vpp.CpuConfig = vppCpuConfig

	s.AssertNil(vpp.Start())
}

func MainCpuPinTest(s *CpuPinningSuite) {
	vppCpuConfig := VppCpuConfig{
		PinMainCpu:         true,
		PinWorkersCorelist: false,
		TranslateCores:     false,
		SkipCores:          0,
	}

	vpp := s.Containers.Vpp.VppInstance
	vpp.CpuConfig = vppCpuConfig

	s.AssertNil(vpp.Start())
}

func WorkersNoMainThreadPinningTest(s *CpuPinningSuite) {
	skipCoresConfiguration := VppCpuConfig{
		PinMainCpu:         false,
		PinWorkersCorelist: false,
		TranslateCores:     false,
		SkipCores:          0,
	}

	vpp := s.Containers.Vpp.VppInstance
	vpp.CpuConfig = skipCoresConfiguration

	s.AssertNil(vpp.Start())
}

func CoreListWorkersNoMainThreadPinningTest(s *CpuPinningSuite) {
	skipCoresConfiguration := VppCpuConfig{
		PinMainCpu:         false,
		PinWorkersCorelist: true,
		TranslateCores:     false,
		SkipCores:          0,
	}

	vpp := s.Containers.Vpp.VppInstance
	vpp.CpuConfig = skipCoresConfiguration

	s.AssertNotNil(vpp.Start()) /* vpp should fail during launch */
}

func WorkersMainThreadPinningTest(s *CpuPinningSuite) {
	vppCpuConfig := VppCpuConfig{
		PinMainCpu:         true,
		PinWorkersCorelist: false,
		TranslateCores:     false,
		SkipCores:          0,
	}

	vpp := s.Containers.Vpp.VppInstance
	vpp.CpuConfig = vppCpuConfig

	s.AssertNil(vpp.Start())
}

func CoreListWorkersMainThreadPinningTest(s *CpuPinningSuite) {
	vppCpuConfig := VppCpuConfig{
		PinMainCpu:         true,
		PinWorkersCorelist: true,
		TranslateCores:     false,
		SkipCores:          0,
	}

	vpp := s.Containers.Vpp.VppInstance
	vpp.CpuConfig = vppCpuConfig

	s.AssertNil(vpp.Start())
}

func TranslateAutoWorkersTest(s *CpuPinningSuite) {

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

func TranslateAutoCoreListWorkersTest(s *CpuPinningSuite) {

	translateCoresConfiguration := VppCpuConfig{
		PinMainCpu:         true, /* main-thread must always be pinned when using translate mode */
		PinWorkersCorelist: true,
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
