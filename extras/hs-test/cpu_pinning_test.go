package main

import (
	. "fd.io/hs-test/infra"
)

func init() {
	RegisterCpuPinningSoloTests(DefaultCpuConfigurationTest, MainThreadOnlyNoPinningTest, MainThreadOnlyTest, CorelistWorkersTest, RelativeMainThreadOnlyTest, RelativeAutoWorkersTest, RelativeAutoWorkersSkipCoresTest, RelativeCorelistWorkersTest, RelativeCorelistWorkersSkipCoresTest)
}

/* Following test-cases verify that VPP CPU pinning configuration work as expected.

Certain configuration are not tested, as they are expected to fail in the CI with VPP running in a container
with specific allocated cores. e.g. "Allocated CPUs [37 38 39] to container 1vpp4500"

For example, assuming the vpp container is allocated CPUs [37 38 39], the following valid configurations will fail:
Config #1: 'cpu {main-core x workers y}'
				    e.g. 'cpu {main-core 37 workers 2}' will fail as workers will be assigned automatically to CPUs 1 and 2
Config #2: 'cpu {main-core x corelist-workers y skip-cores z}'
				    e.g. cpu {main-core 37 corelist-workers 38-39 skip-cores 1} will skip CPU 0 on the machine
*/

func DefaultCpuConfigurationTest(s *CpuPinningSuite) {
	vpp := s.Containers.Vpp.VppInstance
	s.AssertNil(vpp.Start())
}

// cpu {} (main thread automatically pinned on VPP launches on)
func MainThreadOnlyNoPinningTest(s *CpuPinningSuite) {
	vppCpuConfig := VppCpuConfig{
		PinMainCpu:         false,
		UseWorkers:         false,
		PinWorkersCorelist: false,
		RelativeCores:      false,
		SkipCores:          0,
	}

	vpp := s.Containers.Vpp.VppInstance
	vpp.CpuConfig = vppCpuConfig

	s.AssertNil(vpp.Start())
}

// cpu {main-core x}
func MainThreadOnlyTest(s *CpuPinningSuite) {
	vppCpuConfig := VppCpuConfig{
		PinMainCpu:         true,
		UseWorkers:         false,
		PinWorkersCorelist: false,
		RelativeCores:      false,
		SkipCores:          0,
	}

	vpp := s.Containers.Vpp.VppInstance
	vpp.CpuConfig = vppCpuConfig

	s.AssertNil(vpp.Start())
}

// cpu {main-core x corelist-workers y}
func CorelistWorkersTest(s *CpuPinningSuite) {
	vppCpuConfig := VppCpuConfig{
		PinMainCpu:         true,
		UseWorkers:         true,
		PinWorkersCorelist: true,
		RelativeCores:      false,
		SkipCores:          0,
	}

	vpp := s.Containers.Vpp.VppInstance
	vpp.CpuConfig = vppCpuConfig

	s.AssertNil(vpp.Start())
}

// cpu {main-core x relative}
func RelativeMainThreadOnlyTest(s *CpuPinningSuite) {
	vppCpuConfig := VppCpuConfig{
		PinMainCpu:         true,
		UseWorkers:         false,
		PinWorkersCorelist: false,
		RelativeCores:      true,
		SkipCores:          0,
	}

	vpp := s.Containers.Vpp.VppInstance
	vpp.CpuConfig = vppCpuConfig

	s.AssertNil(vpp.Start())
}

// cpu {main-core x workers y relative}
func RelativeAutoWorkersTest(s *CpuPinningSuite) {
	vppCpuConfig := VppCpuConfig{
		PinMainCpu:         true,
		UseWorkers:         true,
		PinWorkersCorelist: false,
		RelativeCores:      true,
		SkipCores:          0,
	}

	vpp := s.Containers.Vpp.VppInstance
	vpp.CpuConfig = vppCpuConfig

	s.AssertNil(vpp.Start())
}

// cpu {main-core x workers y skip-cores z relative}
func RelativeAutoWorkersSkipCoresTest(s *CpuPinningSuite) {
	vppCpuConfig := VppCpuConfig{
		PinMainCpu:         true,
		UseWorkers:         true,
		PinWorkersCorelist: false,
		RelativeCores:      true,
		SkipCores:          1, /* skip 1 core */
	}

	vpp := s.Containers.Vpp.VppInstance
	vpp.CpuConfig = vppCpuConfig

	s.AssertNil(vpp.Start())
}

// cpu {main-core x corelist-workers y relative}
func RelativeCorelistWorkersTest(s *CpuPinningSuite) {
	vppCpuConfig := VppCpuConfig{
		PinMainCpu:         true,
		UseWorkers:         true,
		PinWorkersCorelist: true,
		RelativeCores:      true,
		SkipCores:          0,
	}

	vpp := s.Containers.Vpp.VppInstance
	vpp.CpuConfig = vppCpuConfig

	s.AssertNil(vpp.Start())
}

// cpu {main-core x corelist-workers y skip-cores z relative}
func RelativeCorelistWorkersSkipCoresTest(s *CpuPinningSuite) {
	vppCpuConfig := VppCpuConfig{
		PinMainCpu:         true,
		UseWorkers:         true,
		PinWorkersCorelist: true,
		RelativeCores:      true,
		SkipCores:          1, /* skip 1 core */
	}

	vpp := s.Containers.Vpp.VppInstance
	vpp.CpuConfig = vppCpuConfig

	s.AssertNil(vpp.Start())
}
