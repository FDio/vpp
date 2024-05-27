package main

import (
	"bufio"
	"errors"
	"fmt"
	. "github.com/onsi/ginkgo/v2"
	"os"
	"os/exec"
	"strings"
)

var CgroupPath = "/sys/fs/cgroup/"

type CpuContext struct {
	cpuAllocator *CpuAllocatorT
	cpus         []int
}

type CpuAllocatorT struct {
	cpus []int
}

var cpuAllocator *CpuAllocatorT = nil

func (c *CpuAllocatorT) Allocate(containerCount int, nCpus int) (*CpuContext, error) {
	var cpuCtx CpuContext

	// splitting cpus into equal parts; this will over-allocate cores but it's good enough for now
	maxContainerCount := 4
	minCpu := (GinkgoParallelProcess() - 1) * maxContainerCount * nCpus
	maxCpu := (GinkgoParallelProcess() * maxContainerCount * nCpus) - 1

	if len(c.cpus)-1 < maxCpu {
		err := fmt.Errorf("could not allocate %d CPUs; available: %d; attempted to allocate cores %d-%d",
			nCpus*containerCount, len(c.cpus), minCpu, minCpu+nCpus*containerCount)
		return nil, err
	}
	if containerCount == 1 {
		cpuCtx.cpus = c.cpus[minCpu : minCpu+nCpus]
	} else if containerCount > 1 && containerCount <= maxContainerCount {
		cpuCtx.cpus = c.cpus[minCpu+(nCpus*(containerCount-1)) : minCpu+(nCpus*containerCount)]
	} else {
		return nil, fmt.Errorf("too many containers; CPU allocation for >%d containers is not implemented", maxContainerCount)
	}

	cpuCtx.cpuAllocator = c
	return &cpuCtx, nil
}

func (c *CpuAllocatorT) readCpus() error {
	var first, last int

	// Path depends on cgroup version. We need to check which version is in use.
	// For that following command can be used: 'stat -fc %T /sys/fs/cgroup/'
	// In case the output states 'cgroup2fs' then cgroups v2 is used, 'tmpfs' in case cgroups v1.
	cmd := exec.Command("stat", "-fc", "%T", "/sys/fs/cgroup/")
	byteOutput, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}
	CpuPath := CgroupPath
	if strings.Contains(string(byteOutput), "tmpfs") {
		CpuPath += "cpuset/cpuset.effective_cpus"
	} else if strings.Contains(string(byteOutput), "cgroup2fs") {
		CpuPath += "cpuset.cpus.effective"
	} else {
		return errors.New("cgroup unknown fs: " + string(byteOutput))
	}

	file, err := os.Open(CpuPath)
	if err != nil {
		return err
	}
	defer file.Close()

	sc := bufio.NewScanner(file)
	sc.Scan()
	line := sc.Text()
	_, err = fmt.Sscanf(line, "%d-%d", &first, &last)
	if err != nil {
		return err
	}
	for i := first; i <= last; i++ {
		c.cpus = append(c.cpus, i)
	}
	return nil
}

func CpuAllocator() (*CpuAllocatorT, error) {
	if cpuAllocator == nil {
		cpuAllocator = new(CpuAllocatorT)
		err := cpuAllocator.readCpus()
		if err != nil {
			return nil, err
		}
	}
	return cpuAllocator, nil
}
