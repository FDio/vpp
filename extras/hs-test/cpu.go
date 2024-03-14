package main

import (
	"bufio"
	"fmt"
	"os"
)

var CPU_PATH = "/sys/fs/cgroup/cpuset.cpus.effective"

type CpuContext struct {
	cpuAllocator *CpuAllocatorT
	cpus         []int
}

func (c *CpuContext) Release() {
	c.cpuAllocator.cpus = append(c.cpuAllocator.cpus, c.cpus...)
	c.cpus = c.cpus[:0] // empty the list
}

type CpuAllocatorT struct {
	cpus []int
}

var cpuAllocator *CpuAllocatorT = nil

func (c *CpuAllocatorT) Allocate(nCpus int) (*CpuContext, error) {
	var cpuCtx CpuContext

	if len(c.cpus) < nCpus {
		return nil, fmt.Errorf("could not allocate %d CPUs; available: %d", nCpus, len(c.cpus))
	}
	cpuCtx.cpus = c.cpus[0:nCpus]
	cpuCtx.cpuAllocator = c
	c.cpus = c.cpus[nCpus:]
	return &cpuCtx, nil
}

func (c *CpuAllocatorT) readCpus() error {
	var first, last int
	file, err := os.Open(CPU_PATH)
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
