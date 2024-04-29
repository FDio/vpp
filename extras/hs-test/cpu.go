package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

var CgroupPath = "/sys/fs/cgroup/"

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
