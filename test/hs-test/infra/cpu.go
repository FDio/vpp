package hst

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

type CpuAllocatorT struct {
	cpus    []int
	numa0   []int
	numa1   []int
	lastCpu int
	suite   *HstSuite
}

func iterateAndAppend(start int, end int, slice []int) []int {
	for i := start; i <= end; i++ {
		slice = append(slice, i)
	}
	return slice
}

var cpuAllocator *CpuAllocatorT = nil

func (c *CpuAllocatorT) Allocate(nCpus int, offset int) (*CpuContext, error) {
	var cpuCtx CpuContext
	// indexes, not actual cores
	var minCpu, maxCpu int

	minCpu = offset
	maxCpu = nCpus - 1 + offset

	if len(c.cpus)-1 < maxCpu {
		msg := fmt.Sprintf("could not allocate %d CPUs; available count: %d; attempted to allocate cores with index %d-%d; max index: %d;\n"+
			"available cores: %v", nCpus, len(c.cpus), minCpu, maxCpu, len(c.cpus)-1, c.cpus)
		if c.suite.SkipIfNotEnoguhCpus {
			c.suite.Skip("skipping: " + msg)
		}
		err := fmt.Errorf(msg)
		return nil, err
	}

	if NumaAwareCpuAlloc {
		if len(c.numa0) > maxCpu {
			c.suite.Log("Allocating CPUs from numa #0")
			cpuCtx.cpus = c.numa0[minCpu : minCpu+nCpus]
		} else if len(c.numa1) > maxCpu {
			c.suite.Log("Allocating CPUs from numa #1")
			cpuCtx.cpus = c.numa1[minCpu : minCpu+nCpus]
		} else {
			err := fmt.Errorf("could not allocate %d CPUs; not enough CPUs in either numa node", nCpus)
			return nil, err
		}
	} else {
		cpuCtx.cpus = c.cpus[minCpu : minCpu+nCpus]
	}

	c.lastCpu = minCpu + nCpus
	cpuCtx.cpuAllocator = c
	return &cpuCtx, nil
}

func (c *CpuAllocatorT) readCpus() error {
	var first, second int

	if NumaAwareCpuAlloc {
		var range1, range2 int
		var tmpCpus []int

		file, err := os.Open("/sys/devices/system/node/online")
		if err != nil {
			return err
		}
		defer file.Close()

		sc := bufio.NewScanner(file)
		sc.Scan()
		line := sc.Text()
		// get numa node range
		_, err = fmt.Sscanf(line, "%d-%d", &first, &second)
		if err != nil {
			return err
		}

		for i := first; i <= second; i++ {
			file, err := os.Open("/sys/devices/system/node/node" + fmt.Sprint(i) + "/cpulist")
			if err != nil {
				return err
			}
			defer file.Close()

			// get numa node cores
			sc := bufio.NewScanner(file)
			sc.Scan()
			line := sc.Text()

			for _, coreRange := range strings.Split(line, ",") {
				if strings.ContainsRune(coreRange, '-') {
					_, err = fmt.Sscanf(coreRange, "%d-%d", &range1, &range2)
					if err != nil {
						return err
					}
					tmpCpus = iterateAndAppend(range1, range2, tmpCpus)
				} else {
					_, err = fmt.Sscanf(coreRange, "%d", &range1)
					if err != nil {
						return err
					}
					tmpCpus = append(tmpCpus, range1)
				}
			}

			// discard cpu 0
			if tmpCpus[0] == 0 && !*UseCpu0 {
				tmpCpus = tmpCpus[1:]
			}

			c.cpus = append(c.cpus, tmpCpus...)
			if i == 0 {
				c.numa0 = append(c.numa0, tmpCpus...)
			} else {
				c.numa1 = append(c.numa1, tmpCpus...)
			}
			tmpCpus = tmpCpus[:0]
		}
	} else {
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
		_, err = fmt.Sscanf(line, "%d-%d", &first, &second)
		if err != nil {
			return err
		}
		c.cpus = iterateAndAppend(first, second, c.cpus)
	}

	// discard cpu 0
	if c.cpus[0] == 0 && !*UseCpu0 {
		c.cpus = c.cpus[1:]
	}
	return nil
}

func CpuAllocator() (*CpuAllocatorT, error) {
	if cpuAllocator == nil {
		var err error
		cpuAllocator = new(CpuAllocatorT)
		err = cpuAllocator.readCpus()
		if err != nil {
			return nil, err
		}
	}
	return cpuAllocator, nil
}
