package hst

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
)

var CgroupPath = "/sys/fs/cgroup/"

type CpuContext struct {
	cpuAllocator *CpuAllocatorT
	cpus         []int
}

type CpuAllocatorT struct {
	cpus              []int
	runningInCi       bool
	buildNumber       int
	maxContainerCount int
}

func iterateAndAppend(start int, end int, slice []int) []int {
	for i := start; i <= end; i++ {
		slice = append(slice, i)
	}
	return slice
}

var cpuAllocator *CpuAllocatorT = nil

func (c *CpuAllocatorT) Allocate(containerCount int, nCpus int, offset int) (*CpuContext, error) {
	var cpuCtx CpuContext
	// indexes, not actual cores
	var minCpu, maxCpu int

	if c.runningInCi {
		minCpu = ((c.buildNumber) * c.maxContainerCount * nCpus) + offset
		maxCpu = ((c.buildNumber + 1) * c.maxContainerCount * nCpus) - 1 + offset
	} else {
		minCpu = ((GinkgoParallelProcess() - 1) * c.maxContainerCount * nCpus) + offset
		maxCpu = (GinkgoParallelProcess() * c.maxContainerCount * nCpus) - 1 + offset
	}

	if len(c.cpus)-1 < maxCpu {
		err := fmt.Errorf("could not allocate %d CPUs; available count: %d; attempted to allocate cores with index %d-%d; max index: %d;\n"+
			"available cores: %v", nCpus*containerCount, len(c.cpus), minCpu, maxCpu, len(c.cpus)-1, c.cpus)
		return nil, err
	}

	if containerCount == 1 {
		cpuCtx.cpus = c.cpus[minCpu : minCpu+nCpus]
	} else if containerCount > 1 && containerCount <= c.maxContainerCount {
		cpuCtx.cpus = c.cpus[minCpu+(nCpus*(containerCount-1)) : minCpu+(nCpus*containerCount)]
	} else {
		return nil, fmt.Errorf("too many containers; CPU allocation for >%d containers is not implemented", c.maxContainerCount)
	}
	cpuCtx.cpuAllocator = c
	return &cpuCtx, nil
}

func (c *CpuAllocatorT) readCpus() error {
	var first, second, third, fourth int
	var file *os.File
	var err error

	if c.runningInCi {
		// non-debug build runs on node0, debug on node1
		if *IsDebugBuild {
			file, err = os.Open("/sys/devices/system/node/node1/cpulist")
		} else {
			file, err = os.Open("/sys/devices/system/node/node0/cpulist")
		}
		if err != nil {
			return err
		}
		defer file.Close()

		sc := bufio.NewScanner(file)
		sc.Scan()
		line := sc.Text()
		_, err = fmt.Sscanf(line, "%d-%d,%d-%d", &first, &second, &third, &fourth)
		if err != nil {
			return err
		}

		c.cpus = iterateAndAppend(first, second, c.cpus)
		c.cpus = iterateAndAppend(third, fourth, c.cpus)
	} else if NumaAwareCpuAlloc {
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
				if strings.IndexRune(coreRange, '-') != -1 {
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

			// make c.cpus divisible by maxContainerCount * nCpus, so we don't have to check which numa will be used
			// and we can use offsets
			countToRemove := len(tmpCpus) % (c.maxContainerCount * *NConfiguredCpus)
			if countToRemove >= len(tmpCpus) {
				return fmt.Errorf("requested too much CPUs per container (%d) should be no more than %d", *NConfiguredCpus, len(tmpCpus)/c.maxContainerCount)
			}
			c.cpus = append(c.cpus, tmpCpus[:len(tmpCpus)-countToRemove]...)
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
		cpuAllocator.maxContainerCount = 4
		buildNumberStr := os.Getenv("BUILD_NUMBER")

		if buildNumberStr != "" {
			cpuAllocator.runningInCi = true
			// get last digit of build number
			cpuAllocator.buildNumber, err = strconv.Atoi(buildNumberStr[len(buildNumberStr)-1:])
			if err != nil {
				return nil, err
			}
		}
		err = cpuAllocator.readCpus()
		if err != nil {
			return nil, err
		}
	}
	return cpuAllocator, nil
}
