package hst

import (
	"bufio"
	"errors"
	"fmt"
	. "github.com/onsi/ginkgo/v2"
	"os"
	"os/exec"
	"strconv"
	"strings"
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

func (c *CpuAllocatorT) Allocate(containerCount int, nCpus int) (*CpuContext, error) {
	var cpuCtx CpuContext
	// indexes, not actual cores
	var minCpu, maxCpu int

	// temporary fix for CpuPinningSuite
	if strings.Contains(CurrentSpecReport().ContainerHierarchyTexts[0], "CpuPinning") {
		cpuAllocator.maxContainerCount = 1
	} else {
		cpuAllocator.maxContainerCount = 4
	}

	if c.runningInCi {
		minCpu = ((c.buildNumber) * c.maxContainerCount * nCpus)
		maxCpu = ((c.buildNumber + 1) * c.maxContainerCount * nCpus) - 1
	} else {
		minCpu = ((GinkgoParallelProcess() - 1) * c.maxContainerCount * nCpus)
		maxCpu = (GinkgoParallelProcess() * c.maxContainerCount * nCpus) - 1
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
		var fifth, sixth int
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
			_, err = fmt.Sscanf(line, "%d-%d,%d-%d", &third, &fourth, &fifth, &sixth)
			if err != nil {
				return err
			}

			// get numa node cores from first range
			tmpCpus = iterateAndAppend(third, fourth, tmpCpus)

			// discard cpu 0
			if tmpCpus[0] == 0 && !*UseCpu0 {
				tmpCpus = tmpCpus[1:]
			}

			// get numa node cores from second range
			tmpCpus = iterateAndAppend(fifth, sixth, tmpCpus)

			// make c.cpus divisible by maxContainerCount * nCpus, so we don't have to check which numa will be used
			// and we can use offsets
			count_to_remove := len(tmpCpus) % (c.maxContainerCount * *NConfiguredCpus)
			c.cpus = append(c.cpus, tmpCpus[:len(tmpCpus)-count_to_remove]...)
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
