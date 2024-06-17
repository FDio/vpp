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
	debugBuildCi      int
	buildNumber       string
	maxContainerCount int
}

var cpuAllocator *CpuAllocatorT = nil

func (c *CpuAllocatorT) Allocate(containerCount int, nCpus int) (*CpuContext, error) {
	var cpuCtx CpuContext
	// indexes, not actual cores
	var minCpu, maxCpu int

	if c.runningInCi {
		// get last digit of build number
		build_number_int, err := strconv.Atoi(c.buildNumber[len(c.buildNumber)-1:])
		if err != nil {
			return nil, err
		}
		minCpu = ((build_number_int) * c.maxContainerCount * nCpus)
		maxCpu = ((build_number_int + 1) * c.maxContainerCount * nCpus) - 1
	} else {
		minCpu = ((GinkgoParallelProcess() - 1) * c.maxContainerCount * nCpus)
		maxCpu = (GinkgoParallelProcess() * c.maxContainerCount * nCpus) - 1
	}

	if len(c.cpus)-1 <= maxCpu {
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

	if c.runningInCi {
		// non-debug build runs on node0, debug on node1
		file, err := os.Open("/sys/devices/system/node/node" + fmt.Sprint(c.debugBuildCi) + "/cpulist")
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

		for i := first; i <= second; i++ {
			c.cpus = append(c.cpus, i)
		}
		for i := third; i <= fourth; i++ {
			c.cpus = append(c.cpus, i)
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
		for i := first; i <= second; i++ {
			c.cpus = append(c.cpus, i)
		}
	}

	// discard cpu 0
	if c.cpus[0] == 0 {
		c.cpus = c.cpus[1:]
	}
	return nil
}

func CpuAllocator() (*CpuAllocatorT, error) {
	if cpuAllocator == nil {
		cpuAllocator = new(CpuAllocatorT)

		cpuAllocator.maxContainerCount = 4
		cpuAllocator.buildNumber = os.Getenv("BUILD_NUMBER")
		if cpuAllocator.buildNumber != "" {
			cpuAllocator.runningInCi = true
			workDir, _ := os.Getwd()
			if strings.Contains(workDir, "debug") {
				cpuAllocator.debugBuildCi = 1
			}
		}
		err := cpuAllocator.readCpus()
		if err != nil {
			return nil, err
		}
	}
	return cpuAllocator, nil
}
