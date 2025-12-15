package hst

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
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
	cpus    []int
	numa0   []int
	numa1   []int
	lastCpu int
	suite   *HstSuite
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
			"available cores: %v\ntry running hs-test with HT=true and/or CPU0=true", nCpus, len(c.cpus), minCpu, maxCpu, len(c.cpus)-1, c.cpus)
		if c.suite.SkipIfNotEnoguhCpus {
			c.suite.Skip("skipping: " + msg)
		}
		err := fmt.Errorf("%s", msg)
		return nil, err
	}

	if NumaAwareCpuAlloc {
		if len(c.numa0) > maxCpu {
			Log("Allocating CPUs from numa #0")
			cpuCtx.cpus = c.numa0[minCpu : minCpu+nCpus]
		} else if len(c.numa1) > maxCpu {
			Log("Allocating CPUs from numa #1")
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

// Helper to get physical cores only
func getPhysicalCores() (map[int]bool, error) {
	cmd := exec.Command("lscpu", "-p=CORE,CPU")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// Map to track which physical Core IDs we have already seen.
	// We want to keep the first CPU ID associated with a Core ID and discard the rest.
	seenCores := make(map[int]bool)
	physicalCpuSet := make(map[int]bool)

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			continue
		}
		coreID, _ := strconv.Atoi(parts[0])
		cpuID, _ := strconv.Atoi(parts[1])

		if !seenCores[coreID] {
			seenCores[coreID] = true
			physicalCpuSet[cpuID] = true
		}
	}
	return physicalCpuSet, nil
}

func (c *CpuAllocatorT) readCpus() error {
	var first, second int
	var physicalCores map[int]bool
	var err error

	if !*HyperThreading {
		physicalCores, err = getPhysicalCores()
		if err != nil {
			return fmt.Errorf("failed to get physical cores: %v", err)
		}
	}

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

			for coreRange := range strings.SplitSeq(line, ",") {
				if strings.ContainsRune(coreRange, '-') {
					_, err = fmt.Sscanf(coreRange, "%d-%d", &range1, &range2)
					if err != nil {
						return err
					}
					// filter range
					for cpu := range1; cpu <= range2; cpu++ {
						if !*HyperThreading {
							if _, isPhysical := physicalCores[cpu]; !isPhysical {
								continue
							}
						}
						tmpCpus = append(tmpCpus, cpu)
					}
				} else {
					_, err = fmt.Sscanf(coreRange, "%d", &range1)
					if err != nil {
						return err
					}
					// filter single CPU
					if !*HyperThreading {
						if _, isPhysical := physicalCores[range1]; !isPhysical {
							continue
						}
					}
					tmpCpus = append(tmpCpus, range1)
				}
			}

			// discard cpu 0
			if len(tmpCpus) > 0 && tmpCpus[0] == 0 && !*UseCpu0 {
				tmpCpus = tmpCpus[1:]
			}

			c.cpus = append(c.cpus, tmpCpus...)
			if i == 0 {
				if len(tmpCpus) > *CpuOffset {
					tmpCpus = tmpCpus[*CpuOffset:]
				}
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
			// fallback if not a range (single cpu)
			_, err = fmt.Sscanf(line, "%d", &first)
			if err == nil {
				second = first
			} else {
				return err
			}
		}

		for i := first; i <= second; i++ {
			if !*HyperThreading {
				if _, isPhysical := physicalCores[i]; !isPhysical {
					continue
				}
			}
			c.cpus = append(c.cpus, i)
		}

		if len(c.cpus) > 0 && c.cpus[0] == 0 && !*UseCpu0 {
			c.cpus = c.cpus[1:]
		}

		if len(c.cpus) > *CpuOffset {
			c.cpus = c.cpus[*CpuOffset:]
		}
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
