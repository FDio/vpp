package main

import (
	"bufio"
	"fmt"
	"os"
)

var CPU_PATH = "/sys/fs/cgroup/cpuset.cpus.effective"

type CpuGeneratorT struct {
	nCpus        int
	currentCpuId int
}

var cpuGenerator *CpuGeneratorT = nil

func (c *CpuGeneratorT) ReadCpus(fname string) {
	var maxCpuId int
	file, err := os.Open(fname)
	if err != nil {
		fmt.Printf("failed to open cpuset.file: %v", err)
		return
	}
	defer file.Close()

	sc := bufio.NewScanner(file)
	sc.Scan()
	line := sc.Text()
	fmt.Sscanf(line, "%d-%d", &c.currentCpuId, &maxCpuId)
	c.nCpus = maxCpuId - c.currentCpuId + 1
}

func CpuGenerator() *CpuGeneratorT {
	if cpuGenerator == nil {
		cpuGenerator = new(CpuGeneratorT)
		cpuGenerator.ReadCpus(CPU_PATH)
	}
	return cpuGenerator
}

func (o *CpuGeneratorT) NextCpuId() (nextCpuId int) {
	if o.currentCpuId == o.nCpus {
		nextCpuId = -1
		return
	}
	nextCpuId = o.currentCpuId
	o.currentCpuId++
	return
}

func GenerateCpuConfig(nWorkers int) Stanza {
	var c Stanza
	var s string
	c.newStanza("cpu").
		append(fmt.Sprintf("main-core %d", CpuGenerator().NextCpuId()))
	if nWorkers > 0 {
		s = ""
		for i := nWorkers; i > 0; i-- {
			cpuId := CpuGenerator().NextCpuId()
			if cpuId < 0 {
				fmt.Println("could not allocate more CPUs!")
				break
			}
			if i != nWorkers {
				s = s + ", "
			}
			s = s + fmt.Sprintf("%d", cpuId)
		}
		c.append(fmt.Sprintf("corelist-workers %s", s))
	}
	return *c.close()
}
