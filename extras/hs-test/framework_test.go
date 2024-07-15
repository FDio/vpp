package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestHst(t *testing.T) {
	if *IsVppDebug {
		// 30 minute timeout so that the framework won't timeout while debugging
		SuiteTimeout = time.Minute * 30
	} else {
		SuiteTimeout = time.Minute * 5
	}

	output, err := os.ReadFile("/sys/devices/system/node/online")
	if err == nil && strings.Contains(string(output), "-") {
		NumaAwareCpuAlloc = true
	}
	// creates a file with PPID, used for 'make cleanup-hst'
	ppid := fmt.Sprint(os.Getppid())
	ppid = ppid[:len(ppid)-1]
	f, _ := os.Create(".last_hst_ppid")
	f.Write([]byte(ppid))
	f.Close()

	RegisterFailHandler(Fail)
	RunSpecs(t, "HST")
}
