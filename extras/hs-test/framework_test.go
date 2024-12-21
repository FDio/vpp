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

var _ = ReportAfterSuite("VPP version under test", func(report Report) {
	for i := range report.SpecReports {
		specReport := report.SpecReports[i]
		for j := range specReport.ReportEntries {
			reportEntry := specReport.ReportEntries[j]
			if reportEntry.Name == "VPP version" {
				fmt.Println(reportEntry.Value)
				return
			}
		}
	}
})

func TestHst(t *testing.T) {
	if *IsVppDebug {
		// 30 minute timeout so that the framework won't timeout while debugging
		TestTimeout = time.Minute * 30
	} else {
		TestTimeout = time.Minute * 5
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
	if *DryRun || *IsPersistent {
		fmt.Println("\033[36m" + "Use 'make cleanup-hst' to remove IP files, " +
			"namespaces and containers. \nPPID: " + ppid + "\033[0m")
	}
}
