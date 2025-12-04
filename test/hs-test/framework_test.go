package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = ReportBeforeSuite(func(report Report) {
	TestsThatWillRun = report.PreRunStats.SpecsThatWillRun
})

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
	fmt.Println("Go version: " + runtime.Version())
	// if we're debugging/running a coverage build and timeout isn't overridden,
	// set test timeout to 30 minutes. Also impacts AssertChannelClosed()
	if (*IsVppDebug || *IsCoverage || *PerfTesting) && *Timeout == 5 {
		TestTimeout = time.Minute * 30
		fmt.Printf("[Debugging or coverage build, TestTimeout is set to %s]\n", TestTimeout.String())
	} else {
		TestTimeout = time.Minute * time.Duration(*Timeout)
	}

	RunningInCi = os.Getenv("BUILD_NUMBER") != ""

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
