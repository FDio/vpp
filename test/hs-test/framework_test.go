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
				Log(reportEntry.Value)
				return
			}
		}
	}
})

func TestHst(t *testing.T) {
	Log("* Go version: " + runtime.Version())
	Log("* HyperThreading = %t\n* CPU0 = %t", *HyperThreading, *UseCpu0)
	// if we're debugging/running a coverage build and timeout isn't overridden,
	// set test timeout to 30 minutes. Also impacts AssertChannelClosed()
	if (*IsVppDebug || *IsCoverage || *PerfTesting) && *Timeout == 5 {
		TestTimeout = time.Minute * 30
		Log("[Debugging or coverage build, TestTimeout is set to %s]\n", TestTimeout.String())
	} else {
		TestTimeout = time.Minute * time.Duration(*Timeout)
	}

	RunningInCi = os.Getenv("GITHUB_REPO_URL") != ""

	output, err := os.ReadFile("/sys/devices/system/node/online")
	if err == nil && strings.Contains(string(output), "-") {
		NumaAwareCpuAlloc = true
	}

	Ppid = fmt.Sprint(*HostPpid)
	// trim PPID so we don't exceed interface name char limit and max port number
	// (port = ginkgo process index + ppid)
	if len(Ppid) > 3 {
		Ppid = Ppid[len(Ppid)-3:]
	}

	// creates a file with PPID, used for 'make cleanup-hst'
	f, _ := os.Create(".last_hst_ppid")
	f.Write([]byte(Ppid))
	f.Close()

	RegisterFailHandler(Fail)
	RunSpecs(t, "HST")
	if *DryRun || *IsPersistent {
		Log("\033[36m" + "Use 'make cleanup-hst' to remove IP files, " +
			"namespaces and containers. \nPPID: " + Ppid + "\033[0m")
	}
}
