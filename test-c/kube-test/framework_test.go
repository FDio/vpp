package main

import (
	"fmt"
	"os"
	"testing"
	"time"

	. "fd.io/kube-test/infra"
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
	TestTimeout = time.Minute * time.Duration(*Timeout)

	// creates a file with PPID, used for 'make cleanup-kube'
	ppid := fmt.Sprint(os.Getppid())
	ppid = ppid[:len(ppid)-1]
	f, _ := os.Create(".last_ppid")
	f.Write([]byte(ppid))
	f.Close()

	RegisterFailHandler(Fail)
	RunSpecs(t, "HST")
	if *DryRun || *IsPersistent {
		fmt.Println("\033[36m" + "Use 'make cleanup-kube' to remove pods " +
			"and namespaces. \nPPID: " + ppid + "\033[0m")
	}
}
