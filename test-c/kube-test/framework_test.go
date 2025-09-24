package main

import (
	"fmt"
	"os"
	"strings"
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

func TestKube(t *testing.T) {
	TestTimeout = time.Minute * time.Duration(*Timeout)

	// creates a file with PPID, used for 'make cleanup-kube'
	ppid := fmt.Sprint(os.Getppid())
	ppid = ppid[:len(ppid)-1]
	f, _ := os.Create(".last_ppid")
	f.Write([]byte(ppid))
	f.Close()

	Kubeconfig = os.Getenv("KUBECONFIG")
	if Kubeconfig == "" {
		Kubeconfig = os.Getenv("HOME") + "/.kube/config"
	}
	_, err := os.Stat(Kubeconfig)
	if err != nil {
		fmt.Println("** Kubeconfig not found **")
		os.Exit(1)
	}
	contents, err := os.ReadFile(Kubeconfig)
	if err != nil {
		fmt.Println("** Error reading Kubeconfig **")
		os.Exit(1)
	}
	if strings.Contains(string(contents), "cluster: kind-kind") {
		KindCluster = true
	}
	fmt.Printf("\nKubeconfig: '%s'\nKinD cluster: %v\n", Kubeconfig, KindCluster)

	RegisterFailHandler(Fail)
	RunSpecs(t, "kube-test")
	if *DryRun || *IsPersistent {
		fmt.Println("\033[36m" + "Use 'make cleanup-kube' to remove pods " +
			"and namespaces. \nPPID: " + ppid + "\033[0m")
	}
}
