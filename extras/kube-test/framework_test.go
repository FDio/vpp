package main

import (
	"fmt"
	"os"
	"os/exec"
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
	Ppid = fmt.Sprint(os.Getppid())
	Ppid = Ppid[:len(Ppid)-1]
	f, _ := os.Create(".last_ppid")
	f.Write([]byte(Ppid))
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
	if *IsPersistent {
		fmt.Println("\033[36m" + "Use 'make cleanup-kube' to remove pods " +
			"and namespaces. \nPPID: " + Ppid + "\033[0m")
	}
	// deleting the namespace here since we use the same namespace for every suite
	if !*IsPersistent {
		fmt.Println("Deleting kube-test namespace")
		cmd := exec.Command("kubectl", "delete", "ns", "kube-test"+Ppid)
		fmt.Println(cmd.String())
		o, _ := cmd.CombinedOutput()
		fmt.Printf("%s", string(o))
	}
}
