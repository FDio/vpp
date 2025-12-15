package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	. "fd.io/kube-test/infra"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestKube(t *testing.T) {
	Log("Go version: %s", runtime.Version())
	TestTimeout = time.Minute * time.Duration(*Timeout)

	// creates a file with PPID, used for 'make cleanup-kt'
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
		Log("** Kubeconfig not found **")
		os.Exit(1)
	}
	contents, err := os.ReadFile(Kubeconfig)
	if err != nil {
		Log("** Error reading Kubeconfig **")
		os.Exit(1)
	}
	if strings.Contains(string(contents), "cluster: kind-kind") {
		KindCluster = true
	}
	Log("Kubeconfig: '%s'\nKinD cluster: %v", Kubeconfig, KindCluster)

	RegisterFailHandler(Fail)
	RunSpecs(t, "kube-test")
	if *IsPersistent {
		Log("\033[36m" + "Use 'make cleanup-kt' to remove pods " +
			"and namespaces. \nPPID: " + Ppid + "\033[0m")
	}
	// deleting the namespace here since we use the same namespace for every suite
	if !*IsPersistent {
		Log("Deleting kube-test namespace")
		cmd := exec.Command("kubectl", "delete", "ns", "kube-test"+Ppid)
		Log(cmd.String())
		o, _ := cmd.CombinedOutput()
		Log("%s", string(o))
	}
}
