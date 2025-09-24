package kube_test

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/a8m/envsubst"
	"github.com/joho/godotenv"
	. "github.com/onsi/ginkgo/v2"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var IsCoverage = flag.Bool("coverage", false, "use coverage run config")
var IsPersistent = flag.Bool("persist", false, "persists topology config")
var IsVerbose = flag.Bool("verbose", false, "verbose test output")
var IsVppDebug = flag.Bool("debug", false, "attach gdb to vpp")
var DryRun = flag.Bool("dryrun", false, "set up containers but don't run tests")
var Timeout = flag.Int("timeout", 30, "test timeout override (in minutes)")
var TestTimeout time.Duration
var Kubeconfig string
var KindCluster bool

const (
	LogDir string = "/tmp/kube-test/"
)

type BaseSuite struct {
	ClientSet        *kubernetes.Clientset
	Config           *rest.Config
	Namespace        string
	CurrentlyRunning map[string]*Pod
	images           []string
	AllPods          map[string]*Pod
	MainContext      context.Context
	Ppid             string
	Logger           *log.Logger
	LogFile          *os.File
	Pods             struct {
		ServerGeneric *Pod
		ClientGeneric *Pod
		Nginx         *Pod
		NginxProxy    *Pod
		Ab            *Pod
	}
}

func init() {
	cmd := exec.Command("mkdir", "-p", LogDir)
	if err := cmd.Run(); err != nil {
		panic(err)
	}
}

func (s *BaseSuite) Skip(args string) {
	Skip(args)
}

func (s *BaseSuite) SetupTest() {
	TestCounterFunc()
	s.Log("[* TEST SETUP]")
}

func (s *BaseSuite) SetupSuite() {
	s.CreateLogger()
	s.Log("[* SUITE SETUP]")
	s.Ppid = fmt.Sprint(os.Getppid())
	// remove last number so we have space to prepend a process index (interfaces have a char limit)
	s.Ppid = s.Ppid[:len(s.Ppid)-1]
}

func (s *BaseSuite) TeardownTest() {
	if *IsPersistent || *DryRun {
		s.Skip("Skipping test teardown")
	}
	s.Log("[* TEST TEARDOWN]")
}

func (s *BaseSuite) TeardownSuite() {
	if *IsPersistent || *DryRun {
		s.Skip("Skipping suite teardown")
	}
	s.Log("[* SUITE TEARDOWN]")
}

// reads a file and writes a new one with substituted vars
func (s *BaseSuite) Envsubst(inputPath string, outputPath string) {
	o, err := envsubst.ReadFile(inputPath)
	s.AssertNil(err)
	s.AssertNil(os.WriteFile(outputPath, o, 0644))
}

func (s *BaseSuite) GetCurrentSuiteName() string {
	return CurrentSpecReport().ContainerHierarchyTexts[0]
}

func (s *BaseSuite) CreateLogger() {
	suiteName := s.GetCurrentSuiteName()
	var err error
	s.LogFile, err = os.Create("summary/" + suiteName + ".log")
	if err != nil {
		Fail("Unable to create log file.")
	}
	s.Logger = log.New(io.Writer(s.LogFile), "", log.LstdFlags)
}

// Logs to files by default, logs to stdout when VERBOSE=true with GinkgoWriter
// to keep console tidy
func (s *BaseSuite) Log(log any, arg ...any) {
	var logStr string
	if len(arg) == 0 {
		logStr = fmt.Sprint(log)
	} else {
		logStr = fmt.Sprintf(fmt.Sprint(log), arg...)
	}
	logs := strings.Split(logStr, "\n")

	for _, line := range logs {
		s.Logger.Println(line)
	}
	if *IsVerbose {
		GinkgoWriter.Println(logStr)
	}
}

// sets CALICO_NETWORK_CONFIG, ADDITIONAL_VPP_CONFIG, env vars, applies configs and rollout restarts cluster
func (s *BaseSuite) SetMtuAndRestart(CALICO_NETWORK_CONFIG string, ADDITIONAL_VPP_CONFIG string) {
	os.Setenv("CALICO_NETWORK_CONFIG", CALICO_NETWORK_CONFIG)
	os.Setenv("ADDITIONAL_VPP_CONFIG", ADDITIONAL_VPP_CONFIG)

	if KindCluster {
		s.AssertNil(godotenv.Load("kubernetes/.vars"))
		s.Envsubst("kubernetes/kind-calicovpp-config-template.yaml", "kubernetes/kind-calicovpp-config.yaml")

		cmd := exec.Command("kubectl", "apply", "-f", "kubernetes/kind-calicovpp-config.yaml")
		s.Log(cmd.String())
		o, err := cmd.CombinedOutput()
		s.Log(string(o))
		s.AssertNil(err)
	} else {
		s.Envsubst("kubernetes/baremetal-calicovpp-config-template.yaml", "kubernetes/baremetal-calicovpp-config.yaml")

		cmd := exec.Command("kubectl", "apply", "-f", "kubernetes/baremetal-calicovpp-config.yaml")
		s.Log(cmd.String())
		o, err := cmd.CombinedOutput()
		s.Log(string(o))
		s.AssertNil(err)
	}

	cmd := exec.Command("kubectl", "-n", "calico-vpp-dataplane", "rollout", "restart", "ds/calico-vpp-node")
	s.Log(cmd.String())
	o, err := cmd.CombinedOutput()
	s.Log(string(o))
	s.AssertNil(err)

	cmd = exec.Command("kubectl", "-n", "calico-vpp-dataplane", "rollout", "status", "ds/calico-vpp-node")
	s.Log(cmd.String())
	o, err = cmd.CombinedOutput()
	s.Log(string(o))
	s.AssertNil(err)

	cmd = exec.Command("kubectl", "-n", "calico-system", "rollout", "status", "ds/calico-node")
	s.Log(cmd.String())
	o, err = cmd.CombinedOutput()
	s.Log(string(o))
	s.AssertNil(err)

	// let vpp-dataplane recover, should help with stability issues
	s.Log("Waiting for 20 seconds")
	time.Sleep(time.Second * 20)
}

func (s *BaseSuite) SkipIfBareMetalCluster() {
	if !KindCluster {
		Skip("Kube-Test running on a bare metal cluster. Skipping")
	}
}
