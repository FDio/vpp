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
	"sync"
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
var Ppid string

const (
	LogDir      string = "/tmp/kube-test/"
	EnvVarsFile string = "kubernetes/.vars"
)

type BaseSuite struct {
	ClientSet        *kubernetes.Clientset
	Config           *rest.Config
	Namespace        string
	CurrentlyRunning map[string]*Pod
	images           []string
	AllPods          map[string]*Pod
	MainContext      context.Context
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

type kubeComponent struct {
	name         string
	namespace    string
	resourceType string
	resourceName string
}

func init() {
	if err := os.Mkdir(LogDir, os.FileMode(0777)); err != nil {
		if !os.IsExist(err) {
			panic(fmt.Sprint(err))
		}
	}
}

func (s *BaseSuite) Skip(args string) {
	Skip(args)
}

func (s *BaseSuite) SetupTest() {
	TestCounterFunc()
	s.Log("[* TEST SETUP]")
	s.WaitForComponents()
}

func (s *BaseSuite) SetupSuite() {
	s.CreateLogger()
	s.Log("[* SUITE SETUP]")
	Ppid = fmt.Sprint(os.Getppid())
	Ppid = Ppid[:len(Ppid)-1]
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

func (s *BaseSuite) WaitForComponents() {
	s.Log("Waiting for components.")

	var wg sync.WaitGroup

	// Define all the simple, single-command checks.
	checks := []kubeComponent{
		{name: "calico-vpp-node", namespace: "calico-vpp-dataplane", resourceType: "ds", resourceName: "calico-vpp-node"},
		{name: "calico-node", namespace: "calico-system", resourceType: "ds", resourceName: "calico-node"},
		{name: "coredns", namespace: "kube-system", resourceType: "deployment", resourceName: "coredns"},
		{name: "calico-kube-controllers", namespace: "calico-system", resourceType: "deployment", resourceName: "calico-kube-controllers"},
	}

	wg.Add(len(checks))

	for _, check := range checks {
		go func(c kubeComponent) {
			defer GinkgoRecover()
			defer wg.Done()

			cmd := exec.Command("kubectl", "-n", c.namespace, "rollout", "status", fmt.Sprintf("%s/%s", c.resourceType, c.resourceName))
			s.Log(cmd.String())

			output, err := cmd.CombinedOutput()
			s.Log(string(output))
			s.AssertNil(err)
		}(check)
	}

	wg.Add(1)
	go func() {
		defer GinkgoRecover()
		defer wg.Done()

		cmd := exec.Command("kubectl", "-n", "calico-apiserver", "rollout", "status", "deployment/calico-apiserver")
		s.Log(cmd.String())
		output, err := cmd.CombinedOutput()
		s.Log(string(output))

		if err != nil {
			s.Log("trying calico-system namespace")
			cmd = exec.Command("kubectl", "-n", "calico-system", "rollout", "status", "deployment/calico-apiserver")
			s.Log(cmd.String())
			output, err = cmd.CombinedOutput()
			s.Log(string(output))
		}
		s.AssertNil(err)
	}()

	wg.Wait()

	s.Log("All components are ready")
}

// sets CALICO_NETWORK_CONFIG, ADDITIONAL_VPP_CONFIG, env vars, applies configs and rollout restarts cluster
func (s *BaseSuite) SetMtuAndRestart(CALICO_NETWORK_CONFIG string, ADDITIONAL_VPP_CONFIG string) {
	if os.Getenv("SKIP_CONFIG") == "true" {
		s.Log("** SKIP_CONFIG=true, not updating configuration! **")
		return
	}
	os.Setenv("CALICO_NETWORK_CONFIG", CALICO_NETWORK_CONFIG)
	os.Setenv("ADDITIONAL_VPP_CONFIG", ADDITIONAL_VPP_CONFIG)

	// Kube-test expects a running cluster when running tests, therefore
	// kubernetes/.vars file is initialized by scripts/setup-cluster.sh when testing on a KinD cluster,
	// but initialized by kube-test itself when testing on a bare metal cluster.
	if KindCluster {
		s.AssertNil(godotenv.Load("kubernetes/.vars"))
		s.Envsubst("kubernetes/kind-calicovpp-config-template.yaml", "kubernetes/kind-calicovpp-config.yaml")

		cmd := exec.Command("kubectl", "apply", "-f", "kubernetes/kind-calicovpp-config.yaml")
		s.Log(cmd.String())
		o, err := cmd.CombinedOutput()
		s.Log(string(o))
		s.AssertNil(err)
	} else {
		fileValues, err := godotenv.Read(EnvVarsFile)

		if err == nil {
			s.Log("File '%s' exists. Checking env vars", EnvVarsFile)
			s.handleExistingVarsFile(fileValues)
		} else if os.IsNotExist(err) {
			s.Log("'%s' not found. Checking env vars", EnvVarsFile)
			s.handleNewVarsFile()
		} else {
			s.AssertNil(err)
		}
		godotenv.Load("kubernetes/.vars")
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

	s.Log("Config applied, sleeping for 30s")
	time.Sleep(time.Second * 30)
}

func (s *BaseSuite) SkipIfBareMetalCluster() {
	if !KindCluster {
		Skip("Kube-Test running on a bare metal cluster. Skipping")
	}
}
