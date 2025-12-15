package kube_test

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/a8m/envsubst"
	"github.com/joho/godotenv"
	. "github.com/onsi/ginkgo/v2"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var IsCoverage = flag.Bool("coverage", false, "use coverage run config")
var IsPersistent = flag.Bool("persist", false, "persists topology config")
var IsVerbose = flag.Bool("verbose", false, "verbose test output")
var IsVppDebug = flag.Bool("debug", false, "attach gdb to vpp")
var Timeout = flag.Int("timeout", 30, "test timeout override (in minutes)")
var TestTimeout time.Duration
var Kubeconfig string
var KindCluster bool
var Ppid string
var Logger *log.Logger
var LogFile *os.File
var ClientSet *kubernetes.Clientset
var KubeConfig *rest.Config

const (
	LogDir      string = "/tmp/kube-test/"
	EnvVarsFile string = "kubernetes/.vars"
)

type BaseSuite struct {
	Namespace        string
	CurrentlyRunning map[string]*Pod
	images           []string
	AllPods          map[string]*Pod
	MainContext      context.Context
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

	CreateLogger()
}

func (s *BaseSuite) Skip(args string) {
	Skip(args)
}

func (s *BaseSuite) SetupTest() {
	TestCounterFunc()
	Log("[* TEST SETUP]")
	s.WaitForComponents()
}

func (s *BaseSuite) SetupSuite() {
	CreateLogger()
	Log("[* SUITE SETUP]")
	Ppid = fmt.Sprint(os.Getppid())
	Ppid = Ppid[:len(Ppid)-1]

	s.CurrentlyRunning = make(map[string]*Pod)
	s.LoadPodConfigs()

	var err error
	KubeConfig, err = clientcmd.BuildConfigFromFlags("", Kubeconfig)
	AssertNil(err)

	ClientSet, err = kubernetes.NewForConfig(KubeConfig)
	AssertNil(err)

	if !imagesLoaded {
		s.loadDockerImages()
		s.createNamespace(s.Namespace)
		imagesLoaded = true
	}
}

func (s *BaseSuite) TeardownTest() {
	if *IsPersistent {
		s.Skip("Skipping test teardown")
	}
	Log("[* TEST TEARDOWN]")
}

func (s *BaseSuite) TeardownSuite() {
	if *IsPersistent {
		s.Skip("Skipping suite teardown")
	}
	Log("[* SUITE TEARDOWN]")
}

// reads a file and writes a new one with substituted vars
func (s *BaseSuite) Envsubst(inputPath string, outputPath string) {
	o, err := envsubst.ReadFile(inputPath)
	AssertNil(err)
	AssertNil(os.WriteFile(outputPath, o, 0644))
}

func (s *BaseSuite) WaitForComponents() {
	Log("Waiting for components.")

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
			Log(cmd.String())

			output, err := cmd.CombinedOutput()
			Log(string(output))
			AssertNil(err)
		}(check)
	}

	wg.Add(1)
	go func() {
		defer GinkgoRecover()
		defer wg.Done()

		cmd := exec.Command("kubectl", "-n", "calico-apiserver", "rollout", "status", "deployment/calico-apiserver")
		Log(cmd.String())
		output, err := cmd.CombinedOutput()
		Log(string(output))

		if err != nil {
			Log("trying calico-system namespace")
			cmd = exec.Command("kubectl", "-n", "calico-system", "rollout", "status", "deployment/calico-apiserver")
			Log(cmd.String())
			output, err = cmd.CombinedOutput()
			Log(string(output))
		}
		AssertNil(err)
	}()

	wg.Wait()

	Log("All components are ready")
}

// sets CALICO_NETWORK_CONFIG, ADDITIONAL_VPP_CONFIG, env vars, applies configs and rollout restarts cluster
func (s *BaseSuite) SetMtuAndRestart(CALICO_NETWORK_CONFIG string, ADDITIONAL_VPP_CONFIG string) {
	if os.Getenv("SKIP_CONFIG") == "true" {
		Log("** SKIP_CONFIG=true, not updating configuration! **")
		return
	}
	os.Setenv("CALICO_NETWORK_CONFIG", CALICO_NETWORK_CONFIG)
	os.Setenv("ADDITIONAL_VPP_CONFIG", ADDITIONAL_VPP_CONFIG)

	// Kube-test expects a running cluster when running tests, therefore
	// kubernetes/.vars file is initialized by scripts/setup-cluster.sh when testing on a KinD cluster,
	// but initialized by kube-test itself when testing on a bare metal cluster.
	if KindCluster {
		AssertNil(godotenv.Load("kubernetes/.vars"))
		s.Envsubst("kubernetes/kind-calicovpp-config-template.yaml", "kubernetes/kind-calicovpp-config.yaml")

		cmd := exec.Command("kubectl", "apply", "-f", "kubernetes/kind-calicovpp-config.yaml")
		Log(cmd.String())
		o, err := cmd.CombinedOutput()
		Log(string(o))
		AssertNil(err)
	} else {
		fileValues, err := godotenv.Read(EnvVarsFile)

		if err == nil {
			Log("File '%s' exists. Checking env vars", EnvVarsFile)
			handleExistingVarsFile(fileValues)
		} else if os.IsNotExist(err) {
			Log("'%s' not found. Checking env vars", EnvVarsFile)
			handleNewVarsFile()
		} else {
			AssertNil(err)
		}
		godotenv.Load("kubernetes/.vars")
		s.Envsubst("kubernetes/baremetal-calicovpp-config-template.yaml", "kubernetes/baremetal-calicovpp-config.yaml")

		cmd := exec.Command("kubectl", "apply", "-f", "kubernetes/baremetal-calicovpp-config.yaml")
		Log(cmd.String())
		o, err := cmd.CombinedOutput()
		Log(string(o))
		AssertNil(err)
	}

	cmd := exec.Command("kubectl", "-n", "calico-vpp-dataplane", "rollout", "restart", "ds/calico-vpp-node")
	Log(cmd.String())
	o, err := cmd.CombinedOutput()
	Log(string(o))
	AssertNil(err)

	Log("Config applied, sleeping for 30s")
	time.Sleep(time.Second * 30)
}

func (s *BaseSuite) SkipIfBareMetalCluster() {
	if !KindCluster {
		Skip("Kube-Test running on a bare metal cluster. Skipping")
	}
}
