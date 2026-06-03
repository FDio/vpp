package kube_test

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/a8m/envsubst"
	"github.com/joho/godotenv"
	. "github.com/onsi/ginkgo/v2"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

	// ComponentRolloutTimeout bounds how long we wait for a single component's
	// rollout to be observed as complete. It should be long enough for a worst
	// case CalicoVPP / DaemonSet rollout (multiple node restarts in sequence
	// with readiness probe delays) but short enough to fail fast when a pod is
	// genuinely stuck (e.g. networking lost after a dataplane restart).
	ComponentRolloutTimeout = 5 * time.Minute
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

// rolloutStatus runs `kubectl rollout status` for a single resource with a
// bounded per-call timeout. Both the kubectl process and the underlying
// rollout-status watch are bounded so we cannot hang past ComponentRolloutTimeout.
// kubectl's own `--timeout` flag stops the rollout watch on the server side,
// and exec.CommandContext kills the kubectl subprocess if it does not exit on
// its own (e.g. apiserver is unreachable). Without these bounds a single bad
// rollout would block the entire ginkgo spec until the SpecTimeout fires.
func rolloutStatus(namespace, resource string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "kubectl",
		"-n", namespace,
		"rollout", "status", resource,
		fmt.Sprintf("--timeout=%s", timeout.String()),
	)
	Log(cmd.String())
	output, err := cmd.CombinedOutput()
	Log(string(output))
	return string(output), err
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

			_, err := rolloutStatus(c.namespace, fmt.Sprintf("%s/%s", c.resourceType, c.resourceName), ComponentRolloutTimeout)
			AssertNil(err, "rollout status for %s/%s in namespace %s failed or timed out", c.resourceType, c.resourceName, c.namespace)
		}(check)
	}

	wg.Add(1)
	go func() {
		defer GinkgoRecover()
		defer wg.Done()

		// calico-apiserver lives in either calico-apiserver or calico-system depending on the
		// operator version; try the former first, fall back to the latter only if "not found".
		output, err := rolloutStatus("calico-apiserver", "deployment/calico-apiserver", ComponentRolloutTimeout)
		if err != nil && strings.Contains(output, "NotFound") {
			Log("trying calico-system namespace")
			_, err = rolloutStatus("calico-system", "deployment/calico-apiserver", ComponentRolloutTimeout)
		}
		AssertNil(err, "rollout status for calico-apiserver failed or timed out")
	}()

	wg.Wait()

	Log("All components are ready")
}

// sets CALICO_NETWORK_CONFIG, ADDITIONAL_VPP_CONFIG, env vars, applies configs and rollout restarts cluster
func (s *BaseSuite) ReconfigureAndRestart(CALICO_NETWORK_CONFIG string, ADDITIONAL_VPP_CONFIG string, CALICOVPP_ENABLE_MEMIF bool) {
	if os.Getenv("SKIP_CONFIG") == "true" {
		Log("** SKIP_CONFIG=true, not updating configuration! **")
		return
	}
	os.Setenv("CALICOVPP_ENABLE_MEMIF", fmt.Sprintf("\"%v\"", CALICOVPP_ENABLE_MEMIF))
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

func (s *BaseSuite) getPodsByName(podName string) *Pod {
	return s.AllPods[podName+Ppid]
}

// ListPodsInNamespace lists all pods in a specific namespace
func (s *BaseSuite) ListPodsInNamespace(ctx context.Context, namespace string) ([]string, error) {
	podList, err := ClientSet.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var podNames []string
	for _, pod := range podList.Items {
		podNames = append(podNames, pod.Name)
	}

	return podNames, nil
}

func (s *BaseSuite) loadDockerImages() {
	if !KindCluster {
		return
	}
	Log("This may take a while. If you encounter problems, " +
		"try loading docker images manually: 'kind load docker-image [image]'")

	var cmd *exec.Cmd
	var out []byte
	var err error
	for _, image := range s.images {
		Log("loading docker image %s...", image)
		cmd = exec.Command("go", "run", "sigs.k8s.io/kind@v0.29.0", "load", "docker-image", image)
		out, err = cmd.CombinedOutput()
		Log(string(out))
		AssertNil(err, string(out))
	}
}

func (s *BaseSuite) createNamespace(name string) {
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}

	// Create the namespace in the cluster
	_, err := ClientSet.CoreV1().Namespaces().Create(context.TODO(), namespace, metav1.CreateOptions{})
	AssertNil(err)
	Log("Namespace '%s' created", name)
}

func (s *BaseSuite) DeleteNamespace(namespace string) error {
	return ClientSet.CoreV1().Namespaces().Delete(context.TODO(), namespace, metav1.DeleteOptions{})
}
