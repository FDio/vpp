package hst_kind

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"runtime"
	"strings"

	. "fd.io/hs-test/infra/common"
	"github.com/a8m/envsubst"
	. "github.com/onsi/ginkgo/v2"

	"github.com/joho/godotenv"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type KindSuite struct {
	HstCommon
	ClientSet        *kubernetes.Clientset
	Config           *rest.Config
	Namespace        string
	KubeconfigPath   string
	CurrentlyRunning map[string]*Pod
	images           []string
	AllPods          map[string]*Pod
	MainContext      context.Context
	Pods             struct {
		ServerGeneric *Pod
		ClientGeneric *Pod
		Nginx         *Pod
		NginxProxy    *Pod
		Ab            *Pod
	}
}

var imagesLoaded bool
var kindTests = map[string][]func(s *KindSuite){}

const VclConfIperf = "echo \"vcl {\n" +
	"rx-fifo-size 4000000\n" +
	"tx-fifo-size 4000000\n" +
	"app-scope-local\n" +
	"app-scope-global\n" +
	"app-socket-api abstract:vpp/session\n" +
	"}\" > /vcl.conf"

const VclConfNginx = "echo \"vcl {\n" +
	"heapsize 64M\n" +
	"rx-fifo-size 4000000\n" +
	"tx-fifo-size 4000000\n" +
	"segment-size 4000000000\n" +
	"add-segment-size 4000000000\n" +
	"event-queue-size 100000\n" +
	"use-mq-eventfd\n" +
	"app-socket-api abstract:vpp/session\n" +
	"}\" > /vcl.conf"

func RegisterKindTests(tests ...func(s *KindSuite)) {
	kindTests[GetTestFilename()] = tests
}

func (s *KindSuite) SetupTest() {
	s.MainContext = context.Background()
	s.HstCommon.SetupTest()
}

func (s *KindSuite) SetupSuite() {
	s.HstCommon.SetupSuite()

	s.CurrentlyRunning = make(map[string]*Pod)
	s.LoadPodConfigs()
	s.initPods()
	if !imagesLoaded {
		s.loadDockerImages()
	}

	if *WhoAmI == "root" {
		s.KubeconfigPath = "/.kube/config"
	} else {
		s.KubeconfigPath = "/home/" + *WhoAmI + "/.kube/config"
	}
	s.Log("User: '%s'", *WhoAmI)
	s.Log("Config path: '%s'", s.KubeconfigPath)

	var err error
	s.Config, err = clientcmd.BuildConfigFromFlags("", s.KubeconfigPath)
	s.AssertNil(err)

	s.ClientSet, err = kubernetes.NewForConfig(s.Config)
	s.AssertNil(err)

	if !imagesLoaded {
		s.createNamespace(s.Namespace)
		imagesLoaded = true
	}
}

// sets CALICO_NETWORK_CONFIG, ADDITIONAL_VPP_CONFIG, env vars, applies configs and rollout restarts cluster
func (s *KindSuite) SetMtuAndRestart(CALICO_NETWORK_CONFIG string, ADDITIONAL_VPP_CONFIG string) {
	os.Setenv("CALICO_NETWORK_CONFIG", CALICO_NETWORK_CONFIG)
	os.Setenv("ADDITIONAL_VPP_CONFIG", ADDITIONAL_VPP_CONFIG)
	s.AssertNil(godotenv.Load("kubernetes/.vars"))

	s.Envsubst("kubernetes/calico-config-template.yaml", "kubernetes/calico-config.yaml")

	cmd := exec.Command("kubectl", "apply", "-f", "kubernetes/calico-config.yaml")
	s.Log(cmd.String())
	o, err := cmd.CombinedOutput()
	s.Log(string(o))
	s.AssertNil(err)

	cmd = exec.Command("kubectl", "-n", "calico-vpp-dataplane", "rollout", "restart", "ds/calico-vpp-node")
	s.Log(cmd.String())
	o, err = cmd.CombinedOutput()
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
}

func (s *KindSuite) TeardownTest() {
	s.HstCommon.TeardownTest()
	if len(s.CurrentlyRunning) != 0 {
		s.Log("Removing:")
		for _, pod := range s.CurrentlyRunning {
			s.Log("   %s", pod.Name)
			s.AssertNil(s.deletePod(s.Namespace, pod.Name))
		}
	}
}

func (s *KindSuite) TeardownSuite() {
	s.HstCommon.TeardownSuite()
	if len(s.CurrentlyRunning) == 0 {
		return
	}
	s.Log("Removing:\n   %s", s.Namespace)
	s.AssertNil(s.deleteNamespace(s.Namespace))
}

// Quick and dirty fix for now. Runs 'ldd /usr/lib/libvcl_ldpreload.so'
// and searches for the first version string, then creates symlinks.
func (s *KindSuite) FixVersionNumber(pods ...*Pod) {
	regex := regexp.MustCompile(`lib.*\.so\.([0-9]+\.[0-9]+)`)
	var match []string
	for _, pod := range pods {
		if strings.Contains(pod.Name, "generic") {
			o, _ := pod.Exec(context.TODO(), []string{"/bin/bash", "-c",
				"ldd /usr/lib/libvcl_ldpreload.so"})
			match = regex.FindStringSubmatch(o)
			break
		}
	}

	if len(match) > 1 {
		version := match[1]
		s.Log("Found version: %s", version)
		cmd := fmt.Sprintf("for file in /usr/lib/*.so; do\n"+
			"if [ -e \"$file\" ]; then\n"+
			"base=$(basename \"$file\")\n"+
			"newlink=\"/usr/lib/${base}.%s\"\n"+
			"ln -s \"$file\" \"$newlink\"\n"+
			"fi\n"+
			"done", version)
		for _, pod := range pods {
			pod.Exec(context.TODO(), []string{"/bin/bash", "-c", cmd})
		}

	} else {
		s.Log("Couldn't find version.")
	}
}

func (s *KindSuite) CreateNginxConfig(pod *Pod) {
	values := struct {
		Workers uint8
		Port    uint16
	}{
		Workers: 1,
		Port:    8081,
	}
	pod.CreateConfigFromTemplate(
		"/nginx.conf",
		"./resources/nginx/nginx.conf",
		values,
	)
}

func (s *KindSuite) Envsubst(inputPath string, outputPath string) {
	o, err := envsubst.ReadFile(inputPath)
	s.AssertNil(err)
	os.WriteFile(outputPath, o, 0644)
}

func (s *KindSuite) CreateNginxProxyConfig(pod *Pod) {
	pod.Exec(context.TODO(), []string{"/bin/bash", "-c", "mkdir -p /tmp/nginx"})
	values := struct {
		Workers   uint8
		LogPrefix string
		Proxy     string
		Server    string
		Port      uint16
		Upstream1 string
		Upstream2 string
		Upstream3 string
	}{
		Workers:   1,
		LogPrefix: s.Pods.NginxProxy.Name,
		Proxy:     s.Pods.NginxProxy.IpAddress,
		Server:    s.Pods.Nginx.IpAddress,
		Port:      8080,
		Upstream1: "8081",
		Upstream2: "8081",
		Upstream3: "8081",
	}
	pod.CreateConfigFromTemplate(
		"/nginx.conf",
		"./resources/nginx/nginx_proxy_mirroring.conf",
		values,
	)
}

var _ = Describe("KindSuite", Ordered, ContinueOnFailure, Label("Perf"), func() {
	var s KindSuite
	BeforeAll(func() {
		s.SetupSuite()
		s.SetMtuAndRestart("", "")
	})
	BeforeEach(func() {
		s.SetupTest()
	})
	AfterEach(func() {
		s.TeardownTest()
	})
	AfterAll(func() {
		s.TeardownSuite()
	})

	for filename, tests := range kindTests {
		for _, test := range tests {
			test := test
			pc := reflect.ValueOf(test).Pointer()
			funcValue := runtime.FuncForPC(pc)
			testName := filename + "/" + strings.Split(funcValue.Name(), ".")[2]
			It(testName, func(ctx SpecContext) {
				s.Log(testName + ": BEGIN")
				test(&s)
			}, SpecTimeout(TestTimeout))
		}
	}
})
