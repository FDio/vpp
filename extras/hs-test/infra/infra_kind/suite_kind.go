package hst

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"text/template"
	"time"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type KindSuite struct {
	HstSuite
	ClientSet      *kubernetes.Clientset
	Config         *rest.Config
	ServerIp       string
	Namespace      string
	KubeconfigPath string
	ImageNames
	PodNames
	ContainerNames
}

type ImageNames struct {
	HstVpp string
	Nginx  string
	Ab     string
}

type PodNames struct {
	ClientVpp        string
	ServerVpp        string
	Nginx            string
	Ab               string
	CurrentlyRunning []string
}

type ContainerNames struct {
	Server string
	Client string
}

var kindTests = map[string][]func(s *KindSuite){}

func RegisterKindTests(tests ...func(s *KindSuite)) {
	kindTests[GetTestFilename()] = tests
}

func deletePod(clientset *kubernetes.Clientset, namespace, podName string) error {
	return clientset.CoreV1().Pods(namespace).Delete(context.TODO(), podName, metav1.DeleteOptions{GracePeriodSeconds: int64Ptr(0)})
}

func deleteNamespace(clientset *kubernetes.Clientset, namespace string) error {
	return clientset.CoreV1().Namespaces().Delete(context.TODO(), namespace, metav1.DeleteOptions{})
}

func (s *KindSuite) loadDockerImages() {
	s.Log("This may take a while. If you encounter problems, " +
		"try loading docker images manually: 'kind load docker-image [image]'")
	value := reflect.ValueOf(s.ImageNames)
	reflType := reflect.TypeOf(s.ImageNames)
	var cmd *exec.Cmd
	var out []byte
	var err error

	if reflType.Kind() == reflect.Struct {
		for i := range value.NumField() {
			if value.Field(i).Kind() == reflect.String {
				fieldValue := value.Field(i).Interface().(string)
				s.Log("loading docker image %s...", fieldValue)
				cmd = exec.Command("kind", "load", "docker-image", fieldValue)
				out, err = cmd.CombinedOutput()
				s.Log(string(out))
				s.AssertNil(err, string(out))
			}
		}
	} else {
		s.AssertNil(errors.New("not a struct"))
	}
}

func (s *KindSuite) SetupSuite() {
	s.SetupKindSuite()
	s.ImageNames.Ab = "hs-test/ab:latest"
	s.ImageNames.Nginx = "hs-test/nginx-ldp:latest"
	s.ImageNames.HstVpp = "hs-test/vpp:latest"
	s.PodNames.ServerVpp = "server" + s.Ppid
	s.PodNames.ClientVpp = "client" + s.Ppid
	s.PodNames.Nginx = "nginx-ldp" + s.Ppid
	s.PodNames.Ab = "ab" + s.Ppid
	s.Namespace = "namespace" + s.Ppid
	s.ContainerNames.Client = "client"
	s.ContainerNames.Server = "server"

	s.loadDockerImages()

	var err error
	if *SudoUser == "root" {
		s.KubeconfigPath = "/.kube/config"
	} else {
		s.KubeconfigPath = "/home/" + *SudoUser + "/.kube/config"
	}

	s.Config, err = clientcmd.BuildConfigFromFlags("", s.KubeconfigPath)
	s.AssertNil(err)

	s.ClientSet, err = kubernetes.NewForConfig(s.Config)
	s.AssertNil(err)

	s.CreateNamespace(s.Namespace)
}

func (s *KindSuite) TeardownTest() {
	if *IsPersistent {
		return
	}
	s.Log("[TEST TEARDOWN]")
	s.ServerIp = ""
	if len(s.CurrentlyRunning) != 0 {
		for _, pod := range s.CurrentlyRunning {
			s.Log("   %s", pod)
			deletePod(s.ClientSet, s.Namespace, pod)
		}
	}
}

func (s *KindSuite) TeardownSuite() {
	if *IsPersistent {
		return
	}
	s.Log("[SUITE TEARDOWN]")
	s.Log("   %s", s.Namespace)
	s.AssertNil(deleteNamespace(s.ClientSet, s.Namespace))
}

func (s *KindSuite) CreateConfigFromTemplate(targetConfigName string, templateName string, values any) {
	template := template.Must(template.ParseFiles(templateName))

	f, err := os.CreateTemp(LogDir, "hst-config")
	s.AssertNil(err, err)
	defer os.Remove(f.Name())

	err = template.Execute(f, values)
	s.AssertNil(err, err)

	err = f.Close()
	s.AssertNil(err, err)

	s.CopyToPod(s.PodNames.Nginx, s.Namespace, f.Name(), targetConfigName)
}

func (s *KindSuite) CreateNginxConfig() {
	values := struct {
		Workers uint8
	}{
		Workers: 1,
	}
	s.CreateConfigFromTemplate(
		"/nginx.conf",
		"./resources/nginx/nginx.conf",
		values,
	)
}

var _ = Describe("KindSuite", Ordered, ContinueOnFailure, Label("Perf"), func() {
	var s KindSuite
	BeforeAll(func() {
		s.SetupSuite()
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
			}, SpecTimeout(time.Minute*15))
		}
	}
})
