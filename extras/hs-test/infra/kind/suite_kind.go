package hst_kind

import (
	"os"
	"reflect"
	"runtime"
	"strings"
	"text/template"

	. "fd.io/hs-test/infra/common"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

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
	CurrentlyRunning []string
	images           []string
	Pods             struct {
		ServerGeneric *Pod
		ClientGeneric *Pod
		Nginx         *Pod
		Ab            *Pod
	}
}

var kindTests = map[string][]func(s *KindSuite){}

func RegisterKindTests(tests ...func(s *KindSuite)) {
	kindTests[GetTestFilename()] = tests
}

func (s *KindSuite) SetupTest() {
	s.HstCommon.SetupTest()
}

func (s *KindSuite) SetupSuite() {
	s.HstCommon.SetupSuite()
	RegisterFailHandler(func(message string, callerSkip ...int) {
		Fail(message, callerSkip...)
	})

	s.initPods()
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

	s.createNamespace(s.Namespace)
}

func (s *KindSuite) TeardownTest() {
	s.HstCommon.TeardownTest()
	if len(s.CurrentlyRunning) != 0 {
		for _, pod := range s.CurrentlyRunning {
			s.Log("   %s", pod)
			s.deletePod(s.Namespace, pod)
		}
	}
}

func (s *KindSuite) TeardownSuite() {
	s.Log("   %s", s.Namespace)
	s.AssertNil(s.deleteNamespace(s.Namespace))
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

	s.CopyToPod(s.Pods.Nginx.Name, s.Namespace, f.Name(), targetConfigName)
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
