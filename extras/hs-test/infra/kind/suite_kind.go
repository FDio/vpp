package hst_kind

import (
	"fmt"
	"os"
	"reflect"
	"regexp"
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
	s.Log("User: '%s'", *SudoUser)
	s.Log("Config path: '%s'", s.KubeconfigPath)

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
	s.HstCommon.TeardownSuite()
	s.Log("   %s", s.Namespace)
	s.AssertNil(s.deleteNamespace(s.Namespace))
}

// Quick and dirty fix for now. Runs 'ldd /usr/lib/libvcl_ldpreload.so'
// and searches for the first version string, then creates symlinks.
func (s *KindSuite) FixVersionNumber(pods ...*Pod) {
	regex := regexp.MustCompile(`lib.*\.so\.([0-9]+\.[0-9]+)`)
	o, _ := s.Exec(s.Pods.ServerGeneric, []string{"/bin/bash", "-c",
		"ldd /usr/lib/libvcl_ldpreload.so"})
	match := regex.FindStringSubmatch(o)

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
			s.Exec(pod, []string{"/bin/bash", "-c", cmd})
		}

	} else {
		s.Log("Couldn't find version.")
	}
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
		Port    uint16
	}{
		Workers: 1,
		Port:    8081,
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
