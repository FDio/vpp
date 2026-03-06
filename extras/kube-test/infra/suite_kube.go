package kube_test

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
)

type KubeSuite struct {
	BaseSuite
	Pods struct {
		ServerGeneric *Pod
		ClientGeneric *Pod
		Nginx         *Pod
		NginxProxy    *Pod
		Ab            *Pod
	}
}

var imagesLoaded bool
var kubeTests = map[string][]func(s *KubeSuite){}
var kubeMWTests = map[string][]func(s *KubeSuite){}

func RegisterKubeTests(tests ...func(s *KubeSuite)) {
	kubeTests[GetTestFilename()] = tests
}
func RegisterKubeMWTests(tests ...func(s *KubeSuite)) {
	kubeMWTests[GetTestFilename()] = tests
}

func (s *KubeSuite) SetupTest() {
	s.MainContext = context.Background()
	s.BaseSuite.SetupTest()
}

func (s *KubeSuite) SetupSuite() {
	s.BaseSuite.SetupSuite()
	s.Pods.Ab = s.getPodsByName("ab")
	s.Pods.ClientGeneric = s.getPodsByName("client-generic")
	s.Pods.ServerGeneric = s.getPodsByName("server-generic")
	s.Pods.Nginx = s.getPodsByName("nginx-ldp")
	s.Pods.NginxProxy = s.getPodsByName("nginx-proxy")

}

func (s *KubeSuite) TeardownTest() {
	s.BaseSuite.TeardownTest()
	if len(s.CurrentlyRunning) != 0 {
		Log("Removing pods:")
		for _, pod := range s.CurrentlyRunning {
			Log("   %s", pod.Name)
			AssertNil(pod.deletePod())
		}
	}
}

func (s *KubeSuite) TeardownSuite() {
	s.BaseSuite.TeardownSuite()
}

// Quick and dirty fix for now. Runs 'ldd /usr/lib/libvcl_ldpreload.so'
// and searches for the first version string, then creates symlinks.
func (s *KubeSuite) FixVersionNumber(pods ...*Pod) {
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
		Log("Found version: %s", version)
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
		Log("Couldn't find version.")
	}
}

func (s *KubeSuite) CreateNginxConfig(pod *Pod) {
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

func (s *KubeSuite) CreateNginxProxyConfig(pod *Pod) {
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

var _ = Describe("KubeSuite", Ordered, ContinueOnFailure, func() {
	var s KubeSuite
	BeforeAll(func() {
		s.SetupSuite()
		s.ReconfigureAndRestart("mtu: 0", "tcp { mtu 1460 }\n    cpu { workers 0 }", false)
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

	for filename, tests := range kubeTests {
		for _, test := range tests {
			test := test
			pc := reflect.ValueOf(test).Pointer()
			funcValue := runtime.FuncForPC(pc)
			testName := filename + "/" + strings.Split(funcValue.Name(), ".")[2]
			It(testName, func(ctx SpecContext) {
				Log("[* TEST BEGIN]: " + testName)
				test(&s)
			}, SpecTimeout(TestTimeout))
		}
	}
})

var _ = Describe("KubeMWSuite", Ordered, ContinueOnFailure, Label("Perf", "Multi-worker"), func() {
	var s KubeSuite
	BeforeAll(func() {
		s.SetupSuite()
		s.ReconfigureAndRestart("mtu: 0", "tcp { mtu 1460 }\n    cpu { workers 2 }", false)
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

	for filename, tests := range kubeMWTests {
		for _, test := range tests {
			test := test
			pc := reflect.ValueOf(test).Pointer()
			funcValue := runtime.FuncForPC(pc)
			testName := filename + "/" + strings.Split(funcValue.Name(), ".")[2]
			It(testName, func(ctx SpecContext) {
				Log("[* TEST BEGIN]: " + testName)
				test(&s)
			}, SpecTimeout(TestTimeout))
		}
	}
})
