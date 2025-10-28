package kube_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"text/template"

	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/remotecommand"
)

type Pod struct {
	suite         *BaseSuite
	Name          string
	Image         string
	ContainerName string
	Worker        string
	Namespace     string
	IpAddress     string
	CreatedPod    *corev1.Pod
}

type Image struct {
	Name string `yaml:"name"`
}
type Container struct {
	Name string `yaml:"name"`
}
type Worker struct {
	Name string `yaml:"name"`
}
type Namespace struct {
	Name string `yaml:"name"`
}
type PodYaml struct {
	Name      string      `yaml:"name"`
	Image     []Image     `yaml:"image"`
	Container []Container `yaml:"container"`
	Worker    []Worker    `yaml:"worker"`
	Namespace []Namespace `yaml:"namespace"`
}
type Config struct {
	Pods []PodYaml `yaml:"pods"`
}

func (s *BaseSuite) LoadPodConfigs() {
	envVarsSet := os.Getenv("KUBE_WRK1") != "" && os.Getenv("KUBE_WRK2") != ""

	if KindCluster && !envVarsSet {
		s.Log("KUBE_WRK1, KUBE_WRK2 not set, using default names (KinD only)")
		os.Setenv("KUBE_WRK1", "kind-worker")
		os.Setenv("KUBE_WRK2", "kind-worker2")
		envVarsSet = true
	}

	_, err := os.Stat("kubernetes/pod-definitions.yaml")
	if envVarsSet {
		s.Envsubst("kubernetes/pod-definitions-template.yaml", "kubernetes/pod-definitions.yaml")
		s.Log("pod-definitions.yaml OK [updated]")
	} else if err == nil {
		s.Log("pod-definitions.yaml OK")
	} else if errors.Is(err, os.ErrNotExist) {
		s.AssertNil(err, "Please set KUBE_WRK1 and KUBE_WRK2 env vars")
	} else {
		s.AssertNil(err)
	}

	data, err := os.ReadFile("kubernetes/pod-definitions.yaml")
	s.AssertNil(err)

	var config Config
	err = yaml.Unmarshal(data, &config)
	s.AssertNil(err)

	for _, podData := range config.Pods {
		newPod(s, podData)
	}
}

func newPod(suite *BaseSuite, input PodYaml) (*Pod, error) {
	var pod = new(Pod)
	pod.suite = suite
	pod.Name = input.Name + Ppid
	pod.Image = input.Image[0].Name
	pod.ContainerName = input.Container[0].Name
	pod.Worker = input.Worker[0].Name
	pod.Namespace = input.Namespace[0].Name + Ppid

	if suite.AllPods == nil {
		suite.AllPods = make(map[string]*Pod)
		suite.Namespace = pod.Namespace
	}

	suite.AllPods[pod.Name] = pod
	if !slices.Contains(suite.images, pod.Image) {
		suite.images = append(suite.images, pod.Image)
	}

	return pod, nil
}

func (s *BaseSuite) initPods() {
	s.Pods.Ab = s.getPodsByName("ab")
	s.Pods.ClientGeneric = s.getPodsByName("client-generic")
	s.Pods.ServerGeneric = s.getPodsByName("server-generic")
	s.Pods.Nginx = s.getPodsByName("nginx-ldp")
	s.Pods.NginxProxy = s.getPodsByName("nginx-proxy")
}

func (s *BaseSuite) getPodsByName(podName string) *Pod {
	return s.AllPods[podName+Ppid]
}

func (pod *Pod) CopyToPod(src string, dst string) {
	cmd := exec.Command("kubectl", "--kubeconfig="+Kubeconfig, "cp", src, pod.Namespace+"/"+pod.Name+":"+dst)
	out, err := cmd.CombinedOutput()
	pod.suite.AssertNil(err, string(out))
}

func (pod *Pod) Exec(ctx context.Context, command []string) (string, error) {
	var stdout, stderr bytes.Buffer

	// Prepare the request
	req := pod.suite.ClientSet.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod.Name).
		Namespace(pod.suite.Namespace).
		SubResource("exec").
		Param("container", pod.ContainerName).
		Param("stdout", "true").
		Param("stderr", "true").
		Param("tty", "true")

	for _, cmd := range command {
		req = req.Param("command", cmd)
	}
	pod.suite.Log("%s: %s\n", pod.Name, command)

	executor, err := remotecommand.NewSPDYExecutor(pod.suite.Config, "POST", req.URL())
	if err != nil {
		return "", err
	}

	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
		Tty:    true,
	})

	output := stdout.String()
	if stderr.String() != "" {
		err = errors.New(stderr.String())
	}

	return output, err
}

func (pod *Pod) CreateConfigFromTemplate(targetConfigName string, templateName string, values any) {
	template := template.Must(template.ParseFiles(templateName))

	f, err := os.CreateTemp(LogDir, "kube-config")
	pod.suite.AssertNil(err, fmt.Sprint(err))
	defer os.Remove(f.Name())

	err = template.Execute(f, values)
	pod.suite.AssertNil(err, err)
	err = f.Close()
	pod.suite.AssertNil(err, err)

	pod.CopyToPod(f.Name(), targetConfigName)
}
