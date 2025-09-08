package hst_kube

import (
	"bytes"
	"context"
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
	suite         *KubeSuite
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

func (s *KubeSuite) LoadPodConfigs() {
	data, err := os.ReadFile("kubernetes/pod-definitions.yaml")
	s.AssertNil(err)

	var config Config
	err = yaml.Unmarshal(data, &config)
	s.AssertNil(err)

	for _, podData := range config.Pods {
		newPod(s, podData)
	}
}

func newPod(suite *KubeSuite, input PodYaml) (*Pod, error) {
	var pod = new(Pod)
	pod.suite = suite
	pod.Name = input.Name + suite.Ppid
	pod.Image = input.Image[0].Name
	pod.ContainerName = input.Container[0].Name
	pod.Worker = input.Worker[0].Name
	pod.Namespace = input.Namespace[0].Name + suite.Ppid

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

func (s *KubeSuite) initPods() {
	s.Pods.Ab = s.getPodsByName("ab")
	s.Pods.ClientGeneric = s.getPodsByName("client-generic")
	s.Pods.ServerGeneric = s.getPodsByName("server-generic")
	s.Pods.Nginx = s.getPodsByName("nginx-ldp")
	s.Pods.NginxProxy = s.getPodsByName("nginx-proxy")
}

func (s *KubeSuite) getPodsByName(podName string) *Pod {
	return s.AllPods[podName+s.Ppid]
}

func (pod *Pod) CopyToPod(src string, dst string) {
	cmd := exec.Command("kubectl", "--kubeconfig="+pod.suite.KubeconfigPath, "cp", src, pod.Namespace+"/"+pod.Name+":"+dst)
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
		pod.suite.Log("Error creating executor: %s", err.Error())
	}

	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
		Tty:    true,
	})

	output := stdout.String() + stderr.String()

	if err != nil {
		return output, err
	}

	return output, nil
}

func (pod *Pod) CreateConfigFromTemplate(targetConfigName string, templateName string, values any) {
	template := template.Must(template.ParseFiles(templateName))

	f, err := os.CreateTemp(LogDir, "hst-config")
	pod.suite.AssertNil(err, fmt.Sprint(err))
	defer os.Remove(f.Name())

	err = template.Execute(f, values)
	pod.suite.AssertNil(err, err)
	err = f.Close()
	pod.suite.AssertNil(err, err)

	pod.CopyToPod(f.Name(), targetConfigName)
}
