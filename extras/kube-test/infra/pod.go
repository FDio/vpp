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
	"time"

	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
		Log("KUBE_WRK1, KUBE_WRK2 not set, using default names (KinD only)")
		os.Setenv("KUBE_WRK1", "kind-worker")
		os.Setenv("KUBE_WRK2", "kind-worker2")
		envVarsSet = true
	}

	_, err := os.Stat("kubernetes/pod-definitions.yaml")
	if envVarsSet {
		s.Envsubst("kubernetes/pod-definitions-template.yaml", "kubernetes/pod-definitions.yaml")
		Log("pod-definitions.yaml OK [updated]")
	} else if err == nil {
		Log("pod-definitions.yaml OK")
	} else if errors.Is(err, os.ErrNotExist) {
		AssertNil(err, "Please set KUBE_WRK1 and KUBE_WRK2 env vars")
	} else {
		AssertNil(err)
	}

	data, err := os.ReadFile("kubernetes/pod-definitions.yaml")
	AssertNil(err)

	var config Config
	err = yaml.Unmarshal(data, &config)
	AssertNil(err)

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

func (s *BaseSuite) getPodsByName(podName string) *Pod {
	return s.AllPods[podName+Ppid]
}

func (pod *Pod) CopyToPod(src string, dst string) {
	cmd := exec.Command("kubectl", "--kubeconfig="+Kubeconfig, "cp", src, pod.Namespace+"/"+pod.Name+":"+dst)
	out, err := cmd.CombinedOutput()
	AssertNil(err, string(out))
}

func (pod *Pod) Exec(ctx context.Context, command []string) (string, error) {
	return pod.execTemplate(ctx, true, command)
}

func (pod *Pod) ExecServer(ctx context.Context, command []string) (string, error) {
	return pod.execTemplate(ctx, false, command)
}

func (pod *Pod) ExecVppctl(ctx context.Context, command string) (string, error) {
	return pod.execTemplate(ctx, true, []string{"/bin/bash", "-c", "vppctl -s /cli.sock " + command})
}

func (pod *Pod) ExecServerVppctl(ctx context.Context, command string) (string, error) {
	return pod.execTemplate(ctx, false, []string{"/bin/bash", "-c", "vppctl -s /cli.sock " + command})
}

func (pod *Pod) execTemplate(ctx context.Context, tty bool, command []string) (string, error) {
	var stdout, stderr bytes.Buffer

	// Prepare the request
	req := ClientSet.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod.Name).
		Namespace(pod.suite.Namespace).
		SubResource("exec").
		Param("container", pod.ContainerName).
		Param("stdout", "true").
		Param("stderr", "true").
		Param("tty", fmt.Sprint(tty))

	for _, cmd := range command {
		req = req.Param("command", cmd)
	}
	Log("%s: %s", pod.Name, command)

	executor, err := remotecommand.NewSPDYExecutor(KubeConfig, "POST", req.URL())
	if err != nil {
		return "", err
	}

	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
		Tty:    tty,
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
	AssertNil(err, fmt.Sprint(err))
	defer os.Remove(f.Name())

	err = template.Execute(f, values)
	AssertNil(err, err)
	err = f.Close()
	AssertNil(err, err)

	pod.CopyToPod(f.Name(), targetConfigName)
}

// CreateDynamicPod creates a simple busybox pod for testing purposes in the specified namespace
func (s *BaseSuite) CreateDynamicPod(ctx context.Context, namespace, podName, appName string) error {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
			Labels: map[string]string{
				"app": appName,
			},
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{
				{
					Name:  "busybox",
					Image: "busybox:1.35",
					Command: []string{
						"sh",
						"-c",
						fmt.Sprintf("echo 'Pod %s started at $(date)'; sleep 5; echo 'Pod %s completed at $(date)'", podName, podName),
					},
					Resources: corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse("32Mi"),
							corev1.ResourceCPU:    resource.MustParse("25m"),
						},
						Requests: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse("16Mi"),
							corev1.ResourceCPU:    resource.MustParse("10m"),
						},
					},
				},
			},
		},
	}

	_, err := ClientSet.CoreV1().Pods(namespace).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		Log("Failed to create pod %s: %v", podName, err)
		return err
	}

	Log("Created dynamic pod: %s", podName)
	return nil
}

// DeleteDynamicPod deletes a pod in the specified namespace
func (s *BaseSuite) DeleteDynamicPod(ctx context.Context, namespace, podName string) error {
	err := ClientSet.CoreV1().Pods(namespace).Delete(ctx, podName, metav1.DeleteOptions{})
	if err != nil {
		Log("Failed to delete pod %s: %v", podName, err)
		return err
	}

	Log("Deleted dynamic pod: %s", podName)
	return nil
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

func (pod *Pod) InitVpp() {
	ctx, cancel := context.WithTimeout(pod.suite.MainContext, time.Second*10)
	defer cancel()

	o, err := pod.Exec(ctx, []string{"/bin/bash", "-c", "echo " + VppCliConf + " > /vppcliconf.conf"})
	AssertNil(err, o)

	o, err = pod.Exec(ctx, []string{"/bin/bash", "-c", "echo " + VppStartupConf + " > /startup.conf"})
	AssertNil(err, o)

	_, err = pod.ExecServer(ctx, []string{"/bin/bash", "-c", "vpp -c /startup.conf"})
	AssertNil(err)

	// temporary workaround: VPP has to start without creating interfaces (without running 'exec XYZ.conf'),
	// exec interface config
	// delete interface + route
	// exec interface config again
	// otherwise, VPP ping sends 5 packets but receives 15
	time.Sleep(time.Second * 1)
	o, err = pod.ExecVppctl(ctx, "exec /vppcliconf.conf")
	AssertNil(err, o)
	o, err = pod.ExecVppctl(ctx, "delete host-interface name eth0")
	AssertNil(err, o)
	o, err = pod.ExecVppctl(ctx, "ip route del 0.0.0.0/0")
	AssertNil(err, o)
	o, err = pod.ExecVppctl(ctx, "exec /vppcliconf.conf")
	AssertNil(err, o)
}
