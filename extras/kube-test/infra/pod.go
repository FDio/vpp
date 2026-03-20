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

	. "github.com/onsi/ginkgo/v2"
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
	Vpp           *VppInstance
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

type PodAnnotations struct {
	EnableVcl       *bool
	ExtraMemifPorts string
	ExtraMemifSpec  string
}

func buildAnnotations(pa *PodAnnotations) map[string]string {
	annotations := make(map[string]string)

	if pa == nil {
		return annotations
	}

	if pa.EnableVcl != nil {
		if *pa.EnableVcl {
			annotations["cni.projectcalico.org/vppVcl"] = "enable"
		} else {
			annotations["cni.projectcalico.org/vppVcl"] = "disable"
		}
	}

	if pa.ExtraMemifPorts != "" {
		annotations["cni.projectcalico.org/vppExtraMemifPorts"] = pa.ExtraMemifPorts
	}

	if pa.ExtraMemifSpec != "" {
		annotations["cni.projectcalico.org/vppExtraMemifSpec"] = pa.ExtraMemifSpec
	}

	return annotations
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

func (pod *Pod) CopyToPod(src string, dst string) {
	cmd := exec.Command("kubectl", "--kubeconfig="+Kubeconfig, "cp", src, pod.Namespace+"/"+pod.Name+":"+dst)
	out, err := cmd.CombinedOutput()
	AssertNil(err, string(out))
}

func (pod *Pod) Exec(ctx context.Context, command []string) (string, error) {
	return execTemplate(ctx, pod, true, command)
}

func (pod *Pod) ExecServer(ctx context.Context, command []string) (string, error) {
	return execTemplate(ctx, pod, false, command)
}

func execTemplate(ctx context.Context, pod *Pod, tty bool, command []string) (string, error) {
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

func (s *BaseSuite) DeployPod(pod *Pod, annotations *PodAnnotations) {
	pod.CreatedPod = &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: s.Namespace,
			Name:      pod.Name,
			Labels: map[string]string{
				"app": "Kube-Test",
			},
			Annotations: buildAnnotations(annotations),
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  pod.ContainerName,
					Image: pod.Image,
					SecurityContext: &corev1.SecurityContext{
						Privileged: BoolPtr(true),
					},
					Command:         []string{"tail", "-f", "/dev/null"},
					ImagePullPolicy: corev1.PullIfNotPresent,
					Ports: []corev1.ContainerPort{
						{
							ContainerPort: 6081,
							Protocol:      corev1.ProtocolUDP,
						},
					},
				},
			},
			NodeName: pod.Worker,
		},
	}

	// Create the Pod
	_, err := ClientSet.CoreV1().Pods(s.Namespace).Create(context.TODO(), pod.CreatedPod, metav1.CreateOptions{})
	AssertNil(err)
	s.CurrentlyRunning[pod.Name] = pod
	Log("Pod '%s' created", pod.Name)

	// Get IP
	Log("Obtaining IP from '%s'", pod.Name)
	pod.IpAddress = ""
	counter := 1
	for pod.IpAddress == "" {
		pod.CreatedPod, err = ClientSet.CoreV1().Pods(s.Namespace).Get(context.TODO(), pod.Name, metav1.GetOptions{})
		pod.IpAddress = pod.CreatedPod.Status.PodIP
		time.Sleep(time.Second * 1)
		counter++
		if counter >= 40 {
			Fail("Unable to get IP. Check if all pods are running. " + fmt.Sprint(err))
		}
	}

	Log("IP: %s\n", pod.IpAddress)
}

func (pod *Pod) deletePod() error {
	delete(pod.suite.CurrentlyRunning, pod.Name)
	return ClientSet.CoreV1().Pods(pod.Namespace).Delete(context.TODO(), pod.Name, metav1.DeleteOptions{GracePeriodSeconds: int64Ptr(0)})
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
