package hst

import (
	"bytes"
	"context"
	"fmt"
	"time"
	"reflect"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
)

type KindSuite struct {
	HstSuite
	ClientSet             *kubernetes.Clientset
	Config                *rest.Config
	IperfControlPlaneName string
	IperfClientName       string
	IperfServerName       string
	IperfServerIp         string
	Namespace             string
}

var kindTests = map[string][]func(s *KindSuite){}

func RegisterKindTests(tests ...func(s *KindSuite)) {
	kindTests[getTestFilename()] = tests
}

func boolPtr(b bool) *bool {
	return &b
}

func deletePod(clientset *kubernetes.Clientset, namespace, podName string) error {
	return clientset.CoreV1().Pods(namespace).Delete(context.TODO(), podName, metav1.DeleteOptions{})
}

func deleteNamespace(clientset *kubernetes.Clientset, namespace string) error {
	return clientset.CoreV1().Namespaces().Delete(context.TODO(), namespace, metav1.DeleteOptions{})
}

func (s *KindSuite) SetupSuite(){
	s.SkipIfNotPerf()
	s.SetupKindSuite()

	var err error
	var kubeconfig string
	if *SudoUser == "root" {
		kubeconfig = "/.kube/config"
	} else {
		kubeconfig = "/home/" + *SudoUser + "/.kube/config"
	}
	s.Log(kubeconfig)
	s.Config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	s.AssertNil(err)

	s.ClientSet, err = kubernetes.NewForConfig(s.Config)
	s.AssertNil(err)

	s.Deploy()
}

// Deletes pods in a namespace. Lastly, deletes the namespace itself.
func (s *KindSuite) Teardown(podNames ...string) {
	s.SkipIfNotPerf()
	if *IsPersistent {
		return
	}
	s.Log("Teardown:")
	if len(podNames) != 0 {
		for _, pod := range podNames {
			s.Log("   %s", pod)
			deletePod(s.ClientSet, s.Namespace, pod)
		}
	}

    s.Log("   %s", s.Namespace)
	s.AssertNil(deleteNamespace(s.ClientSet, s.Namespace))
}

func (s *KindSuite) Exec(podName string, containerName string, namespace string, command []string) error {
	var stdout, stderr bytes.Buffer

	// Prepare the request
	req := s.ClientSet.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		Param("container", containerName).
		Param("stdout", "true").
		Param("stderr", "true").
		Param("tty", "true")

	for _, cmd := range command {
		req = req.Param("command", cmd)
	}
	s.Log("%s: %s", podName, command)

	executor, err := remotecommand.NewSPDYExecutor(s.Config, "POST", req.URL())
	if err != nil {
		s.Log("Error creating executor: %s", err.Error())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
		Tty:    true,
	})

	s.Log(stdout.String())
	if stderr.String() != "" {
		s.Log("stderr: %s", stderr.String())
	}

	if err != nil {
		return err
	}

	return nil
}

func (s *KindSuite) Deploy() {
	var err error
	var counter uint8
	var serverDetails *corev1.Pod
	s.IperfServerName = "server"
	s.IperfClientName = "client"
	s.Namespace = "custom-namespace"

	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: s.Namespace,
		},
	}

	// Create the namespace in the cluster
	_, err = s.ClientSet.CoreV1().Namespaces().Create(context.TODO(), namespace, metav1.CreateOptions{})
	s.AssertNil(err)
	s.Log("Namespace created")

	server := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: s.Namespace,
			Name:      s.IperfServerName,
			Labels: map[string]string{
				"app": s.IperfServerName,
			},
			Annotations: map[string]string{
				"cni.projectcalico.org/vppVcl": "enable",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  s.IperfServerName,
					Image: "hs-test/vpp:latest",
					SecurityContext: &corev1.SecurityContext{
						Privileged: boolPtr(true),
					},
					Command:         []string{"tail", "-f", "/dev/null"},
					ImagePullPolicy: corev1.PullIfNotPresent,
					Ports: []corev1.ContainerPort{
						{
							ContainerPort: 5201,
						},
					},
				},
			},
			NodeName: "kind-worker",
		},
	}

	// Create the Pod
	_, err = s.ClientSet.CoreV1().Pods(s.Namespace).Create(context.TODO(), server, metav1.CreateOptions{})
	s.AssertNil(err)
	s.Log("Pod created")

	// Get IP
	s.Log("Obtaining server IP")
	for s.IperfServerIp == "" {
		serverDetails, err = s.ClientSet.CoreV1().Pods(s.Namespace).Get(context.TODO(), s.IperfServerName, metav1.GetOptions{})
		s.IperfServerIp = serverDetails.Status.PodIP
		time.Sleep(time.Second * 1)
		counter++
		if counter >= 10 {
			Fail("Unable to get IP. Check if all pods are running. " + fmt.Sprint(err))
		}
	}

	s.Log("Server IP: %s", s.IperfServerIp)

	iperfClient := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: s.Namespace,
			Name:      s.IperfClientName,
			Annotations: map[string]string{
				"cni.projectcalico.org/vppVcl": "enable",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:            s.IperfClientName,
					Image:           "hs-test/vpp:latest",
					ImagePullPolicy: corev1.PullIfNotPresent,
					Command:         []string{"tail", "-f", "/dev/null"},
					Ports: []corev1.ContainerPort{
						{
							ContainerPort: 5201,
						},
					},
					SecurityContext: &corev1.SecurityContext{
						Privileged: boolPtr(true),
					},
				},
			},
			NodeName: "kind-worker2",
		},
	}

	_, err = s.ClientSet.CoreV1().Pods(s.Namespace).Create(context.TODO(), iperfClient, metav1.CreateOptions{})
	s.AssertNil(err)
	s.Log("Pod created")

	// let pods start properly
	time.Sleep(time.Second * 5)
}

var _ = Describe("KindSuite", Ordered, ContinueOnFailure, func() {
	var s KindSuite
	BeforeAll(func() {
		s.SetupSuite()
	})

    AfterAll(func() {
		s.Teardown(s.IperfClientName, s.IperfServerName)
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
