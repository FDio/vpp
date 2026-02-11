package kube_test

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (s *BaseSuite) loadDockerImages() {
	if !KindCluster {
		return
	}
	Log("This may take a while. If you encounter problems, " +
		"try loading docker images manually: 'kind load docker-image [image]'")

	var cmd *exec.Cmd
	var out []byte
	var err error
	for _, image := range s.images {
		Log("loading docker image %s...", image)
		cmd = exec.Command("go", "run", "sigs.k8s.io/kind@v0.29.0", "load", "docker-image", image)
		out, err = cmd.CombinedOutput()
		Log(string(out))
		AssertNil(err, string(out))
	}
}

func (s *BaseSuite) createNamespace(name string) {
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}

	// Create the namespace in the cluster
	_, err := ClientSet.CoreV1().Namespaces().Create(context.TODO(), namespace, metav1.CreateOptions{})
	AssertNil(err)
	Log("Namespace '%s' created", name)
}

func (s *BaseSuite) deletePod(namespace string, podName string) error {
	delete(s.CurrentlyRunning, podName)
	return ClientSet.CoreV1().Pods(namespace).Delete(context.TODO(), podName, metav1.DeleteOptions{GracePeriodSeconds: int64Ptr(0)})
}

func (s *BaseSuite) DeleteNamespace(namespace string) error {
	return ClientSet.CoreV1().Namespaces().Delete(context.TODO(), namespace, metav1.DeleteOptions{})
}

func (s *BaseSuite) DeployPod(pod *Pod, enableDisableVcl bool) {
	var enableDisableVclStr string
	if enableDisableVcl {
		enableDisableVclStr = "enable"
	} else {
		enableDisableVclStr = "disable"
	}
	pod.CreatedPod = &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: s.Namespace,
			Name:      pod.Name,
			Labels: map[string]string{
				"app": "Kube-Test",
			},
			Annotations: map[string]string{
				"cni.projectcalico.org/vppVcl": enableDisableVclStr,
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  pod.ContainerName,
					Image: pod.Image,
					SecurityContext: &corev1.SecurityContext{
						Privileged: boolPtr(true),
					},
					Command:         []string{"tail", "-f", "/dev/null"},
					ImagePullPolicy: corev1.PullIfNotPresent,
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
