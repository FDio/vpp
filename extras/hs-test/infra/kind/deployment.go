package hst_kind

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (s *KindSuite) loadDockerImages() {
	s.Log("This may take a while. If you encounter problems, " +
		"try loading docker images manually: 'kind load docker-image [image]'")

	var cmd *exec.Cmd
	var out []byte
	var err error
	for _, image := range s.images {
		s.Log("loading docker image %s...", image)
		cmd = exec.Command("go", "run", "sigs.k8s.io/kind@v0.29.0", "load", "docker-image", image)
		out, err = cmd.CombinedOutput()
		s.Log(string(out))
		s.AssertNil(err, string(out))
	}
}

func (s *KindSuite) createNamespace(name string) {
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}

	// Create the namespace in the cluster
	_, err := s.ClientSet.CoreV1().Namespaces().Create(context.TODO(), namespace, metav1.CreateOptions{})
	s.AssertNil(err)
	s.Log("Namespace '%s' created", name)
}

func (s *KindSuite) deletePod(namespace string, podName string) error {
	return s.ClientSet.CoreV1().Pods(namespace).Delete(context.TODO(), podName, metav1.DeleteOptions{GracePeriodSeconds: int64Ptr(0)})
}

func (s *KindSuite) deleteNamespace(namespace string) error {
	return s.ClientSet.CoreV1().Namespaces().Delete(context.TODO(), namespace, metav1.DeleteOptions{})
}

func (s *KindSuite) DeployPod(pod *Pod) {
	s.CurrentlyRunning = append(s.CurrentlyRunning, pod.Name)
	pod.CreatedPod = &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: s.Namespace,
			Name:      pod.Name,
			Labels: map[string]string{
				"app": "HST",
			},
			Annotations: map[string]string{
				"cni.projectcalico.org/vppVcl": "enable",
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
					Ports: []corev1.ContainerPort{
						{
							ContainerPort: 5201,
						},
					},
				},
			},
			NodeName: pod.Worker,
		},
	}

	// Create the Pod
	_, err := s.ClientSet.CoreV1().Pods(s.Namespace).Create(context.TODO(), pod.CreatedPod, metav1.CreateOptions{})
	s.AssertNil(err)
	s.Log("Pod '%s' created", pod.Name)

	// Get IP
	s.Log("Obtaining IP from '%s'", pod.Name)
	counter := 1
	for pod.IpAddress == "" {
		pod.CreatedPod, err = s.ClientSet.CoreV1().Pods(s.Namespace).Get(context.TODO(), pod.Name, metav1.GetOptions{})
		pod.IpAddress = pod.CreatedPod.Status.PodIP
		time.Sleep(time.Second * 1)
		counter++
		if counter >= 10 {
			Fail("Unable to get IP. Check if all pods are running. " + fmt.Sprint(err))
		}
	}

	s.Log("IP: %s", pod.IpAddress)
}
