package hst

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (s *KindSuite) CreateNamespace(name string) {
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: s.Namespace,
		},
	}

	// Create the namespace in the cluster
	_, err := s.ClientSet.CoreV1().Namespaces().Create(context.TODO(), namespace, metav1.CreateOptions{})
	s.AssertNil(err)
	s.Log("Namespace '%s' created", s.Namespace)
}

func (s *KindSuite) DeployServerClient(imageNameServer string, imageNameClient string, serverPod string, clientPod string) {
	var err error
	var counter uint8
	var serverDetails *corev1.Pod
	s.CurrentlyRunning = append(s.CurrentlyRunning, serverPod, clientPod)

	server := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: s.Namespace,
			Name:      serverPod,
			Labels: map[string]string{
				"app": serverPod,
			},
			Annotations: map[string]string{
				"cni.projectcalico.org/vppVcl": "enable",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "server",
					Image: imageNameServer,
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
	s.Log("Pod '%s' created", serverPod)

	// Get IP
	s.Log("Obtaining IP from '%s'", server.Name)
	for s.ServerIp == "" {
		serverDetails, err = s.ClientSet.CoreV1().Pods(s.Namespace).Get(context.TODO(), serverPod, metav1.GetOptions{})
		s.ServerIp = serverDetails.Status.PodIP
		time.Sleep(time.Second * 1)
		counter++
		if counter >= 10 {
			Fail("Unable to get IP. Check if all pods are running. " + fmt.Sprint(err))
		}
	}

	s.Log("IP: %s", s.ServerIp)

	client := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: s.Namespace,
			Name:      clientPod,
			Annotations: map[string]string{
				"cni.projectcalico.org/vppVcl": "enable",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:            "client",
					Image:           imageNameClient,
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

	_, err = s.ClientSet.CoreV1().Pods(s.Namespace).Create(context.TODO(), client, metav1.CreateOptions{})
	s.AssertNil(err)
	s.Log("Pod '%s' created", clientPod)

	// let pods start properly
	time.Sleep(time.Second * 5)
}
