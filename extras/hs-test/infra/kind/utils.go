package hst_kind

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func boolPtr(b bool) *bool {
	return &b
}

func int64Ptr(integer int64) *int64 {
	return &integer
}

func int32Ptr(i int32) *int32 {
	return &i
}

// findNodePod finds a pod with the given prefix running on the specified node
func (s *KindSuite) findNodePod(nodeName, podPrefix, namespace string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	s.Log("Searching for pods with prefix '%s' in namespace '%s' on node '%s'", podPrefix, namespace, nodeName)

	pods, err := s.ClientSet.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", nodeName),
	})
	if err != nil {
		s.Log("Failed to list pods in namespace %s: %v", namespace, err)
		return "", err
	}

	for _, pod := range pods.Items {
		if strings.HasPrefix(pod.Name, podPrefix) {
			s.Log("Found pod %s on node %s", pod.Name, nodeName)
			return pod.Name, nil
		}
	}

	return "", fmt.Errorf("pod with prefix '%s' not found on node '%s' in namespace '%s'", podPrefix, nodeName, namespace)
}

// execInPod executes a command in a specific container within a pod
func (s *KindSuite) execInPod(namespace, podName, containerName string, command ...string) ([]byte, error) {
	kubectlArgs := append([]string{
		"exec",
		"-n", namespace,
		"-c", containerName,
		podName,
		"--",
	}, command...)

	cmd := exec.Command("kubectl", kubectlArgs...)
	s.Log(cmd.String())
	return cmd.CombinedOutput()
}

// ExecInKindNodeContainer executes a command inside a container within a KinD node
// This uses kubectl exec to access pods running on the specified KinD node
// kindNodeName: name of the KinD node (e.g., "kind-worker", "kind-worker2")
// containerName: name of the container within the pod (e.g., "vpp", "agent")
// command: the command to execute as separate arguments
func (s *KindSuite) ExecInKindNodeContainer(kindNodeName, containerName string, command ...string) ([]byte, error) {
	// Find the Calico VPP pod on the specified node
	podName, err := s.findNodePod(kindNodeName, "calico-vpp-node", "calico-vpp-dataplane")
	if err != nil {
		s.Log("Failed to find Calico VPP pod on %s: %v", kindNodeName, err)
		return nil, err
	}

	// Execute the command in the pod
	output, err := s.execInPod("calico-vpp-dataplane", podName, containerName, command...)
	if err != nil {
		s.Log("Command failed on %s in container %s: %v", kindNodeName, containerName, err)
		return output, err
	}

	return output, nil
}

// ExecVppctlInKindNode executes a vppctl command in the Calico VPP container on a KinD node
func (s *KindSuite) ExecVppctlInKindNode(kindNodeName string, vppctlArgs ...string) ([]byte, error) {
	// Use the full path to vppctl and add the socket path as per the sample code
	vppctlPath := "/usr/bin/vppctl"
	vppSockPath := "/var/run/vpp/cli.sock"

	command := []string{vppctlPath, "-s", vppSockPath}
	command = append(command, vppctlArgs...)

	return s.ExecInKindNodeContainer(kindNodeName, "vpp", command...)
}
