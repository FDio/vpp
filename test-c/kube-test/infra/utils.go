package kube_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/joho/godotenv"

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

func GetTestFilename() string {
	_, filename, _, _ := runtime.Caller(2)
	return filepath.Base(filename)
}

var testCounter uint16
var startTime time.Time = time.Now()

func TestCounterFunc() {
	testCounter++
	fmt.Printf("Test counter: %d\n"+
		"Time elapsed: %.2fs\n",
		testCounter, time.Since(startTime).Seconds())
}

type IPerfResult struct {
	Start struct {
		Timestamp struct {
			Time string `json:"time"`
		} `json:"timestamp"`
		Connected []struct {
			Socket     int    `json:"socket"`
			LocalHost  string `json:"local_host"`
			LocalPort  int    `json:"local_port"`
			RemoteHost string `json:"remote_host"`
			RemotePort int    `json:"remote_port"`
		} `json:"connected"`
		Version string `json:"version"`
		Details struct {
			Protocol string `json:"protocol"`
		} `json:"test_start"`
	} `json:"start"`
	End struct {
		TcpSent *struct {
			MbitsPerSecond float64 `json:"bits_per_second"`
			MBytes         float64 `json:"bytes"`
		} `json:"sum_sent,omitempty"`
		TcpReceived *struct {
			MbitsPerSecond float64 `json:"bits_per_second"`
			MBytes         float64 `json:"bytes"`
		} `json:"sum_received,omitempty"`
		Udp *struct {
			MbitsPerSecond float64 `json:"bits_per_second"`
			JitterMs       float64 `json:"jitter_ms,omitempty"`
			LostPackets    int     `json:"lost_packets,omitempty"`
			Packets        int     `json:"packets,omitempty"`
			LostPercent    float64 `json:"lost_percent,omitempty"`
			MBytes         float64 `json:"bytes"`
		} `json:"sum,omitempty"`
	} `json:"end"`
}

func (s *BaseSuite) ParseJsonIperfOutput(jsonResult []byte) IPerfResult {
	var result IPerfResult

	// VCL/LDP debugging can pollute output so find the first occurrence of a curly brace to locate the start of JSON data
	jsonStart := -1
	jsonEnd := len(jsonResult)
	braceCount := 0
	for i := 0; i < len(jsonResult); i++ {
		if jsonResult[i] == '{' {
			if jsonStart == -1 {
				jsonStart = i
			}
			braceCount++
		} else if jsonResult[i] == '}' {
			braceCount--
			if braceCount == 0 {
				jsonEnd = i + 1
				break
			}
		}
	}
	jsonResult = jsonResult[jsonStart:jsonEnd]

	// remove iperf warning line if present
	if strings.Contains(string(jsonResult), "warning") {
		index := strings.Index(string(jsonResult), "\n")
		jsonResult = jsonResult[index+1:]
	}

	err := json.Unmarshal(jsonResult, &result)
	s.AssertNil(err)

	if result.Start.Details.Protocol == "TCP" {
		result.End.TcpSent.MbitsPerSecond = result.End.TcpSent.MbitsPerSecond / 1000000
		result.End.TcpSent.MBytes = result.End.TcpSent.MBytes / 1000000
		result.End.TcpReceived.MbitsPerSecond = result.End.TcpReceived.MbitsPerSecond / 1000000
		result.End.TcpReceived.MBytes = result.End.TcpReceived.MBytes / 1000000
	} else {
		result.End.Udp.MBytes = result.End.Udp.MBytes / 1000000
		result.End.Udp.MbitsPerSecond = result.End.Udp.MbitsPerSecond / 1000000
	}

	return result
}

func (s *BaseSuite) LogJsonIperfOutput(result IPerfResult) {
	s.Log("\n*******************************************\n"+
		"%s\n"+
		"[%s] %s:%d connected to %s:%d\n"+
		"Started:  %s\n",
		result.Start.Version,
		result.Start.Details.Protocol,
		result.Start.Connected[0].LocalHost, result.Start.Connected[0].LocalPort,
		result.Start.Connected[0].RemoteHost, result.Start.Connected[0].RemotePort,
		result.Start.Timestamp.Time)

	if result.Start.Details.Protocol == "TCP" {
		s.Log("Transfer (sent):     %.2f MBytes\n"+
			"Bitrate  (sent):     %.2f Mbits/sec\n"+
			"Transfer (received): %.2f MBytes\n"+
			"Bitrate  (received): %.2f Mbits/sec",
			result.End.TcpSent.MBytes,
			result.End.TcpSent.MbitsPerSecond,
			result.End.TcpReceived.MBytes,
			result.End.TcpReceived.MbitsPerSecond)
	} else {
		s.Log("Transfer:     %.2f MBytes\n"+
			"Bitrate:      %.2f Mbits/sec\n"+
			"Jitter:       %.3f ms\n"+
			"Packets:      %d\n"+
			"Packets lost: %d\n"+
			"Percent lost: %.2f%%",
			result.End.Udp.MBytes,
			result.End.Udp.MbitsPerSecond,
			result.End.Udp.JitterMs,
			result.End.Udp.Packets,
			result.End.Udp.LostPackets,
			result.End.Udp.LostPercent)
	}
	s.Log("*******************************************\n")
}

func (s *BaseSuite) handleExistingVarsFile(fileValues map[string]string) error {
	varsToWatch := []string{"CALICOVPP_VERSION", "CALICOVPP_INTERFACE"}
	needsWrite := false

	for _, key := range varsToWatch {
		envValue := os.Getenv(key)
		if envValue != "" {
			if fileValue, ok := fileValues[key]; !ok || fileValue != envValue {
				s.Log("Updating '%s'. New value: '%s'", key, envValue)
				fileValues[key] = envValue
				needsWrite = true
			}
		}
	}

	if needsWrite {
		if err := godotenv.Write(fileValues, EnvVarsFile); err != nil {
			return err
		}
		s.Log("File %s updated", EnvVarsFile)
	} else {
		s.Log("%s OK", EnvVarsFile)
	}
	return nil
}

func (s *BaseSuite) handleNewVarsFile() error {
	iface := os.Getenv("CALICOVPP_INTERFACE")
	version := os.Getenv("CALICOVPP_VERSION")

	if iface != "" && version != "" {
		newFileValues := map[string]string{
			"CALICOVPP_INTERFACE": iface,
			"CALICOVPP_VERSION":   version,
		}

		s.Log("\nCreating '%s' from environment variables\n", EnvVarsFile)
		if err := godotenv.Write(newFileValues, EnvVarsFile); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("Error: '%s' not found and env vars are not set. "+
			"To create it, please set both CALICOVPP_INTERFACE and CALICOVPP_VERSION env vars", EnvVarsFile)
	}
	return nil
}

// findNodePod finds a pod with the given prefix running on the specified node
func (s *BaseSuite) findNodePod(nodeName, podPrefix, namespace string) (string, error) {
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

// execInContainer executes a command in the given container within the specified pod
func (s *BaseSuite) execInContainer(namespace, podName, containerName string, command ...string) ([]byte, error) {
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

// ExecInKubeContainer executes a command in a container on a Kubernetes node
// This uses kubectl exec to access pods running on the specified Kubernetes node
// nodeName: name of the Kubernetes node (e.g., "kind-worker", "kind-worker2")
// containerName: name of the container within the pod (e.g., "vpp", "agent")
// command: the command to execute as separate arguments
func (s *BaseSuite) ExecInKubeContainer(nodeName, containerName string, command ...string) ([]byte, error) {
	// Find the Calico VPP pod on the specified node
	podName, err := s.findNodePod(nodeName, "calico-vpp-node", "calico-vpp-dataplane")
	if err != nil {
		s.Log("Failed to find Calico VPP pod on %s: %v", nodeName, err)
		return nil, err
	}

	// Execute the command in the pod
	output, err := s.execInContainer("calico-vpp-dataplane", podName, containerName, command...)
	if err != nil {
		s.Log("Command failed on %s in container %s: %v", nodeName, containerName, err)
		return output, err
	}

	return output, nil
}

// ExecVppctlInKubeNode executes a vppctl command in the VPP container on a Kubernetes node
func (s *BaseSuite) ExecVppctlInKubeNode(nodeName string, vppctlArgs ...string) ([]byte, error) {
	command := []string{"/usr/bin/vppctl", "-s", "/var/run/vpp/cli.sock"}
	command = append(command, vppctlArgs...)

	return s.ExecInKubeContainer(nodeName, "vpp", command...)
}
