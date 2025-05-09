package hst

import (
	"bytes"
	"context"
	"os/exec"
	"time"

	"k8s.io/client-go/tools/remotecommand"
)

func (s *KindSuite) CopyToPod(podName string, namespace string, src string, dst string) {
	cmd := exec.Command("kubectl", "--kubeconfig="+s.KubeconfigPath, "cp", src, namespace+"/"+podName+":"+dst)
	out, err := cmd.CombinedOutput()
	s.AssertNil(err, string(out))
}

func (s *KindSuite) Exec(podName string, containerName string, command []string) (string, error) {
	var stdout, stderr bytes.Buffer

	// Prepare the request
	req := s.ClientSet.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(s.Namespace).
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

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Second)
	defer cancel()

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

// Alternative exec function. Use if regular Exec() doesn't work.
func (s *KindSuite) ExecAlt(podName string, containerName string, namespace string, command []string) (string, error) {
	baseCmd := []string{
		"kubectl",
		"--kubeconfig=" + s.KubeconfigPath,
		"-n", namespace,
		"exec",
		podName,
		"--",
	}
	fullCmd := append(baseCmd, command...)
	cmd := exec.Command(fullCmd[0], fullCmd[1:]...)
	s.Log(cmd)
	out, err := cmd.CombinedOutput()

	return string(out), err
}

func boolPtr(b bool) *bool {
	return &b
}

func int64Ptr(integer int64) *int64 {
	return &integer
}
