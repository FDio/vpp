package hst_kind

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

func (s *KindSuite) Exec(pod *Pod, command []string) (string, error) {
	var stdout, stderr bytes.Buffer

	// Prepare the request
	req := s.ClientSet.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod.Name).
		Namespace(s.Namespace).
		SubResource("exec").
		Param("container", pod.ContainerName).
		Param("stdout", "true").
		Param("stderr", "true").
		Param("tty", "true")

	for _, cmd := range command {
		req = req.Param("command", cmd)
	}
	s.Log("%s: %s", pod.Name, command)

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

func boolPtr(b bool) *bool {
	return &b
}

func int64Ptr(integer int64) *int64 {
	return &integer
}
