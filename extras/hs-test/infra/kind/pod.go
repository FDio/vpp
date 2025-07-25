package hst_kind

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"text/template"
	"time"

	. "fd.io/hs-test/infra/common"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/remotecommand"
)

type Pod struct {
	suite         *KindSuite
	Name          string
	Image         string
	ContainerName string
	Worker        string
	IpAddress     string
	CreatedPod    *corev1.Pod
}

// Sets pod names, image names, namespace name
func (s *KindSuite) initPods() {
	wrk1 := "kind-worker"
	wrk2 := "kind-worker2"
	vppImg := "hs-test/vpp:latest"
	nginxLdpImg := "hs-test/nginx-ldp:latest"
	abImg := "hs-test/ab:latest"
	clientCont := "client"
	serverCont := "server"

	// TODO: load from file
	s.images = append(s.images, vppImg, nginxLdpImg, abImg)
	s.Namespace = "namespace" + s.Ppid

	s.Pods.ClientGeneric = new(Pod)
	s.Pods.ClientGeneric.Name = "client" + s.Ppid
	s.Pods.ClientGeneric.Image = vppImg
	s.Pods.ClientGeneric.ContainerName = clientCont
	s.Pods.ClientGeneric.Worker = wrk1

	s.Pods.ServerGeneric = new(Pod)
	s.Pods.ServerGeneric.Name = "server" + s.Ppid
	s.Pods.ServerGeneric.Image = vppImg
	s.Pods.ServerGeneric.ContainerName = serverCont
	s.Pods.ServerGeneric.Worker = wrk2

	s.Pods.Ab = new(Pod)
	s.Pods.Ab.Name = "ab" + s.Ppid
	s.Pods.Ab.Image = abImg
	s.Pods.Ab.ContainerName = clientCont
	s.Pods.Ab.Worker = wrk1

	s.Pods.Nginx = new(Pod)
	s.Pods.Nginx.Name = "nginx-ldp" + s.Ppid
	s.Pods.Nginx.Image = nginxLdpImg
	s.Pods.Nginx.ContainerName = serverCont
	s.Pods.Nginx.Worker = wrk2

	s.Pods.NginxProxy = new(Pod)
	s.Pods.NginxProxy.Name = "nginx-proxy" + s.Ppid
	s.Pods.NginxProxy.Image = nginxLdpImg
	s.Pods.NginxProxy.ContainerName = serverCont
	s.Pods.NginxProxy.Worker = wrk2
}

func (pod *Pod) CopyToPod(namespace string, src string, dst string) {
	cmd := exec.Command("kubectl", "--kubeconfig="+pod.suite.KubeconfigPath, "cp", src, namespace+"/"+pod.Name+":"+dst)
	out, err := cmd.CombinedOutput()
	pod.suite.AssertNil(err, string(out))
}

func (pod *Pod) Exec(command []string) (string, error) {
	var stdout, stderr bytes.Buffer

	// Prepare the request
	req := pod.suite.ClientSet.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod.Name).
		Namespace(pod.suite.Namespace).
		SubResource("exec").
		Param("container", pod.ContainerName).
		Param("stdout", "true").
		Param("stderr", "true").
		Param("tty", "true")

	for _, cmd := range command {
		req = req.Param("command", cmd)
	}
	pod.suite.Log("%s: %s\n", pod.Name, command)

	executor, err := remotecommand.NewSPDYExecutor(pod.suite.Config, "POST", req.URL())
	if err != nil {
		pod.suite.Log("Error creating executor: %s", err.Error())
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

func (pod *Pod) CreateConfigFromTemplate(targetConfigName string, templateName string, values any) {
	template := template.Must(template.ParseFiles(templateName))

	f, err := os.CreateTemp(LogDir, "hst-config")
	pod.suite.AssertNil(err, err)
	defer os.Remove(f.Name())

	err = template.Execute(f, values)
	pod.suite.AssertNil(err, err)

	err = f.Close()
	pod.suite.AssertNil(err, err)

	pod.CopyToPod(pod.suite.Namespace, f.Name(), targetConfigName)
}
