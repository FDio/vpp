package hst_kind

import corev1 "k8s.io/api/core/v1"

type Pod struct {
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
}
