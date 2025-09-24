package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	. "fd.io/kube-test/infra"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterKubeTests(KubeTcpIperfVclTest, KubeUdpIperfVclTest, NginxRpsTest, NginxProxyMirroringTest)
	RegisterKubeMWTests(KubeTcpIperfVclMWTest, KubeUdpIperfVclMWTest)
	RegisterLargeMtuTests(KubeTcpIperfVclLargeMTUTest)
}

const vcl string = "VCL_CONFIG=/vcl.conf"
const ldp string = "LD_PRELOAD=/usr/lib/libvcl_ldpreload.so"

func kubeIperfVclTest(s *KubeSuite, clientArgs string) IPerfResult {
	s.DeployPod(s.Pods.ClientGeneric)
	s.DeployPod(s.Pods.ServerGeneric)
	ctx, cancel := context.WithTimeout(s.MainContext, time.Minute*2)
	defer cancel()
	defer func() {
		o, err := s.Pods.ServerGeneric.Exec(ctx, []string{"/bin/bash", "-c", "cat /iperf_server.log"})
		s.Log(o)
		s.AssertNil(err)
	}()

	_, err := s.Pods.ClientGeneric.Exec(ctx, []string{"/bin/bash", "-c", VclConfIperf})
	s.AssertNil(err)
	_, err = s.Pods.ServerGeneric.Exec(ctx, []string{"/bin/bash", "-c", VclConfIperf})
	s.AssertNil(err)

	s.FixVersionNumber(s.Pods.ClientGeneric, s.Pods.ServerGeneric)

	iperfClientCmd := fmt.Sprintf("%s %s iperf3 %s -J -4 -b 40g -c %s",
		vcl, ldp, clientArgs, s.Pods.ServerGeneric.IpAddress)

	o, err := s.Pods.ServerGeneric.Exec(ctx, []string{"/bin/bash", "-c",
		vcl + " " + ldp + " iperf3 -s -D --logfile /iperf_server.log -B " + s.Pods.ServerGeneric.IpAddress})
	s.Log("Sleeping for 2s")
	time.Sleep(time.Second * 2)
	s.AssertNil(err)
	out, err := s.Pods.ServerGeneric.Exec(ctx, []string{"/bin/bash", "-c", "pidof iperf3"})
	s.Log(out)
	s.AssertNil(err)
	s.AssertNil(err, o)

	o, err = s.Pods.ClientGeneric.Exec(ctx, []string{"/bin/bash", "-c", iperfClientCmd})
	s.AssertNil(err, o)
	result := s.ParseJsonIperfOutput([]byte(o))
	s.LogJsonIperfOutput(result)
	return result
}

// TODO: use interfaces to avoid duplicated code
func kubeIperfVclMtuTest(s *LargeMtuSuite, clientArgs string) IPerfResult {
	s.DeployPod(s.Pods.ClientGeneric)
	s.DeployPod(s.Pods.ServerGeneric)
	ctx, cancel := context.WithTimeout(s.MainContext, time.Minute*2)
	defer cancel()
	defer func() {
		o, err := s.Pods.ServerGeneric.Exec(ctx, []string{"/bin/bash", "-c", "cat /iperf_server.log"})
		s.Log(o)
		s.AssertNil(err)
	}()

	_, err := s.Pods.ClientGeneric.Exec(ctx, []string{"/bin/bash", "-c", VclConfIperf})
	s.AssertNil(err)
	_, err = s.Pods.ServerGeneric.Exec(ctx, []string{"/bin/bash", "-c", VclConfIperf})
	s.AssertNil(err)

	s.FixVersionNumber(s.Pods.ClientGeneric, s.Pods.ServerGeneric)

	iperfClientCmd := fmt.Sprintf("%s %s iperf3 %s -J -4 -b 40g -c %s",
		vcl, ldp, clientArgs, s.Pods.ServerGeneric.IpAddress)

	o, err := s.Pods.ServerGeneric.Exec(ctx, []string{"/bin/bash", "-c",
		vcl + " " + ldp + " iperf3 -s -D --logfile /iperf_server.log -B " + s.Pods.ServerGeneric.IpAddress})
	s.Log("Sleeping for 2s")
	time.Sleep(time.Second * 2)
	s.AssertNil(err)
	out, err := s.Pods.ServerGeneric.Exec(ctx, []string{"/bin/bash", "-c", "pidof iperf3"})
	s.Log(out)
	s.AssertNil(err)
	s.AssertNil(err, o)

	o, err = s.Pods.ClientGeneric.Exec(ctx, []string{"/bin/bash", "-c", iperfClientCmd})
	s.AssertNil(err, o)
	result := s.ParseJsonIperfOutput([]byte(o))
	s.LogJsonIperfOutput(result)
	return result
}

func KubeTcpIperfVclTest(s *KubeSuite) {
	s.AssertIperfMinTransfer(kubeIperfVclTest(s, "-M 1460"), 2000)
}

func KubeTcpIperfVclLargeMTUTest(s *LargeMtuSuite) {
	s.AssertIperfMinTransfer(kubeIperfVclMtuTest(s, "-M 8900"), 2000)
}

func KubeUdpIperfVclTest(s *KubeSuite) {
	s.AssertIperfMinTransfer(kubeIperfVclTest(s, "-l 1460 -u"), 2000)
}

func KubeTcpIperfVclMWTest(s *KubeSuite) {
	s.AssertIperfMinTransfer(kubeIperfVclTest(s, "-M 1460"), 200)
}

func KubeUdpIperfVclMWTest(s *KubeSuite) {
	s.AssertIperfMinTransfer(kubeIperfVclTest(s, "-l 1460 -u"), 200)
}

func NginxRpsTest(s *KubeSuite) {
	ctx, cancel := context.WithTimeout(s.MainContext, time.Minute*3)
	defer cancel()

	s.DeployPod(s.Pods.Nginx)
	s.DeployPod(s.Pods.Ab)
	s.CreateNginxConfig(s.Pods.Nginx)

	out, err := s.Pods.Nginx.Exec(ctx, []string{"/bin/bash", "-c", VclConfNginx})
	s.AssertNil(err, out)

	go func() {
		defer GinkgoRecover()
		out, err := s.Pods.Nginx.Exec(ctx, []string{"/bin/bash", "-c", "nginx -c /nginx.conf"})
		if !errors.Is(err, context.Canceled) {
			s.AssertNil(err, out)
		}
	}()

	// wait for nginx to start up
	time.Sleep(time.Second * 2)
	out, err = s.Pods.Ab.Exec(ctx, []string{"ab", "-k", "-r", "-n", "1000000", "-c", "1000", "http://" + s.Pods.Nginx.IpAddress + ":8081/64B.json"})
	s.Log(out)
	s.AssertNil(err)
}

func NginxProxyMirroringTest(s *KubeSuite) {
	ctx, cancel := context.WithTimeout(s.MainContext, time.Minute*3)
	defer cancel()

	s.DeployPod(s.Pods.Nginx)
	s.DeployPod(s.Pods.NginxProxy)
	s.DeployPod(s.Pods.ClientGeneric)
	s.CreateNginxConfig(s.Pods.Nginx)
	s.CreateNginxProxyConfig(s.Pods.NginxProxy)

	out, err := s.Pods.Nginx.Exec(ctx, []string{"/bin/bash", "-c", VclConfNginx})
	s.AssertNil(err, out)
	out, err = s.Pods.NginxProxy.Exec(ctx, []string{"/bin/bash", "-c", VclConfNginx})
	s.AssertNil(err, out)

	go func() {
		defer GinkgoRecover()
		out, err := s.Pods.Nginx.Exec(ctx, []string{"/bin/bash", "-c", ldp + " " + vcl + " nginx -c /nginx.conf"})
		if !errors.Is(err, context.Canceled) {
			s.AssertNil(err, out)
		}
	}()

	go func() {
		defer GinkgoRecover()
		out, err := s.Pods.NginxProxy.Exec(ctx, []string{"/bin/bash", "-c", "nginx -c /nginx.conf"})
		if !errors.Is(err, context.Canceled) {
			s.AssertNil(err, out)
		}
	}()

	// wait for nginx to start up
	time.Sleep(time.Second * 2)
	out, err = s.Pods.ClientGeneric.Exec(ctx, []string{"curl", "-v", "--noproxy", "'*'", "--insecure", "http://" + s.Pods.NginxProxy.IpAddress + ":8080/64B.json"})
	s.Log(out)
	s.AssertNil(err)
}
