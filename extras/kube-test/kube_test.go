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

type iperfVclInterface interface {
	DeployPod(*Pod)
	FixVersionNumber(...*Pod)
}

func kubeIperfVclTest(ctx context.Context, clnPod *Pod, srvPod *Pod, s iperfVclInterface, clientArgs string) IPerfResult {
	s.DeployPod(clnPod)
	s.DeployPod(srvPod)
	ctx, cancel := context.WithTimeout(ctx, time.Minute*2)
	defer cancel()
	defer func() {
		o, err := srvPod.Exec(ctx, []string{"/bin/bash", "-c", "cat /iperf_server.log"})
		Log(o)
		AssertNil(err)
	}()

	_, err := clnPod.Exec(ctx, []string{"/bin/bash", "-c", VclConfIperf})
	AssertNil(err)
	_, err = srvPod.Exec(ctx, []string{"/bin/bash", "-c", VclConfIperf})
	AssertNil(err)

	s.FixVersionNumber(clnPod, srvPod)

	iperfClientCmd := fmt.Sprintf("%s %s iperf3 %s -J -4 -b 40g -c %s",
		vcl, ldp, clientArgs, srvPod.IpAddress)

	o, err := srvPod.Exec(ctx, []string{"/bin/bash", "-c",
		vcl + " " + ldp + " iperf3 -s -D --logfile /iperf_server.log -B " + srvPod.IpAddress})
	Log("Sleeping for 2s")
	time.Sleep(time.Second * 2)
	AssertNil(err)
	out, err := srvPod.Exec(ctx, []string{"/bin/bash", "-c", "pidof iperf3"})
	Log(out)
	AssertNil(err)
	AssertNil(err, o)

	o, err = clnPod.Exec(ctx, []string{"/bin/bash", "-c", iperfClientCmd})
	AssertNil(err, o)
	result := ParseJsonIperfOutput([]byte(o))
	LogJsonIperfOutput(result)
	return result
}

func KubeTcpIperfVclTest(s *KubeSuite) {
	AssertIperfMinTransfer(kubeIperfVclTest(s.MainContext, s.Pods.ClientGeneric, s.Pods.ServerGeneric, s, "-M 1460"), 2000)
}

func KubeTcpIperfVclLargeMTUTest(s *LargeMtuSuite) {
	AssertIperfMinTransfer(kubeIperfVclTest(s.MainContext, s.Pods.ClientGeneric, s.Pods.ServerGeneric, s, "-M 8900"), 2000)
}

func KubeUdpIperfVclTest(s *KubeSuite) {
	AssertIperfMinTransfer(kubeIperfVclTest(s.MainContext, s.Pods.ClientGeneric, s.Pods.ServerGeneric, s, "-l 1460 -u"), 2000)
}

func KubeTcpIperfVclMWTest(s *KubeSuite) {
	AssertIperfMinTransfer(kubeIperfVclTest(s.MainContext, s.Pods.ClientGeneric, s.Pods.ServerGeneric, s, "-M 1460"), 200)
}

func KubeUdpIperfVclMWTest(s *KubeSuite) {
	AssertIperfMinTransfer(kubeIperfVclTest(s.MainContext, s.Pods.ClientGeneric, s.Pods.ServerGeneric, s, "-l 1460 -u"), 200)
}

func NginxRpsTest(s *KubeSuite) {
	ctx, cancel := context.WithTimeout(s.MainContext, time.Minute*3)
	defer cancel()

	s.DeployPod(s.Pods.Nginx)
	s.DeployPod(s.Pods.Ab)
	s.CreateNginxConfig(s.Pods.Nginx)

	go func() {
		defer GinkgoRecover()
		out, err := s.Pods.Nginx.Exec(ctx, []string{"/bin/bash", "-c", "nginx -c /nginx.conf"})
		if !errors.Is(err, context.Canceled) {
			AssertNil(err, out)
		}
	}()

	// wait for nginx to start up
	time.Sleep(time.Second * 2)
	filename := GetTestName() + GetDateTime() + ".csv"
	out, err := s.Pods.Ab.Exec(ctx, []string{"ab", "-k", "-e", filename, "-r", "-n", "1000000", "-c", "1000", "http://" + s.Pods.Nginx.IpAddress + ":8081/64B.json"})
	Log(out)
	fileOut, err2 := s.Pods.Ab.Exec(ctx, []string{"cat", filename})
	AssertNil(err)
	AssertNil(err2)
	WriteToFile(PerfLogsDir+filename, []byte(fileOut))
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
	AssertNil(err, out)
	out, err = s.Pods.NginxProxy.Exec(ctx, []string{"/bin/bash", "-c", VclConfNginx})
	AssertNil(err, out)

	go func() {
		defer GinkgoRecover()
		out, err := s.Pods.Nginx.Exec(ctx, []string{"/bin/bash", "-c", ldp + " " + vcl + " nginx -c /nginx.conf"})
		if !errors.Is(err, context.Canceled) {
			AssertNil(err, out)
		}
	}()

	go func() {
		defer GinkgoRecover()
		out, err := s.Pods.NginxProxy.Exec(ctx, []string{"/bin/bash", "-c", "nginx -c /nginx.conf"})
		if !errors.Is(err, context.Canceled) {
			AssertNil(err, out)
		}
	}()

	// wait for nginx to start up
	time.Sleep(time.Second * 2)
	out, err = s.Pods.ClientGeneric.Exec(ctx, []string{"curl", "-v", "--noproxy", "'*'", "--insecure", "http://" + s.Pods.NginxProxy.IpAddress + ":8080/64B.json"})
	Log(out)
	AssertNil(err)
}
