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
	RegisterKubeTests(KubeTcpIperfVclTest, KubeUdpIperfVclTest, NginxRpsTest, NginxProxyMirroringTest, VppPingTest, EchoBuiltinEchobytesTest, NginxRpsVclTest,
		HttpClientStaticServerTest)
	RegisterKubeMWTests(KubeTcpIperfVclMWTest, KubeUdpIperfVclMWTest)
	RegisterLargeMtuTests(KubeTcpIperfVclLargeMTUTest)
}

const vcl string = "VCL_CONFIG=/vcl.conf"
const ldp string = "LD_PRELOAD=/usr/lib/libvcl_ldpreload.so"

type iperfVclInterface interface {
	DeployPod(*Pod, bool)
	FixVersionNumber(...*Pod)
}

func kubeIperfVclTest(ctx context.Context, clnPod *Pod, srvPod *Pod, s iperfVclInterface, clientArgs string) IPerfResult {
	s.DeployPod(clnPod, true)
	s.DeployPod(srvPod, true)
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
	nginxRps(s, false)
}

func NginxRpsVclTest(s *KubeSuite) {
	nginxRps(s, true)
}

func nginxRps(s *KubeSuite, isVcl bool) {
	var vclLdpPath string
	ctx, cancel := context.WithTimeout(s.MainContext, time.Minute*3)
	defer cancel()

	s.DeployPod(s.Pods.Nginx, isVcl)
	s.DeployPod(s.Pods.Ab, isVcl)
	s.CreateNginxConfig(s.Pods.Nginx)

	if isVcl {
		out, err := s.Pods.Nginx.Exec(ctx, []string{"/bin/bash", "-c", VclConfNginx})
		AssertNil(err, out)
		_, err = s.Pods.Ab.Exec(ctx, []string{"/bin/bash", "-c", VclConfIperf})
		AssertNil(err)
		vclLdpPath = fmt.Sprintf("%s %s ", ldp, vcl)
	}

	go func() {
		defer GinkgoRecover()
		out, err := s.Pods.Nginx.Exec(ctx, []string{"/bin/bash", "-c", vclLdpPath + "nginx -c /nginx.conf"})
		if !errors.Is(err, context.Canceled) {
			AssertNil(err, out)
		}
	}()

	// wait for nginx to start up
	time.Sleep(time.Second * 2)
	filename := GetTestName() + GetDateTime() + ".csv"
	out, err := s.Pods.Ab.Exec(ctx, []string{"/bin/bash", "-c", vclLdpPath + "ab -k -e " + filename + " -r -n 1000000 -c 1000 http://" + s.Pods.Nginx.IpAddress + ":8081/64B.json"})
	Log(out)
	fileOut, err2 := s.Pods.Ab.Exec(ctx, []string{"cat", filename})
	AssertNil(err)
	AssertNil(err2)
	WriteToFile(PerfLogsDir+filename, []byte(fileOut))
}

func NginxProxyMirroringTest(s *KubeSuite) {
	ctx, cancel := context.WithTimeout(s.MainContext, time.Minute*3)
	defer cancel()

	s.DeployPod(s.Pods.Nginx, true)
	s.DeployPod(s.Pods.NginxProxy, true)
	s.DeployPod(s.Pods.ClientGeneric, true)
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

func VppPingTest(s *KubeSuite) {
	s.DeployPod(s.Pods.ClientGeneric, false)
	s.DeployPod(s.Pods.ServerGeneric, false)
	ctx, cancel := context.WithTimeout(s.MainContext, time.Minute*2)
	defer cancel()

	s.FixVersionNumber(s.Pods.ClientGeneric, s.Pods.ServerGeneric)

	s.Pods.ClientGeneric.InitVpp()
	s.Pods.ServerGeneric.InitVpp()

	o, _ := s.Pods.ClientGeneric.ExecVppctl(ctx, "ping "+s.Pods.ServerGeneric.IpAddress)
	Log(o)
	AssertContains(o, "5 sent, 5 received")
}

func EchoBuiltinEchobytesTest(s *KubeSuite) {
	s.DeployPod(s.Pods.ClientGeneric, false)
	s.DeployPod(s.Pods.ServerGeneric, false)
	ctx, cancel := context.WithTimeout(s.MainContext, time.Minute*2)
	defer cancel()

	s.FixVersionNumber(s.Pods.ClientGeneric, s.Pods.ServerGeneric)

	s.Pods.ClientGeneric.InitVpp()
	s.Pods.ServerGeneric.InitVpp()

	o, err := s.Pods.ServerGeneric.ExecServerVppctl(ctx, "test echo server uri tcp://"+s.Pods.ServerGeneric.IpAddress+"/1234")
	Log(o)
	AssertNil(err)
	o, err = s.Pods.ClientGeneric.ExecVppctl(ctx, "test echo client echo-bytes run-time 10 verbose uri tcp://"+s.Pods.ServerGeneric.IpAddress+"/1234")
	Log(o)
	AssertContains(o, "Test started")
	AssertContains(o, "Test finished")
}

func HttpClientStaticServerTest(s *KubeSuite) {
	s.DeployPod(s.Pods.ClientGeneric, false)
	s.DeployPod(s.Pods.ServerGeneric, false)
	ctx, cancel := context.WithTimeout(s.MainContext, time.Minute*2)
	defer cancel()

	s.FixVersionNumber(s.Pods.ClientGeneric, s.Pods.ServerGeneric)

	s.Pods.ClientGeneric.InitVpp()
	s.Pods.ServerGeneric.InitVpp()

	o, err := s.Pods.ServerGeneric.ExecServerVppctl(ctx, "http static server http1-only url-handlers uri tcp://"+s.Pods.ServerGeneric.IpAddress+"/8080")
	AssertNil(err, o)
	o, err = s.Pods.ServerGeneric.ExecVppctl(ctx, "test-url-handler enable")
	AssertNil(err, o)
	time.Sleep(time.Second * 2)
	o, err = s.Pods.ClientGeneric.ExecVppctl(ctx, "http client uri http://"+s.Pods.ServerGeneric.IpAddress+":8080/version.json verbose duration 10")
	Log(o)
	AssertNotContains(o, "error")
	AssertNil(err, o)
}
