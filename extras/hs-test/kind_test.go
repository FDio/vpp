package main

import (
	"context"
	"errors"
	"time"

	. "fd.io/hs-test/infra/kind"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterKindTests(KindIperfVclTest, NginxRpsTest, NginxProxyMirroringTest)
}

const vcl string = "VCL_CONFIG=/vcl.conf"
const ldp string = "LD_PRELOAD=/usr/lib/libvcl_ldpreload.so"

func KindIperfVclTest(s *KindSuite) {
	s.DeployPod(s.Pods.ClientGeneric)
	s.DeployPod(s.Pods.ServerGeneric)
	ctx, cancel := context.WithTimeout(s.MainContext, time.Second*40)
	defer cancel()

	_, err := s.Pods.ClientGeneric.Exec(ctx, []string{"/bin/bash", "-c", VclConfIperf})
	s.AssertNil(err)
	_, err = s.Pods.ServerGeneric.Exec(ctx, []string{"/bin/bash", "-c", VclConfIperf})
	s.AssertNil(err)

	s.FixVersionNumber(s.Pods.ClientGeneric, s.Pods.ServerGeneric)

	o, err := s.Pods.ServerGeneric.Exec(ctx, []string{"/bin/bash", "-c",
		vcl + " " + ldp + " iperf3 -s -D -4 -B " + s.Pods.ServerGeneric.IpAddress})
	s.AssertNil(err, o)
	o, err = s.Pods.ClientGeneric.Exec(ctx, []string{"/bin/bash", "-c",
		vcl + " " + ldp + " iperf3 -J -l 1460 -b 10g -c " + s.Pods.ServerGeneric.IpAddress})

	s.AssertNil(err)
	result := s.ParseJsonIperfOutput([]byte(o))
	s.LogJsonIperfOutput(result)
	s.AssertIperfMinTransfer(result, 2000)
}

func NginxRpsTest(s *KindSuite) {
	ctx, cancel := context.WithCancel(s.MainContext)
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

func NginxProxyMirroringTest(s *KindSuite) {
	ctx, cancel := context.WithCancel(s.MainContext)
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
