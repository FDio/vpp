package main

import (
	"fmt"
	"time"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterLdpTests(LdpIperfUdpVppTest, LdpIperfUdpVppInterruptModeTest, RedisBenchmarkTest, LdpIperfTlsTcpTest, LdpIperfTcpVppTest)
}

func LdpIperfUdpVppInterruptModeTest(s *LdpSuite) {
	ldPreloadIperfVpp(s, true)
}

func LdpIperfTlsTcpTest(s *LdpSuite) {
	for _, c := range s.StartedContainers {
		defer delete(c.EnvVars, "LDP_TRANSPARENT_TLS")
		defer delete(c.EnvVars, "LDP_TLS_CERT_FILE")
		defer delete(c.EnvVars, "LDP_TLS_KEY_FILE")
		c.Exec(false, "openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout key.key -out crt.crt -subj \"/CN=test\"")
		c.AddEnvVar("LDP_TRANSPARENT_TLS", "1")
		c.AddEnvVar("LDP_TLS_CERT_FILE", "/crt.crt")
		c.AddEnvVar("LDP_TLS_KEY_FILE", "/key.key")
	}
	ldPreloadIperfVpp(s, false)
}

func LdpIperfTcpVppTest(s *LdpSuite) {
	ldPreloadIperfVpp(s, false)
}

func LdpIperfUdpVppTest(s *LdpSuite) {
	ldPreloadIperfVpp(s, true)
}

func ldPreloadIperfVpp(s *LdpSuite, useUdp bool) {
	protocol := ""
	if useUdp {
		protocol = " -u "
	}
	serverVethAddress := s.Interfaces.Server.Ip4AddressString()
	stopServerCh := make(chan struct{}, 1)
	srvCh := make(chan error, 1)
	clnCh := make(chan error)
	clnRes := make(chan []byte, 1)

	defer func() {
		stopServerCh <- struct{}{}
	}()

	go func() {
		defer GinkgoRecover()
		cmd := "iperf3 -4 -s -p " + s.GetPortFromPpid() + " --logfile " + s.IperfLogFileName(s.Containers.ServerVpp)
		s.StartServerApp(s.Containers.ServerVpp, "iperf3", cmd, srvCh, stopServerCh)
	}()

	err := <-srvCh
	s.AssertNil(err, fmt.Sprint(err))

	go func() {
		defer GinkgoRecover()
		cmd := "iperf3 -c " + serverVethAddress + " -l 1460 -b 10g -J -p " + s.GetPortFromPpid() + protocol
		s.StartClientApp(s.Containers.ClientVpp, cmd, clnCh, clnRes)
	}()

	s.AssertChannelClosed(time.Minute*3, clnCh)
	output := <-clnRes
	result := s.ParseJsonIperfOutput(output)
	s.LogJsonIperfOutput(result)
	s.AssertIperfMinTransfer(result, 50)
}

func RedisBenchmarkTest(s *LdpSuite) {
	s.SkipIfMultiWorker()
	s.SkipIfArm()

	serverVethAddress := s.Interfaces.Server.Ip4AddressString()
	runningSrv := make(chan error)
	doneSrv := make(chan struct{})
	clnCh := make(chan error)
	clnRes := make(chan []byte, 1)

	defer func() {
		doneSrv <- struct{}{}
	}()

	go func() {
		defer GinkgoRecover()
		// Avoid redis warning during startup
		s.Containers.ServerVpp.Exec(false, "sysctl vm.overcommit_memory=1")
		// Note: --save "" disables snapshotting which during upgrade to ubuntu 24.04 was
		// observed to corrupt vcl memory / heap. Needs more debugging.
		cmd := "redis-server --daemonize yes --protected-mode no --save \"\" --bind " + serverVethAddress + " --loglevel notice --logfile " + s.RedisServerLogFileName(s.Containers.ServerVpp)
		s.StartServerApp(s.Containers.ServerVpp, "redis-server", cmd, runningSrv, doneSrv)
	}()

	err := <-runningSrv
	s.AssertNil(err)

	go func() {
		defer GinkgoRecover()
		var cmd string
		if *NConfiguredCpus == 1 {
			cmd = "redis-benchmark -q --threads 1 -h " + serverVethAddress
		} else {
			cmd = "redis-benchmark -q --threads " + fmt.Sprint(*NConfiguredCpus) + "-h " + serverVethAddress
		}
		s.StartClientApp(s.Containers.ClientVpp, cmd, clnCh, clnRes)

	}()

	// 4.5 minutes
	s.AssertChannelClosed(time.Second*270, clnCh)
	s.Log(string(<-clnRes))
}
