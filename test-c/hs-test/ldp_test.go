package main

import (
	"fmt"
	"os/exec"
	"time"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterSoloLdpTests(LdpIperfUdpTest, LdpIperfUdpVppInterruptModeTest, RedisBenchmarkTest,
		LdpIperfTlsTcpTest, LdpIperfTcpTest, LdpIperfTcpReorderTest, LdpIperfReverseTcpReorderTest,
		LdpIperfUdpReorderTest, LdpIperfReverseUdpReorderTest)
	RegisterLdpMWTests(LdpIperfUdpMWTest)
}

func LdpIperfUdpMWTest(s *LdpSuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	s.AssertIperfMinTransfer(ldPreloadIperf(s, "-u -P 5"), 50)
}

func LdpIperfUdpVppInterruptModeTest(s *LdpSuite) {
	s.AssertIperfMinTransfer(ldPreloadIperf(s, "-u"), 100)
}

func ldpIperfTcpReorder(s *LdpSuite, netInterface *NetInterface, extraIperfArgs string) {
	cmd := exec.Command("tc", "qdisc", "del", "dev", netInterface.Peer.Name(),
		"root")
	s.Log("defer '%s'", cmd.String())
	defer cmd.Run()

	// "10% of packets (with a correlation of 50%) will get sent immediately, others will be delayed by 10ms"
	// https://www.man7.org/linux/man-pages/man8/tc-netem.8.html
	cmd = exec.Command("tc", "qdisc", "add", "dev", netInterface.Peer.Name(),
		"root", "netem", "delay", "10ms", "reorder", "10%", "50%")
	s.Log(cmd.String())
	o, err := cmd.CombinedOutput()
	s.AssertNil(err, string(o))

	delete(s.Containers.ClientApp.EnvVars, "VCL_CONFIG")
	delete(s.Containers.ClientApp.EnvVars, "LD_PRELOAD")
	delete(s.Containers.ClientApp.EnvVars, "VCL_DEBUG")
	delete(s.Containers.ClientApp.EnvVars, "LDP_DEBUG")
	s.Containers.ClientVpp.VppInstance.Disconnect()
	s.Containers.ClientVpp.VppInstance.Stop()
	s.Containers.ClientVpp.Exec(false, "ip addr add dev %s %s", s.Interfaces.Client.Name(), s.Interfaces.Client.Ip4Address)

	s.AssertIperfMinTransfer(ldPreloadIperf(s, extraIperfArgs), 20)
}

func LdpIperfTcpReorderTest(s *LdpSuite) {
	ldpIperfTcpReorder(s, s.Interfaces.Server, "")
}

func LdpIperfReverseTcpReorderTest(s *LdpSuite) {
	ldpIperfTcpReorder(s, s.Interfaces.Client, "-R")
}

func LdpIperfUdpReorderTest(s *LdpSuite) {
	ldpIperfTcpReorder(s, s.Interfaces.Server, "-u")
}

func LdpIperfReverseUdpReorderTest(s *LdpSuite) {
	ldpIperfTcpReorder(s, s.Interfaces.Client, "-u -R")
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
	s.AssertIperfMinTransfer(ldPreloadIperf(s, ""), 100)
}

func LdpIperfTcpTest(s *LdpSuite) {
	s.AssertIperfMinTransfer(ldPreloadIperf(s, ""), 100)
}

func LdpIperfUdpTest(s *LdpSuite) {
	s.AssertIperfMinTransfer(ldPreloadIperf(s, "-u"), 100)
}

func ldPreloadIperf(s *LdpSuite, extraClientArgs string) IPerfResult {
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
		cmd := fmt.Sprintf("sh -c \"iperf3 -4 -s -B %s -p %s > %s 2>&1\"", serverVethAddress, s.Ports.Port1, s.IperfLogFileName(s.Containers.ServerApp))
		s.StartServerApp(s.Containers.ServerApp, "iperf3", cmd, srvCh, stopServerCh)
	}()

	err := <-srvCh
	s.AssertNil(err, fmt.Sprint(err))

	go func() {
		defer GinkgoRecover()
		cmd := fmt.Sprintf("iperf3 -c %s -B %s -l 1460 -b 10g -J -p %s %s", serverVethAddress, s.Interfaces.Client.Ip4AddressString(), s.Ports.Port1, extraClientArgs)
		s.StartClientApp(s.Containers.ClientApp, cmd, clnCh, clnRes)
	}()

	s.AssertChannelClosed(time.Minute*4, clnCh)
	output := <-clnRes
	result := s.ParseJsonIperfOutput(output)
	s.LogJsonIperfOutput(result)

	return result
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
		s.Containers.ServerApp.Exec(false, "sysctl vm.overcommit_memory=1")
		// Note: --save "" disables snapshotting which during upgrade to ubuntu 24.04 was
		// observed to corrupt vcl memory / heap. Needs more debugging.
		cmd := "redis-server --daemonize yes --protected-mode no --save \"\" --bind " + serverVethAddress + " --loglevel notice --logfile " + s.RedisServerLogFileName(s.Containers.ServerApp)
		s.StartServerApp(s.Containers.ServerApp, "redis-server", cmd, runningSrv, doneSrv)
	}()

	err := <-runningSrv
	s.AssertNil(err)

	go func() {
		defer GinkgoRecover()
		var cmd string
		if *NConfiguredCpus == 1 {
			cmd = "redis-benchmark -q --threads 1 -h " + serverVethAddress
		} else {
			cmd = "redis-benchmark -q --threads " + fmt.Sprint(s.CpusPerContainer) + "-h " + serverVethAddress
		}
		s.StartClientApp(s.Containers.ClientApp, cmd, clnCh, clnRes)
	}()

	// 4.5 minutes
	s.AssertChannelClosed(time.Second*270, clnCh)
	s.Log(string(<-clnRes))
}
