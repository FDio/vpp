package main

import (
	"context"
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
	AssertGreaterEqualUnlessCoverageBuild(ldPreloadIperf(s, "-u -b 1g -P 5", false), 50)
}

func LdpIperfUdpVppInterruptModeTest(s *LdpSuite) {
	AssertGreaterEqualUnlessCoverageBuild(ldPreloadIperf(s, "-u -b 1g", false), 100)
}

func ldpIperfTcpReorder(s *LdpSuite, netInterface *NetInterface, extraIperfArgs string) {
	cmd := exec.Command("tc", "qdisc", "del", "dev", netInterface.Host.Name(),
		"root")
	Log("defer '%s'", cmd.String())
	defer cmd.Run()

	// "10% of packets (with a correlation of 50%) will get sent immediately, others will be delayed by 10ms"
	// https://www.man7.org/linux/man-pages/man8/tc-netem.8.html
	cmd = exec.Command("tc", "qdisc", "add", "dev", netInterface.Host.Name(),
		"root", "netem", "delay", "10ms", "reorder", "10%", "50%")
	Log(cmd.String())
	o, err := cmd.CombinedOutput()
	AssertNil(err, string(o))

	delete(s.Containers.ClientApp.EnvVars, "VCL_CONFIG")
	delete(s.Containers.ClientApp.EnvVars, "LD_PRELOAD")
	delete(s.Containers.ClientApp.EnvVars, "VCL_DEBUG")
	delete(s.Containers.ClientApp.EnvVars, "LDP_DEBUG")

	AssertGreaterEqualUnlessCoverageBuild(ldPreloadIperf(s, extraIperfArgs, true), 20)
}

func LdpIperfTcpReorderTest(s *LdpSuite) {
	ldpIperfTcpReorder(s, s.Interfaces.Server, "")
}

func LdpIperfReverseTcpReorderTest(s *LdpSuite) {
	ldpIperfTcpReorder(s, s.Interfaces.Client, "-R")
}

func LdpIperfUdpReorderTest(s *LdpSuite) {
	ldpIperfTcpReorder(s, s.Interfaces.Server, "-u -b 1g")
}

func LdpIperfReverseUdpReorderTest(s *LdpSuite) {
	ldpIperfTcpReorder(s, s.Interfaces.Client, "-u -b 1g -R")
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
	AssertGreaterEqualUnlessCoverageBuild(ldPreloadIperf(s, "", false), 100)
}

func LdpIperfTcpTest(s *LdpSuite) {
	AssertGreaterEqualUnlessCoverageBuild(ldPreloadIperf(s, "", false), 100)
}

func LdpIperfUdpTest(s *LdpSuite) {
	AssertGreaterEqualUnlessCoverageBuild(ldPreloadIperf(s, "-u -b 1g", false), 100)
}

func ldPreloadIperf(s *LdpSuite, extraClientArgs string, isReorder bool) float64 {
	serverAddress := s.Interfaces.Server.Ip4AddressString()
	var clientBindAddress string
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	defer cancel()

	if isReorder {
		clientBindAddress = s.Interfaces.Client.Host.Ip4AddressString()
	} else {
		clientBindAddress = s.Interfaces.Client.Ip4AddressString()
	}

	// running as daemon makes reorder tests unstable
	cmd := fmt.Sprintf("sh -c \"iperf3 -4 -s --one-off -B %s -p %s --logfile %s\"",
		serverAddress, s.Ports.Port1, IperfLogFileName(s.Containers.ServerApp))
	s.Containers.ServerApp.ExecServer(true, cmd)
	s.Containers.ServerVpp.VppInstance.WaitForApp("iperf", 3)

	cmd = fmt.Sprintf("iperf3 -c %s -B %s -l 1460 -p %s %s", serverAddress, clientBindAddress, s.Ports.Port1, extraClientArgs)
	o, err := s.Containers.ClientApp.ExecContext(ctx, true, cmd)

	fileLog, _ := s.Containers.ServerApp.Exec(false, "cat "+IperfLogFileName(s.Containers.ServerApp))
	Log("*** Server logs: \n%s\n***", fileLog)

	Log(o)
	AssertNil(err, o)
	result, err := ParseIperfText(o)
	AssertNil(err)
	return result.BitrateMbps
}

func RedisBenchmarkTest(s *LdpSuite) {
	s.SkipIfMultiWorker()
	s.SkipIfArm()

	serverAddress := s.Interfaces.Server.Ip4AddressString()
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
		cmd := "redis-server --daemonize yes --protected-mode no --save \"\" --bind " + serverAddress + " --loglevel notice --logfile " + RedisServerLogFileName(s.Containers.ServerApp)
		StartServerApp(s.Containers.ServerApp, "redis-server", cmd, runningSrv, doneSrv)
	}()

	err := <-runningSrv
	AssertNil(err)

	go func() {
		defer GinkgoRecover()
		var cmd string
		if *NConfiguredCpus == 1 {
			cmd = "redis-benchmark -q --threads 1 -h " + serverAddress
		} else {
			cmd = "redis-benchmark -q --threads " + fmt.Sprint(s.CpusPerContainer) + "-h " + serverAddress
		}
		StartClientApp(s.Containers.ClientApp, cmd, clnCh, clnRes)
	}()

	// 4.5 minutes
	AssertChannelClosed(time.Second*270, clnCh)
	Log(string(<-clnRes))
}
