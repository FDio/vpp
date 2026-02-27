package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterNoTopoSoloTests(RedisCutThruTest, LdpIperfTcpCutThruTest, LdpIperfUdpCutThruTest)
	RegisterNoTopoMWTests(RedisCutThruMWTest, LdpIperfTcpCutThruMWTest, LdpIperfUdpCutThruMWTest)
}

func RedisCutThruTest(s *NoTopoSuite) {
	redisCutThru(s)
}

// redis-benchmark (client) core dumps when --threads > 1
func RedisCutThruMWTest(s *NoTopoSuite) {
	s.Skip("Broken")
	s.CpusPerVppContainer = 3
	s.CpusPerContainer = 3
	s.SetupTest()
	redisCutThru(s)
}

func redisCutThru(s *NoTopoSuite) {
	s.SkipIfArm()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.CreateGenericVclConfig(s.Containers.Vpp)
	// delete env vars so the next test is started without them
	containers := [2]*Container{s.Containers.ServerApp, s.Containers.ClientApp}
	for _, c := range containers {
		c.AddEnvVar("VCL_DEBUG", "0")
		c.AddEnvVar("LDP_DEBUG", "0")
		c.AddEnvVar("VCL_CONFIG", s.Containers.Vpp.GetContainerWorkDir()+"/vcl.conf")
		c.AddEnvVar("LD_PRELOAD", "/usr/lib/libvcl_ldpreload.so")
		c.AddEnvVar("VCL_APP_SCOPE_LOCAL", "true")
		defer delete(c.EnvVars, "VCL_CONFIG")
		defer delete(c.EnvVars, "LD_PRELOAD")
		defer delete(c.EnvVars, "VCL_APP_SCOPE_LOCAL")
	}
	s.Containers.Vpp.AddEnvVar("VCL_APP_SCOPE_LOCAL", "true")

	s.Containers.ServerApp.Run()
	s.Containers.ClientApp.Run()

	serverAddress := s.Interfaces.Tap.Ip4AddressString()
	cmd := fmt.Sprintf("redis-server --daemonize yes --protected-mode no --save \"\" --bind %s --loglevel notice --logfile %s",
		serverAddress, RedisServerLogFileName(s.Containers.Vpp))
	o, err := s.Containers.ServerApp.Exec(true, cmd)
	AssertNil(err)

	// check for sessions during test run
	go func() {
		defer GinkgoRecover()
		time.Sleep(time.Second * 2)
		o = s.Containers.Vpp.VppInstance.Vppctl("show session verbose proto ct")
		Log(o)
		if !strings.Contains(strings.ToLower(o), "[ct:t]") {
			cancel()
			AssertContains(o, "[CT:T]")
		}
	}()

	cmd = fmt.Sprintf("redis-benchmark -q --threads %d -h %s", 1, serverAddress)
	o, err = s.Containers.ClientApp.ExecContext(ctx, true, cmd)
	Log(o)
	AssertNil(err)
}

func LdpIperfTcpCutThruTest(s *NoTopoSuite) {
	AssertGreaterEqualUnlessCoverageBuild(ldPreloadIperfCutThru(s, ""), 100)
}

func LdpIperfTcpCutThruMWTest(s *NoTopoSuite) {
	s.CpusPerVppContainer = 3
	s.CpusPerContainer = 3
	s.SetupTest()
	AssertGreaterEqualUnlessCoverageBuild(ldPreloadIperfCutThru(s, ""), 100)
}

// hangs
func LdpIperfUdpCutThruTest(s *NoTopoSuite) {
	s.Skip("Broken")
	AssertGreaterEqualUnlessCoverageBuild(ldPreloadIperfCutThru(s, "-u -b 10g"), 100)
}

// hangs
func LdpIperfUdpCutThruMWTest(s *NoTopoSuite) {
	s.Skip("Broken")
	s.CpusPerVppContainer = 3
	s.SetupTest()
	AssertGreaterEqualUnlessCoverageBuild(ldPreloadIperfCutThru(s, "-u -b 10g"), 100)
}

// only runs iperf for 5s
func ldPreloadIperfCutThru(s *NoTopoSuite, extraClientArgs string) float64 {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.CreateGenericVclConfig(s.Containers.Vpp)
	// delete env vars so the next test is started without them
	containers := [2]*Container{s.Containers.ServerApp, s.Containers.ClientApp}
	for _, c := range containers {
		c.AddEnvVar("VCL_DEBUG", "0")
		c.AddEnvVar("LDP_DEBUG", "0")
		c.AddEnvVar("VCL_CONFIG", s.Containers.Vpp.GetContainerWorkDir()+"/vcl.conf")
		c.AddEnvVar("LD_PRELOAD", "/usr/lib/libvcl_ldpreload.so")
		c.AddEnvVar("VCL_APP_SCOPE_LOCAL", "true")
		defer delete(c.EnvVars, "VCL_CONFIG")
		defer delete(c.EnvVars, "LD_PRELOAD")
		defer delete(c.EnvVars, "VCL_APP_SCOPE_LOCAL")
	}
	s.Containers.Vpp.AddEnvVar("VCL_APP_SCOPE_LOCAL", "true")

	s.Containers.ServerApp.Run()
	s.Containers.ClientApp.Run()

	serverAddress := s.Interfaces.Tap.Ip4AddressString()

	cmd := fmt.Sprintf("sh -c \"iperf3 -4 -s --one-off -B %s -p %s --logfile %s\"",
		serverAddress, s.Ports.CutThru, IperfLogFileName(s.Containers.ServerApp))
	s.Containers.ServerApp.ExecServer(true, cmd)
	s.Containers.Vpp.VppInstance.WaitForApp("iperf", 3)

	// check for sessions during test run
	go func() {
		defer GinkgoRecover()
		time.Sleep(time.Second * 2)
		o := s.Containers.Vpp.VppInstance.Vppctl("show session verbose")
		Log(o)
		if !(strings.Contains(strings.ToLower(o), "[ct:t]") || strings.Contains(strings.ToLower(o), "[ct:u]")) {
			cancel()
			AssertNil(fmt.Errorf("[CT:T] or [CT:U] not found in output"))
		}
	}()

	cmd = fmt.Sprintf("iperf3 -c %s -t 5 -l 1460 -p %s %s",
		serverAddress, s.Ports.CutThru, extraClientArgs)
	o, err := s.Containers.ClientApp.ExecContext(ctx, true, cmd)

	fileLog, _ := s.Containers.ServerApp.Exec(false, "cat "+IperfLogFileName(s.Containers.ServerApp))
	Log("*** Server logs: \n%s\n***", fileLog)

	Log(o)
	AssertNil(err, o)
	result, err := ParseIperfText(o)
	AssertNil(err)

	return result.BitrateMbps
}
