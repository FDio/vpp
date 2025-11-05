package main

import (
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
	s.SetupTest()
	redisCutThru(s)
}

func redisCutThru(s *NoTopoSuite) {
	s.SkipIfArm()
	s.CreateGenericVclConfig(s.Containers.Vpp)
	// delete env vars so the next test is started without them
	defer delete(s.Containers.Vpp.EnvVars, "VCL_CONFIG")
	defer delete(s.Containers.Vpp.EnvVars, "LD_PRELOAD")
	defer delete(s.Containers.Vpp.EnvVars, "VCL_APP_SCOPE_LOCAL")
	s.Containers.Vpp.AddEnvVar("VCL_DEBUG", "0")
	s.Containers.Vpp.AddEnvVar("LDP_DEBUG", "0")
	s.Containers.Vpp.AddEnvVar("VCL_CONFIG", s.Containers.Vpp.GetContainerWorkDir()+"/vcl.conf")
	s.Containers.Vpp.AddEnvVar("LD_PRELOAD", "/usr/lib/libvcl_ldpreload.so")
	s.Containers.Vpp.AddEnvVar("VCL_APP_SCOPE_LOCAL", "true")

	serverAddress := s.Interfaces.Tap.Peer.Ip4AddressString()
	cmd := fmt.Sprintf("redis-server --daemonize yes --protected-mode no --save \"\" --bind %s --loglevel notice --logfile %s",
		serverAddress, s.RedisServerLogFileName(s.Containers.Vpp))
	o, err := s.Containers.Vpp.Exec(true, cmd)
	s.AssertNil(err)

	// check for sessions during test run
	go func() {
		defer GinkgoRecover()
		time.Sleep(time.Second * 2)
		o = s.Containers.Vpp.VppInstance.Vppctl("show session verbose proto ct")
		s.Log(o)
		s.AssertContains(o, "[CT:T]")
	}()

	cmd = fmt.Sprintf("redis-benchmark -q --threads %d -h %s", 1, serverAddress)
	o, err = s.Containers.Vpp.Exec(true, cmd)
	s.Log(o)
	s.AssertNil(err)
}

func LdpIperfTcpCutThruTest(s *NoTopoSuite) {
	s.AssertIperfMinTransfer(ldPreloadIperfCutThru(s, ""), 100)
}

func LdpIperfTcpCutThruMWTest(s *NoTopoSuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	s.AssertIperfMinTransfer(ldPreloadIperfCutThru(s, ""), 100)
}

// hangs
func LdpIperfUdpCutThruTest(s *NoTopoSuite) {
	s.Skip("Broken")
	s.AssertIperfMinTransfer(ldPreloadIperfCutThru(s, "-u"), 100)
}

// hangs
func LdpIperfUdpCutThruMWTest(s *NoTopoSuite) {
	s.Skip("Broken")
	s.CpusPerVppContainer = 3
	s.SetupTest()
	s.AssertIperfMinTransfer(ldPreloadIperfCutThru(s, "-u"), 100)
}

// only runs iperf for 5s
func ldPreloadIperfCutThru(s *NoTopoSuite, extraClientArgs string) IPerfResult {
	// delete env vars so the next test is started without them
	defer delete(s.Containers.Vpp.EnvVars, "VCL_CONFIG")
	defer delete(s.Containers.Vpp.EnvVars, "LD_PRELOAD")
	defer delete(s.Containers.Vpp.EnvVars, "VCL_APP_SCOPE_LOCAL")
	serverVethAddress := s.Interfaces.Tap.Peer.Ip4AddressString()
	s.CreateGenericVclConfig(s.Containers.Vpp)
	s.Containers.Vpp.AddEnvVar("VCL_DEBUG", "0")
	s.Containers.Vpp.AddEnvVar("LDP_DEBUG", "0")
	s.Containers.Vpp.AddEnvVar("VCL_CONFIG", s.Containers.Vpp.GetContainerWorkDir()+"/vcl.conf")
	s.Containers.Vpp.AddEnvVar("LD_PRELOAD", "/usr/lib/libvcl_ldpreload.so")
	s.Containers.Vpp.AddEnvVar("VCL_APP_SCOPE_LOCAL", "true")

	cmd := fmt.Sprintf("sh -c \"iperf3 -4 -s --one-off -B %s -p %s --logfile %s\"",
		serverVethAddress, s.Ports.CutThru, s.IperfLogFileName(s.Containers.Vpp))
	s.Containers.Vpp.ExecServer(true, cmd)

	// check for sessions during test run
	go func() {
		defer GinkgoRecover()
		time.Sleep(time.Second * 2)
		o := s.Containers.Vpp.VppInstance.Vppctl("show session verbose")
		s.Log(o)
		if strings.Contains(extraClientArgs, "-u") {
			s.AssertContains(o, "[CT:U]")
		} else {
			s.AssertContains(o, "[CT:T]")
		}
	}()

	cmd = fmt.Sprintf("iperf3 -c %s -B %s -t 5 -l 1460 -b 10g -J -p %s %s", serverVethAddress, s.Interfaces.Tap.Peer.Ip4AddressString(), s.Ports.CutThru, extraClientArgs)
	o, err := s.Containers.Vpp.Exec(true, cmd)

	fileLog, _ := s.Containers.Vpp.Exec(false, "cat "+s.IperfLogFileName(s.Containers.Vpp))
	s.Log("*** Server logs: \n%s\n***", fileLog)

	s.AssertNil(err, o)
	result := s.ParseJsonIperfOutput([]byte(o))
	s.LogJsonIperfOutput(result)

	return result
}
