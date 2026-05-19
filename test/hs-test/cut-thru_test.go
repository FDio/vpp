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
	RegisterNoTopoTests(BuiltinEchoVclClientCutThruTest)
	RegisterNoTopoSoloTests(RedisCutThruTest, LdpIperfTcpCutThruTest, LdpIperfUdpCutThruTest)
	RegisterNoTopoMWTests(RedisCutThruMWTest, LdpIperfTcpCutThruMWTest, LdpIperfUdpCutThruMWTest,
		BuiltinEchoVclClientCutThruMWTest)
}

func RedisCutThruTest(s *NoTopoSuite) {
	redisCutThru(s)
}

func BuiltinEchoVclClientCutThruTest(s *NoTopoSuite) {
	builtinEchoVclClientCutThru(s)
}

func BuiltinEchoVclClientCutThruMWTest(s *NoTopoSuite) {
	s.CpusPerVppContainer = 3
	s.CpusPerContainer = 3
	s.SetupTest()
	builtinEchoVclClientCutThru(s)
}

func createSmallFifoVclConfig(container *Container) {
	var vclConf Stanza
	vclFileName := container.GetHostWorkDir() + "/vcl.conf"
	appSocketApi := fmt.Sprintf("app-socket-api %s/var/run/app_ns_sockets/default",
		container.GetContainerWorkDir())

	err := vclConf.
		NewStanza("vcl").
		Append("rx-fifo-size 16384").
		Append("tx-fifo-size 16384").
		Append("app-scope-local").
		Append("app-scope-global").
		Append("use-mq-eventfd").
		Append(appSocketApi).Close().
		SaveToFile(vclFileName)
	AssertNil(err, fmt.Sprint(err))
}

func removeStaleWorkDirVolumes(container *Container, containerWorkDir string) {
	for name, volume := range container.Volumes {
		if volume.IsDefaultWorkDir || volume.ContainerDir == containerWorkDir {
			delete(container.Volumes, name)
		}
	}
}

func builtinEchoVclClientCutThru(s *NoTopoSuite) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	createSmallFifoVclConfig(s.Containers.Vpp)
	clientApp := s.Containers.ClientApp
	removeStaleWorkDirVolumes(clientApp, s.Containers.Vpp.GetContainerWorkDir())
	clientApp.AddEnvVar("VCL_DEBUG", "0")
	clientApp.AddEnvVar("VCL_CONFIG", s.Containers.Vpp.GetContainerWorkDir()+"/vcl.conf")
	clientApp.AddEnvVar("VCL_APP_SCOPE_LOCAL", "true")
	clientApp.AddEnvVar("VCL_APP_SCOPE_GLOBAL", "true")
	defer delete(clientApp.EnvVars, "VCL_DEBUG")
	defer delete(clientApp.EnvVars, "VCL_CONFIG")
	defer delete(clientApp.EnvVars, "VCL_APP_SCOPE_LOCAL")
	defer delete(clientApp.EnvVars, "VCL_APP_SCOPE_GLOBAL")

	clientApp.Run()

	serverAddress := "0.0.0.0"
	clientAddress := "127.0.0.1"
	vpp := s.Containers.Vpp.VppInstance
	o := vpp.Vppctl("test echo server local-scope uri tcp://%s/%s fifo-size 16k",
		serverAddress, s.Ports.CutThru)
	Log(o)
	AssertNotContains(o, "failed")

	o = vpp.Vppctl("show session verbose proto ct")
	Log(o)
	AssertContains(o, "[CT:T]")

	cmd := fmt.Sprintf("vcl_test_client -X -B -p tcp -s 1 -N 4 -T 8192 %s %s",
		clientAddress, s.Ports.CutThru)
	o, stderr, err := clientApp.ExecLineBuffered(ctx, true, cmd)
	Log(o)
	Log(stderr)
	AssertNil(ctx.Err(), o+stderr)
	AssertNil(err, o+stderr)
	AssertContains(o+stderr, "CLIENT RESULTS")
	AssertNotContains(o+stderr, "failed")
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
	AssertGreaterEqualUnlessCoverageBuild(ldPreloadIperfCutThru(s, ""), 100, "Iperf bitrate below threshold")
}

func LdpIperfTcpCutThruMWTest(s *NoTopoSuite) {
	s.CpusPerVppContainer = 3
	s.CpusPerContainer = 3
	s.SetupTest()
	AssertGreaterEqualUnlessCoverageBuild(ldPreloadIperfCutThru(s, ""), 100, "Iperf bitrate below threshold")
}

// hangs
func LdpIperfUdpCutThruTest(s *NoTopoSuite) {
	s.Skip("Broken")
	AssertGreaterEqualUnlessCoverageBuild(ldPreloadIperfCutThru(s, "-u -b 10g"), 100, "Iperf bitrate below threshold")
}

// hangs
func LdpIperfUdpCutThruMWTest(s *NoTopoSuite) {
	s.Skip("Broken")
	s.CpusPerVppContainer = 3
	s.SetupTest()
	AssertGreaterEqualUnlessCoverageBuild(ldPreloadIperfCutThru(s, "-u -b 10g"), 100, "Iperf bitrate below threshold")
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
