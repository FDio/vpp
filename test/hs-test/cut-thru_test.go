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
	RegisterNoTopoTests(RedisCutThruTest, LdpIperfTcpCutThruTest, LdpIperfUdpCutThruTest)
	RegisterNoTopoMWTests(RedisCutThruMWTest, LdpIperfTcpCutThruMWTest, LdpIperfUdpCutThruMWTest)
	RegisterVppProxyTests(LdpWgetVppProxyNginxCutThruTest, LdpWgetVppProxyNginxCutThruSmallFifoTest)
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

func LdpWgetVppProxyNginxCutThruTest(s *VppProxySuite) {
	ldpWgetVppProxyNginxCutThru(s, "64k", 64<<10, "--limit-rate=5m --timeout=30", "HTTP/1.1 200 OK")
}

func LdpWgetVppProxyNginxCutThruSmallFifoTest(s *VppProxySuite) {
	ldpWgetVppProxyNginxCutThru(s, "4k", 4096,
		"--header=Range:bytes=0-2097151 --limit-rate=128k --timeout=45",
		"HTTP/1.1 206 Partial Content")
}

func ldpWgetVppProxyNginxCutThru(s *VppProxySuite, proxyFifoSize string, vclFifoSize int, wgetArgs, expectedStatus string) {
	s.SetupNginxServer()
	cleanup := configureVppProxyLdpClient(s, vclFifoSize)
	defer cleanup()

	vppProxy := s.Containers.VppProxy.VppInstance
	cmd := fmt.Sprintf("test proxy server fifo-size %s server-uri tcp://%s:%d client-uri tcp://%s:%d",
		proxyFifoSize, s.VppProxyAddr(), s.Ports.Proxy, s.ServerAddr(), s.Ports.Server)
	output := vppProxy.Vppctl(cmd)
	Log("proxy configured: " + output)
	AssertNotContains(output, "failed")

	ctCheck := make(chan error, 1)
	go func() {
		deadline := time.Now().Add(5 * time.Second)
		var sessions string
		for time.Now().Before(deadline) {
			sessions = vppProxy.Vppctl("show session verbose proto ct")
			if strings.Contains(strings.ToLower(sessions), "[ct:t]") {
				Log(sessions)
				ctCheck <- nil
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		Log(sessions)
		ctCheck <- fmt.Errorf("[CT:T] not found in sessions:\n%s", sessions)
	}()

	uri := fmt.Sprintf("http://%s:%d/httpTestFile", s.VppProxyAddr(), s.Ports.Proxy)
	args := fmt.Sprintf("--server-response --progress=dot:giga --tries=1 --no-proxy -O /tmp/ldpProxyHttpTestFile %s %s", wgetArgs, uri)
	log := RunLdpWgetContainer(s.Containers.IperfC, args)
	AssertNil(<-ctCheck)
	AssertContains(log, expectedStatus)
	AssertContains(log, "saved")
	AssertNotContains(log, "bytes remaining to read")
	AssertNotContains(log, "timed out")
}

func configureVppProxyLdpClient(s *VppProxySuite, fifoSize int) func() {
	vppProxy := s.Containers.VppProxy
	client := s.Containers.IperfC
	appSocketApi := fmt.Sprintf("app-socket-api %s/var/run/app_ns_sockets/default",
		vppProxy.GetContainerWorkDir())

	var vclConf Stanza
	err := vclConf.
		NewStanza("vcl").
		Append(fmt.Sprintf("rx-fifo-size %d", fifoSize)).
		Append(fmt.Sprintf("tx-fifo-size %d", fifoSize)).
		Append("app-scope-local").
		Append("app-scope-global").
		Append("use-mq-eventfd").
		Append(appSocketApi).Close().
		SaveToFile(vppProxy.GetHostWorkDir() + "/vcl.conf")
	AssertNil(err, fmt.Sprint(err))

	envVars := map[string]string{
		"VCL_DEBUG":  "0",
		"LDP_DEBUG":  "0",
		"VCL_CONFIG": vppProxy.GetContainerWorkDir() + "/vcl.conf",
		"LD_PRELOAD": "/usr/lib/libvcl_ldpreload.so",
	}
	for key, value := range envVars {
		client.AddEnvVar(key, value)
	}
	return func() {
		for key := range envVars {
			delete(client.EnvVars, key)
		}
	}
}

func RunLdpWgetContainer(clientCont *Container, args string) string {
	cmd := fmt.Sprintf("wget %s", args)
	Log(cmd)
	clientCont.Run()
	output, err := clientCont.Exec(true, cmd)
	Log(output)
	AssertNil(err, output)
	return output
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
