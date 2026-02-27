package main

import (
	"fmt"
	"os"
	"strings"

	. "fd.io/hs-test/infra"
	"github.com/edwarnicke/exechelper"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterNoTopoTests(NginxHttp3Test, NginxAsServerTest)
	RegisterNoTopoSoloTests(NginxPerfRpsMultiThreadTest, NginxPerfCpsMultiThreadTest, NginxPerfCpsTest, NginxPerfRpsTest, NginxPerfWrkTest,
		NginxPerfCpsInterruptModeTest, NginxPerfRpsInterruptModeTest, NginxPerfWrkInterruptModeTest)
	RegisterNoTopo6SoloTests(NginxPerfRps6Test)
}

func NginxHttp3Test(s *NoTopoSuite) {
	query := "index.html"

	s.Containers.NginxHttp3.Create()
	s.CreateNginxHttp3Config(s.Containers.NginxHttp3)
	s.Containers.NginxHttp3.Start()

	vpp := s.Containers.Vpp.VppInstance
	vpp.WaitForApp("nginx-", 5)
	serverAddress := s.VppAddr()

	defer func() { os.Remove(query) }()
	args := fmt.Sprintf("curl --noproxy '*' --http3-only -k https://%s:%s/%s",
		serverAddress, s.Ports.NginxHttp3, query)
	s.Containers.Curl.ExtraRunningArgs = args
	s.Containers.Curl.Run()
	body, stats := s.Containers.Curl.GetOutput()
	Log(body)
	Log(stats)
	AssertNotContains(stats, "refused")
	AssertContains(stats, "100")
	AssertContains(body, "<http>", "<http> not found in the result!")

	// check worker crash
	logPath := s.Containers.NginxHttp3.GetHostWorkDir() + "/" + s.Containers.NginxHttp3.Name + "-error.log"
	logContents, err := exechelper.Output("cat " + logPath)
	AssertNil(err)
	AssertNotContains(string(logContents), "signal 17 (SIGCHLD) received from")
}

func NginxAsServerTest(s *NoTopoSuite) {
	query := "return_ok"
	finished := make(chan error, 1)

	s.Containers.Nginx.Create()
	s.CreateNginxConfig(s.Containers.Nginx, false)
	s.AddNginxVclConfig(false)
	s.Containers.Nginx.Start()

	vpp := s.Containers.Vpp.VppInstance
	vpp.WaitForApp("nginx-", 5)

	serverAddress := s.VppAddr()

	defer func() { os.Remove(query) }()
	go func() {
		defer GinkgoRecover()
		StartWget(finished, serverAddress, s.Ports.NginxServer, query, "")
	}()
	AssertNil(<-finished)
}

func parseString(s, pattern string) string {
	temp := strings.SplitSeq(s, "\n")
	for item := range temp {
		if strings.Contains(item, pattern) {
			return item
		}
	}
	return ""
}

type nginxPerfInterface interface {
	VppAddr() string
	AddNginxVclConfig(bool)
	CreateNginxConfig(*Container, bool)
}

func runNginxPerf(s nginxPerfInterface, mode, ab_or_wrk string, multiThreadWorkers bool, port string,
	vpp *VppInstance, nginxCont *Container, wrkCont *Container, abCont *Container) error {
	nRequests := 1000000
	nClients := 1000
	serverAddress := JoinHostPort(s.VppAddr(), port)

	nginxCont.Create()
	s.AddNginxVclConfig(multiThreadWorkers)
	s.CreateNginxConfig(nginxCont, multiThreadWorkers)
	nginxCont.Start()
	vpp.WaitForApp("nginx-", 5)

	if ab_or_wrk == "ab" {
		args := fmt.Sprintf("-n %d -c %d", nRequests, nClients)
		if mode == "rps" {
			args += " -k"
		} else if mode != "cps" {
			return fmt.Errorf("invalid mode %s; expected cps/rps", mode)
		}
		// don't exit on socket receive errors
		args += " -r"
		args += " http://" + serverAddress + "/64B.json"
		abCont.ExtraRunningArgs = args
		Log("Test might take up to 2 minutes to finish. Please wait")
		abCont.Run()
		o, err := abCont.GetOutput()
		rps := parseString(o, "Requests per second:")
		Log(rps)
		AssertContains(err, "Finished "+fmt.Sprint(nRequests))
	} else {
		args := fmt.Sprintf("-c %d -t 2 -d 30 http://%s/64B.json", nClients,
			serverAddress)
		wrkCont.ExtraRunningArgs = args
		wrkCont.Run()
		Log("Please wait for 30s, test is running.")
		o, err := wrkCont.GetOutput()
		rps := parseString(o, "requests")
		Log(rps)
		Log(err)
		AssertEmpty(err, "err: '%s', output: '%s'", err, o)
	}
	return nil
}

func NginxPerfCpsInterruptModeTest(s *NoTopoSuite) {
	NginxPerfCpsTest(s)
}

func NginxPerfCpsMultiThreadTest(s *NoTopoSuite) {
	AssertNil(runNginxPerf(s, "cps", "ab", true, s.Ports.NginxServer, s.Containers.Vpp.VppInstance,
		s.Containers.Nginx, s.Containers.Wrk, s.Containers.Ab))
}

func NginxPerfCpsTest(s *NoTopoSuite) {
	AssertNil(runNginxPerf(s, "cps", "ab", false, s.Ports.NginxServer, s.Containers.Vpp.VppInstance,
		s.Containers.Nginx, s.Containers.Wrk, s.Containers.Ab))
}

func NginxPerfRpsInterruptModeTest(s *NoTopoSuite) {
	NginxPerfRpsTest(s)
}

func NginxPerfRpsMultiThreadTest(s *NoTopoSuite) {
	AssertNil(runNginxPerf(s, "rps", "ab", true, s.Ports.NginxServer, s.Containers.Vpp.VppInstance,
		s.Containers.Nginx, s.Containers.Wrk, s.Containers.Ab))
}

func NginxPerfRpsTest(s *NoTopoSuite) {
	AssertNil(runNginxPerf(s, "rps", "ab", false, s.Ports.NginxServer, s.Containers.Vpp.VppInstance,
		s.Containers.Nginx, s.Containers.Wrk, s.Containers.Ab))
}

func NginxPerfWrkInterruptModeTest(s *NoTopoSuite) {
	NginxPerfWrkTest(s)
}

func NginxPerfWrkTest(s *NoTopoSuite) {
	AssertNil(runNginxPerf(s, "", "wrk", false, s.Ports.NginxServer, s.Containers.Vpp.VppInstance,
		s.Containers.Nginx, s.Containers.Wrk, s.Containers.Ab))
}

func NginxPerfRps6Test(s *NoTopo6Suite) {
	AssertNil(runNginxPerf(s, "rps", "ab", false, s.Ports.NginxServer, s.Containers.Vpp.VppInstance,
		s.Containers.Nginx, s.Containers.Wrk, s.Containers.Ab))
}
