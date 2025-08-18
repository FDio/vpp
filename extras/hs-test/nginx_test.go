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
	s.Log(body)
	s.Log(stats)
	s.AssertNotContains(stats, "refused")
	s.AssertContains(stats, "100")
	s.AssertContains(body, "<http>", "<http> not found in the result!")

	// check worker crash
	logPath := s.Containers.NginxHttp3.GetHostWorkDir() + "/" + s.Containers.NginxHttp3.Name + "-error.log"
	logContents, err := exechelper.Output("cat " + logPath)
	s.AssertNil(err)
	s.AssertNotContains(string(logContents), "signal 17 (SIGCHLD) received from")
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
		s.StartWget(finished, serverAddress, s.Ports.NginxServer, query, "")
	}()
	s.AssertNil(<-finished)
}

func parseString(s, pattern string) string {
	temp := strings.Split(s, "\n")
	for _, item := range temp {
		if strings.Contains(item, pattern) {
			return item
		}
	}
	return ""
}

func runNginxPerf(s *NoTopoSuite, mode, ab_or_wrk string, multiThreadWorkers bool) error {
	nRequests := 1000000
	nClients := 1000

	serverAddress := s.VppAddr() + ":" + s.Ports.NginxServer

	vpp := s.Containers.Vpp.VppInstance

	s.Containers.Nginx.Create()
	s.AddNginxVclConfig(multiThreadWorkers)
	s.CreateNginxConfig(s.Containers.Nginx, multiThreadWorkers)
	s.Containers.Nginx.Start()
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
		s.Containers.Ab.ExtraRunningArgs = args
		s.Log("Test might take up to 2 minutes to finish. Please wait")
		s.Containers.Ab.Run()
		o, err := s.Containers.Ab.GetOutput()
		rps := parseString(o, "Requests per second:")
		s.Log(rps)
		s.AssertContains(err, "Finished "+fmt.Sprint(nRequests))
	} else {
		args := fmt.Sprintf("-c %d -t 2 -d 30 http://%s/64B.json", nClients,
			serverAddress)
		s.Containers.Wrk.ExtraRunningArgs = args
		s.Containers.Wrk.Run()
		s.Log("Please wait for 30s, test is running.")
		o, err := s.Containers.Wrk.GetOutput()
		rps := parseString(o, "requests")
		s.Log(rps)
		s.Log(err)
		s.AssertEmpty(err, "err: '%s', output: '%s'", err, o)
	}
	return nil
}

func NginxPerfCpsInterruptModeTest(s *NoTopoSuite) {
	NginxPerfCpsTest(s)
}

func NginxPerfCpsMultiThreadTest(s *NoTopoSuite) {
	s.AssertNil(runNginxPerf(s, "cps", "ab", true))
}

func NginxPerfCpsTest(s *NoTopoSuite) {
	s.AssertNil(runNginxPerf(s, "cps", "ab", false))
}

func NginxPerfRpsInterruptModeTest(s *NoTopoSuite) {
	NginxPerfRpsTest(s)
}

func NginxPerfRpsMultiThreadTest(s *NoTopoSuite) {
	s.AssertNil(runNginxPerf(s, "rps", "ab", true))
}

func NginxPerfRpsTest(s *NoTopoSuite) {
	s.AssertNil(runNginxPerf(s, "rps", "ab", false))
}

func NginxPerfWrkInterruptModeTest(s *NoTopoSuite) {
	NginxPerfWrkTest(s)
}

func NginxPerfWrkTest(s *NoTopoSuite) {
	s.AssertNil(runNginxPerf(s, "", "wrk", false))
}

func runNginxPerf6(s *NoTopo6Suite, mode, ab_or_wrk string, multiThreadWorkers bool) error {
	nRequests := 1000000
	nClients := 1000

	serverAddress := "[" + s.VppAddr() + "]:" + s.Ports.NginxServer
	vpp := s.Containers.Vpp.VppInstance

	s.Containers.Nginx.Create()
	s.AddNginxVclConfig(multiThreadWorkers)
	s.CreateNginxConfig(s.Containers.Nginx, multiThreadWorkers)
	s.Containers.Nginx.Start()
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
		s.Containers.Ab.ExtraRunningArgs = args
		s.Log("Test might take up to 2 minutes to finish. Please wait")
		s.Containers.Ab.Run()
		o, err := s.Containers.Ab.GetOutput()
		rps := parseString(o, "Requests per second:")
		s.Log(rps)
		s.AssertContains(err, "Finished "+fmt.Sprint(nRequests))
	} else {
		args := fmt.Sprintf("-c %d -t 2 -d 30 http://%s/64B.json", nClients,
			serverAddress)
		s.Containers.Wrk.ExtraRunningArgs = args
		s.Containers.Wrk.Run()
		s.Log("Please wait for 30s, test is running.")
		o, err := s.Containers.Wrk.GetOutput()
		rps := parseString(o, "requests")
		s.Log(rps)
		s.Log(err)
		s.AssertEmpty(err, "err: '%s', output: '%s'", err, o)
	}
	return nil
}

func NginxPerfRps6Test(s *NoTopo6Suite) {
	s.AssertNil(runNginxPerf6(s, "rps", "ab", false))
}
