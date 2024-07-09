package main

import (
	. "fd.io/hs-test/infra"
	"fmt"
	"github.com/edwarnicke/exechelper"
	. "github.com/onsi/ginkgo/v2"
	"os"
	"strings"
)

func init() {
	RegisterNginxTests(MirroringTest)
	RegisterNoTopoTests(NginxHttp3Test, NginxAsServerTest, NginxPerfCpsTest, NginxPerfRpsTest, NginxPerfWrkTest,
		NginxPerfCpsInterruptModeTest, NginxPerfRpsInterruptModeTest, NginxPerfWrkInterruptModeTest)
}

// broken when CPUS > 1
func MirroringTest(s *NginxSuite) {
	s.SkipIfMultiWorker()
	proxyAddress := s.GetInterfaceByName(MirroringClientInterfaceName).Peer.Ip4AddressString()

	path := "/64B.json"

	testCommand := "wrk -c 20 -t 10 -d 10 http://" + proxyAddress + ":80" + path
	s.Log(testCommand)
	o, _ := exechelper.Output(testCommand)
	s.Log(string(o))
	s.AssertNotEmpty(o)

	vppProxyContainer := s.GetContainerByName(VppProxyContainerName)
	s.AssertEqual(0, vppProxyContainer.VppInstance.GetSessionStat("no lcl port"))
}

func NginxHttp3Test(s *NoTopoSuite) {
	s.SkipUnlessExtendedTestsBuilt()

	query := "index.html"
	nginxCont := s.GetContainerByName("nginx-http3")
	nginxCont.Run()

	vpp := s.GetContainerByName("vpp").VppInstance
	vpp.WaitForApp("nginx-", 5)
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()

	defer func() { os.Remove(query) }()
	curlCont := s.GetContainerByName("curl")
	args := fmt.Sprintf("curl --noproxy '*' --local-port 55444 --http3-only -k https://%s:8443/%s", serverAddress, query)
	curlCont.ExtraRunningArgs = args
	curlCont.Run()
	o, err := curlCont.GetOutput()
	s.Log(o)
	s.AssertEmpty(err)
	s.AssertContains(o, "<http>", "<http> not found in the result!")
}
func NginxAsServerTest(s *NoTopoSuite) {
	query := "return_ok"
	finished := make(chan error, 1)

	nginxCont := s.GetContainerByName("nginx")
	nginxCont.Run()

	vpp := s.GetContainerByName("vpp").VppInstance
	vpp.WaitForApp("nginx-", 5)

	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()

	defer func() { os.Remove(query) }()
	go func() {
		defer GinkgoRecover()
		s.StartWget(finished, serverAddress, "80", query, "")
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

func runNginxPerf(s *NoTopoSuite, mode, ab_or_wrk string) error {
	nRequests := 1000000
	nClients := 1000

	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()

	vpp := s.GetContainerByName("vpp").VppInstance

	nginxCont := s.GetContainerByName(SingleTopoContainerNginx)
	nginxCont.Run()
	vpp.WaitForApp("nginx-", 5)

	if ab_or_wrk == "ab" {
		abCont := s.GetContainerByName("ab")
		args := fmt.Sprintf("-n %d -c %d", nRequests, nClients)
		if mode == "rps" {
			args += " -k"
		} else if mode != "cps" {
			return fmt.Errorf("invalid mode %s; expected cps/rps", mode)
		}
		// don't exit on socket receive errors
		args += " -r"
		args += " http://" + serverAddress + ":80/64B.json"
		abCont.ExtraRunningArgs = args
		abCont.Run()
		o, err := abCont.GetOutput()
		rps := parseString(o, "Requests per second:")
		s.Log(rps)
		s.AssertContains(err, "Finished "+fmt.Sprint(nRequests))
	} else {
		wrkCont := s.GetContainerByName("wrk")
		args := fmt.Sprintf("-c %d -t 2 -d 30 http://%s:80/64B.json", nClients,
			serverAddress)
		wrkCont.ExtraRunningArgs = args
		wrkCont.Run()
		s.Log("Please wait for 30s, test is running.")
		o, err := wrkCont.GetOutput()
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

// unstable with multiple workers
func NginxPerfCpsTest(s *NoTopoSuite) {
	s.SkipIfMultiWorker()
	s.AssertNil(runNginxPerf(s, "cps", "ab"))
}

func NginxPerfRpsInterruptModeTest(s *NoTopoSuite) {
	NginxPerfRpsTest(s)
}

func NginxPerfRpsTest(s *NoTopoSuite) {
	s.AssertNil(runNginxPerf(s, "rps", "ab"))
}

func NginxPerfWrkInterruptModeTest(s *NoTopoSuite) {
	NginxPerfWrkTest(s)
}

func NginxPerfWrkTest(s *NoTopoSuite) {
	s.AssertNil(runNginxPerf(s, "", "wrk"))
}
