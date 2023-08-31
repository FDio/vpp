package main

import (
	"fmt"
	"os"
	"strings"
)

func (s *NsSuite) TestHttpTps() {
	iface := s.netInterfaces[clientInterface]
	client_ip := iface.Ip4AddressString()
	port := "8080"
	finished := make(chan error, 1)

	container := s.GetContainerByName("vpp")

	// configure vpp in the container
	container.vppInstance.Vppctl("http tps uri tcp://0.0.0.0/8080")

	go s.StartWget(finished, client_ip, port, "test_file_10M", "client")
	// wait for client
	err := <-finished
	s.AssertNil(err)
}

func (s *VethsSuite) TestHttpCli() {
	serverContainer := s.GetContainerByName("server-vpp")
	clientContainer := s.GetContainerByName("client-vpp")

	serverVeth := s.netInterfaces[serverInterfaceName]

	serverContainer.vppInstance.Vppctl("http cli server")

	uri := "http://" + serverVeth.Ip4AddressString() + "/80"

	o := clientContainer.vppInstance.Vppctl("http cli client" +
		" uri " + uri + " query /show/version")

	s.Log(o)
	s.AssertContains(o, "<html>", "<html> not found in the result!")
}

func (s *NoTopoSuite) TestNginxHttp3() {
	s.SkipUnlessExtendedTestsBuilt()

	query := "index.html"
	nginxCont := s.GetContainerByName("nginx-http3")
	s.AssertNil(nginxCont.Run())

	vpp := s.GetContainerByName("vpp").vppInstance
	vpp.WaitForApp("nginx-", 5)
	serverAddress := s.netInterfaces[tapInterfaceName].peer.Ip4AddressString()

	defer func() { os.Remove(query) }()
	curlCont := s.GetContainerByName("curl")
	args := fmt.Sprintf("curl --noproxy '*' --http3-only -k https://%s:8443/%s", serverAddress, query)
	curlCont.extraRunningArgs = args
	o, err := curlCont.CombinedOutput()
	s.AssertNil(err)
	s.AssertContains(o, "<http>", "<http> not found in the result!")
}

func (s *NoTopoSuite) TestNginxAsServer() {
	query := "return_ok"
	finished := make(chan error, 1)

	nginxCont := s.GetContainerByName("nginx")
	s.AssertNil(nginxCont.Run())

	vpp := s.GetContainerByName("vpp").vppInstance
	vpp.WaitForApp("nginx-", 5)

	serverAddress := s.netInterfaces[tapInterfaceName].peer.Ip4AddressString()

	defer func() { os.Remove(query) }()
	go s.StartWget(finished, serverAddress, "80", query, "")
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

	serverAddress := s.netInterfaces[tapInterfaceName].peer.Ip4AddressString()

	vpp := s.GetContainerByName("vpp").vppInstance

	nginxCont := s.GetContainerByName("nginx")
	s.AssertNil(nginxCont.Run())
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
		abCont.extraRunningArgs = args
		o, err := abCont.CombinedOutput()
		rps := parseString(o, "Requests per second:")
		s.Log(rps, err)
		s.AssertNil(err)
	} else {
		wrkCont := s.GetContainerByName("wrk")
		args := fmt.Sprintf("-c %d -t 2 -d 30 http://%s:80/64B.json", nClients,
			serverAddress)
		wrkCont.extraRunningArgs = args
		o, err := wrkCont.CombinedOutput()
		rps := parseString(o, "requests")
		s.Log(rps, err)
		s.AssertNil(err)
	}
	return nil
}

func (s *NoTopoSuite) TestNginxPerfCps() {
	s.AssertNil(runNginxPerf(s, "cps", "ab"))
}

func (s *NoTopoSuite) TestNginxPerfRps() {
	s.AssertNil(runNginxPerf(s, "rps", "ab"))
}

func (s *NoTopoSuite) TestNginxPerfWrk() {
	s.AssertNil(runNginxPerf(s, "", "wrk"))
}
