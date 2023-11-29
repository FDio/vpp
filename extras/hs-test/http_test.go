package main

import (
	"fmt"
	"os"
	"strings"
)

func (s *NsSuite) TestHttpTps() {
	iface := s.netInterfaces[clientInterface]
	client_ip := iface.ip4AddressString()
	port := "8080"
	finished := make(chan error, 1)

	container := s.getContainerByName("vpp")

	// configure vpp in the container
	container.vppInstance.vppctl("http tps uri tcp://0.0.0.0/8080")

	go s.startWget(finished, client_ip, port, "test_file_10M", "client")
	// wait for client
	err := <-finished
	s.assertNil(err)
}

func (s *VethsSuite) TestHttpCli() {
	serverContainer := s.getContainerByName("server-vpp")
	clientContainer := s.getContainerByName("client-vpp")

	serverVeth := s.netInterfaces[serverInterfaceName]

	serverContainer.vppInstance.vppctl("http cli server")

	uri := "http://" + serverVeth.ip4AddressString() + "/80"

	o := clientContainer.vppInstance.vppctl("http cli client" +
		" uri " + uri + " query /show/version")

	s.log(o)
	s.assertContains(o, "<html>", "<html> not found in the result!")
}

func (s *NoTopoSuite) TestNginxHttp3() {
	s.SkipUnlessExtendedTestsBuilt()

	query := "index.html"
	nginxCont := s.getContainerByName("nginx-http3")
	s.assertNil(nginxCont.run())

	vpp := s.getContainerByName("vpp").vppInstance
	vpp.waitForApp("nginx-", 5)
	serverAddress := s.netInterfaces[tapInterfaceName].peer.ip4AddressString()

	defer func() { os.Remove(query) }()
	curlCont := s.getContainerByName("curl")
	args := fmt.Sprintf("curl --noproxy '*' --http3-only -k https://%s:8443/%s", serverAddress, query)
	curlCont.extraRunningArgs = args
	o, err := curlCont.combinedOutput()
	s.assertNil(err)
	s.assertContains(o, "<http>", "<http> not found in the result!")
}

func (s *NoTopoSuite) TestHttpStaticProm() {
	finished := make(chan error, 1)
	query := "stats.prom"
	vpp := s.getContainerByName("vpp").vppInstance
	serverAddress := s.netInterfaces[tapInterfaceName].peer.ip4AddressString()
	s.log(vpp.vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers"))
	s.log(vpp.vppctl("prom enable"))
	go s.startWget(finished, serverAddress, "80", query, "")
	err := <-finished
	s.assertNil(err)
}

func (s *NoTopoSuite) TestNginxAsServer() {
	query := "return_ok"
	finished := make(chan error, 1)

	nginxCont := s.getContainerByName("nginx")
	s.assertNil(nginxCont.run())

	vpp := s.getContainerByName("vpp").vppInstance
	vpp.waitForApp("nginx-", 5)

	serverAddress := s.netInterfaces[tapInterfaceName].peer.ip4AddressString()

	defer func() { os.Remove(query) }()
	go s.startWget(finished, serverAddress, "80", query, "")
	s.assertNil(<-finished)
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

	serverAddress := s.netInterfaces[tapInterfaceName].peer.ip4AddressString()

	vpp := s.getContainerByName("vpp").vppInstance

	nginxCont := s.getContainerByName("nginx")
	s.assertNil(nginxCont.run())
	vpp.waitForApp("nginx-", 5)

	if ab_or_wrk == "ab" {
		abCont := s.getContainerByName("ab")
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
		o, err := abCont.combinedOutput()
		rps := parseString(o, "Requests per second:")
		s.log(rps, err)
		s.assertNil(err)
	} else {
		wrkCont := s.getContainerByName("wrk")
		args := fmt.Sprintf("-c %d -t 2 -d 30 http://%s:80/64B.json", nClients,
			serverAddress)
		wrkCont.extraRunningArgs = args
		o, err := wrkCont.combinedOutput()
		rps := parseString(o, "requests")
		s.log(rps, err)
		s.assertNil(err)
	}
	return nil
}

func (s *NoTopoSuite) TestNginxPerfCps() {
	s.assertNil(runNginxPerf(s, "cps", "ab"))
}

func (s *NoTopoSuite) TestNginxPerfRps() {
	s.assertNil(runNginxPerf(s, "rps", "ab"))
}

func (s *NoTopoSuite) TestNginxPerfWrk() {
	s.assertNil(runNginxPerf(s, "", "wrk"))
}
