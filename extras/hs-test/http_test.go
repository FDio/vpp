package main

import (
	"fmt"
	"os"
	"os/exec"
)

const (
	query string = "return_ok"
)

func (s *NsSuite) TestHttpTps() {
	iface := s.netInterfaces[clientInterface]
	client_ip := iface.IP4AddressString()
	port := "8080"
	finished := make(chan error, 1)

	container := s.getContainerByName("vpp")

	// configure vpp in the container
	container.vppInstance.vppctl("http tps uri tcp://0.0.0.0/8080")

	go startWget(finished, client_ip, port, "test_file_10M", "client")
	// wait for client
	err := <-finished
	s.assertNil(err)
}

func (s *VethsSuite) TestHttpCli() {
	serverContainer := s.getContainerByName("server-vpp")
	clientContainer := s.getContainerByName("client-vpp")

	serverVeth := s.netInterfaces[serverInterfaceName]

	serverContainer.vppInstance.vppctl("http cli server")

	uri := "http://" + serverVeth.IP4AddressString() + "/80"

	o := clientContainer.vppInstance.vppctl("http cli client" +
		" uri " + uri + " query /show/version")

	s.log(o)
	s.assertContains(o, "<html>", "<html> not found in the result!")
}

func (s *NoTopoSuite) TestNginxAsServer() {
	finished := make(chan error, 1)

	nginxCont := s.getContainerByName("nginx")
	s.assertNil(nginxCont.run())

	vpp := s.getContainerByName("vpp").vppInstance
	err := vpp.waitForApp("-app", 5)
	s.assertNil(err)

	serverAddress := s.netInterfaces[tapNameVpp].IP4AddressString()

	defer func() { os.Remove(query) }()
	go startWget(finished, serverAddress, "80", query, "")
	s.assertNil(<-finished)
}

func runNginxPerf(s *NoTopoSuite, mode, ab_or_wrk string) error {
	nRequests := 1000000
	nClients := 2000
	var args []string
	var exeName string

	serverAddress := s.netInterfaces[tapNameVpp].IP4AddressString()

	if ab_or_wrk == "ab" {
		args = []string{"-n", fmt.Sprintf("%d", nRequests), "-c",
			fmt.Sprintf("%d", nClients)}
		if mode == "rps" {
			args = append(args, "-k")
		} else if mode != "cps" {
			return fmt.Errorf("invalid mode %s; expected cps/rps", mode)
		}
		args = append(args, "http://"+serverAddress+":80/64B.json")
		exeName = "ab"
	} else {
		args = []string{"-c", fmt.Sprintf("%d", nClients), "-t", "2", "-d", "30",
			"http://" + serverAddress + ":80/" + query}
		exeName = "wrk"
	}

	vpp := s.getContainerByName("vpp").vppInstance

	nginxCont := s.getContainerByName("nginx")
	s.assertNil(nginxCont.run())
	err := vpp.waitForApp("-app", 5)
	s.assertNil(err)

	cmd := exec.Command(exeName, args...)
	s.log(cmd)
	o, _ := cmd.CombinedOutput()
	s.log(string(o))
	s.assertNotEmpty(o)
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
