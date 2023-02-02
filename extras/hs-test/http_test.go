package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func (s *NsSuite) TestHttpTps() {
	iface := s.netInterfaces[clientInterface]
	client_ip := iface.Ip4AddressString()
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

	uri := "http://" + serverVeth.Ip4AddressString() + "/80"

	o := clientContainer.vppInstance.vppctl("http cli client" +
		" uri " + uri + " query /show/version")

	s.log(o)
	s.assertContains(o, "<html>", "<html> not found in the result!")
}

func waitForApp(vppInst *VppInstance, appName string, timeout int) error {
	for i := 0; i < timeout; i++ {
		o := vppInst.vppctl("show app")
		if strings.Contains(o, appName) {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("Timeout while waiting for app '%s'", appName)
}

func (s *NoTopoSuite) TestNginx() {
	query := "return_ok"
	finished := make(chan error, 1)
	vppCont := s.getContainerByName("vpp")
	vppInst := NewVppInstance(vppCont)
	vppInst.actionFuncName = "ConfigureTap"
	s.assertNil(vppInst.start(), "failed to start vpp")

	nginxCont := s.getContainerByName("nginx")
	s.assertNil(nginxCont.run())

	err := waitForApp(vppInst, "-app", 5)
	s.assertNil(err)

	defer func() { os.Remove(query) }()
	go startWget(finished, "10.10.10.1", "80", query, "")
	s.assertNil(<-finished)
}

func runNginxPerf(s *NoTopoSuite, mode, ab_or_wrk string) error {
	nRequests := 1000000
	nClients := 2000
	var args []string
	var exeName string

	if ab_or_wrk == "ab" {
		args = []string{"-n", fmt.Sprintf("%d", nRequests), "-c",
			fmt.Sprintf("%d", nClients)}
		if mode == "rps" {
			args = append(args, "-k")
		} else if mode != "cps" {
			return fmt.Errorf("invalid mode %s; expected cps/rps", mode)
		}
		args = append(args, "http://10.10.10.1:80/64B.json")
		exeName = "ab"
	} else {
		args = []string{"-c", fmt.Sprintf("%d", nClients), "-t", "2", "-d", "30",
			"http://10.10.10.1:80"}
		exeName = "wrk"
	}

	vppCont := s.getContainerByName("vpp")
	vppInst := NewVppInstance(vppCont)
	vppInst.actionFuncName = "ConfigureTap"
	s.assertNil(vppInst.start(), "failed to start vpp")

	nginxCont := s.getContainerByName("nginx")
	s.assertNil(nginxCont.run())
	err := waitForApp(vppInst, "-app", 5)
	s.assertNil(err)

	cmd := exec.Command(exeName, args...)
	fmt.Println(cmd)
	o, _ := cmd.CombinedOutput()
	fmt.Print(string(o))
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
