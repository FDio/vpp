package main

import (
	"os"
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

func (s *NoTopoSuite) TestNginx() {
	query := "return_ok"
	finished := make(chan error, 1)
	vppCont := s.getContainerByName("vpp")
	vppInst := NewVppInstance(vppCont)
	vppInst.actionFuncName = "ConfigureTap"
	s.assertNil(vppInst.start(), "failed to start vpp")

	nginxCont := s.getContainerByName("nginx")
	s.assertNil(nginxCont.run())

	time.Sleep(3 * time.Second)

	defer func() { os.Remove(query) }()
	go startWget(finished, "10.10.10.1", "80", query, "")
	s.assertNil(<-finished)
}
