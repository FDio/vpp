package main

import (
	"os"
	"time"
)

func (s *NsSuite) TestHttpTps() {
	finished := make(chan error, 1)
	server_ip := "10.0.0.2"
	port := "8080"

	container := s.getContainerByName("vpp")

	s.log("starting vpp..")

	// start & configure vpp in the container
	_, err := container.execAction("ConfigureHttpTps")
	s.assertNil(err)

	go startWget(finished, server_ip, port, "test_file_10M", "client")
	// wait for client
	err = <-finished
	s.assertNil(err)
}

func (s *VethsSuite) TestHttpCli() {
	serverContainer := s.getContainerByName("server-vpp")
	clientContainer := s.getContainerByName("client-vpp")

	_, err := serverContainer.execAction("Configure2Veths srv")
	s.assertNil(err)

	_, err = clientContainer.execAction("Configure2Veths cln")
	s.assertNil(err)

	s.log("configured IPs...")

	_, err = serverContainer.execAction("RunHttpCliSrv")
	s.assertNil(err)

	s.log("configured http server")

	o, err := clientContainer.execAction("RunHttpCliCln /show/version")
	s.assertNil(err)

	s.assertContains(o, "<html>", "<html> not found in the result!")
}

func (s *NoTopoSuite) TestNginx() {
	query := "return_ok"
	finished := make(chan error, 1)
	vppCont := s.getContainerByName("vpp")
	vppInst := NewVppInstance(vppCont)
	vppInst.actionFuncName = "ConfigureTap"
	s.assertNil(vppInst.start(), "failed to start vpp")

	_, err := vppCont.execAction("ConfigureTap")
	s.assertNil(err)

	nginxCont := s.getContainerByName("nginx")
	s.assertNil(nginxCont.run())

	time.Sleep(3 * time.Second)

	defer func() { os.Remove(query) }()
	go startWget(finished, "10.10.10.1", "80", query, "")
	err = <-finished
	s.assertNil(err)
}
