package main

import (
	"github.com/edwarnicke/exechelper"
)

func (s *NsSuite) TestHttpTps() {
	t := s.T()
	finished := make(chan error, 1)
	server_ip := "10.0.0.2"
	port := "8080"
	dockerInstance := "http-tps"

	t.Log("starting vpp..")

	s.assertNil(dockerRun(dockerInstance, ""), "failed to start docker")
	defer func() { exechelper.Run("docker stop " + dockerInstance) }()

	// start & configure vpp in the container
	_, err := hstExec("ConfigureHttpTps", dockerInstance)
	s.assertNil(err)

	go startWget(finished, server_ip, port, "client")
	// wait for client
	err = <-finished
	s.assertNil(err)
}

func (s *VethsSuite) TestHttpCli() {
	t := s.T()

	srvInstance := s.GetContainers()[0]
	clnInstance := s.GetContainers()[1]

	_, err := hstExec("Configure2Veths srv", srvInstance.name)
	s.assertNil(err)

	_, err = hstExec("Configure2Veths cln", clnInstance.name)
	s.assertNil(err)

	t.Log("configured IPs...")

	_, err = hstExec("RunHttpCliSrv", srvInstance.name)
	s.assertNil(err)

	t.Log("configured http server")

	o, err := hstExec("RunHttpCliCln /show/version", clnInstance.name)
	s.assertNil(err)

	s.assertContains(o, "<html>", "<html> not found in the result!")
}
