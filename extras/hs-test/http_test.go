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

	srvInstance := "http-cli-srv"
	clnInstance := "http-cli-cln"
	s.assertNil(dockerRun(srvInstance, ""), "failed to start docker (srv)")
	defer func() { exechelper.Run("docker stop " + srvInstance) }()

	s.assertNil(dockerRun(clnInstance, ""), "failed to start docker (cln)")
	defer func() { exechelper.Run("docker stop " + clnInstance) }()

	_, err := hstExec("Configure2Veths srv", srvInstance)
	s.assertNil(err)

	_, err = hstExec("Configure2Veths cln", clnInstance)
	s.assertNil(err)

	t.Log("configured IPs...")

	_, err = hstExec("RunHttpCliSrv", srvInstance)
	s.assertNil(err)

	t.Log("configured http server")

	o, err := hstExec("RunHttpCliCln /show/version", clnInstance)
	s.assertNil(err)

	s.assertContains(o, "<html>", "<html> not found in the result!")
}
