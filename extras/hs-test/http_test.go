package main

import (
	"strings"

	"github.com/edwarnicke/exechelper"
)

func (s *NsSuite) TestHttpTps() {
	t := s.T()
	finished := make(chan error, 1)
	server_ip := "10.0.0.2"
	port := "8080"
	dockerInstance := "http-tps"

	t.Log("starting vpp..")

	err := dockerRun(dockerInstance, "")
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer func() { exechelper.Run("docker stop " + dockerInstance) }()

	// start & configure vpp in the container
	_, err = hstExec("ConfigureHttpTps", dockerInstance)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	go startWget(finished, server_ip, port, "client")
	// wait for client
	err = <-finished
	if err != nil {
		t.Errorf("%v", err)
	}
}

func (s *Veths2Suite) TestHttpCli() {
	t := s.T()

	srvInstance := "http-cli-srv"
	clnInstance := "http-cli-cln"
	err := dockerRun(srvInstance, "")
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer func() { exechelper.Run("docker stop " + srvInstance) }()

	err = dockerRun(clnInstance, "")
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer func() { exechelper.Run("docker stop " + clnInstance) }()

	_, err = hstExec("2veths srv", srvInstance)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	_, err = hstExec("2veths cln", clnInstance)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	t.Log("configured IPs...")

	_, err = hstExec("http-cli-srv", srvInstance)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	t.Log("configured http server")

	o, err := hstExec("http-cli-cln /show/version", clnInstance)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	if strings.Index(o, "<html>") < 0 {
		t.Error("<html> not found in the result!")
	}
}
