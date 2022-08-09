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

	err := dockerRun(dockerInstance, "")
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer func() { exechelper.Run("docker stop " + dockerInstance) }()

	// start & configure vpp in the container
	_, err = hstExec(dockerInstance, dockerInstance)
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
