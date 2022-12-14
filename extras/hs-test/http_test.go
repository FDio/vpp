package main

func (s *NsSuite) TestHttpTps() {
	t := s.T()
	finished := make(chan error, 1)
	server_ip := "10.0.0.2"
	port := "8080"

	container := s.containers[0]

	t.Log("starting vpp..")

	// start & configure vpp in the container
	_, err := container.execAction("ConfigureHttpTps")
	s.assertNil(err)

	go startWget(finished, server_ip, port, "client")
	// wait for client
	err = <-finished
	s.assertNil(err)
}

func (s *VethsSuite) TestHttpCli() {
	t := s.T()

	serverVolume := s.volumes[0]
	clientVolume := s.volumes[1]
	serverContainer := s.containers[0]
	clientContainer := s.containers[1]

	_, err := serverContainer.useVolumeAsWorkDir(serverVolume).execAction("Configure2Veths srv")
	s.assertNil(err)

	_, err = clientContainer.useVolumeAsWorkDir(clientVolume).execAction("Configure2Veths cln")
	s.assertNil(err)

	t.Log("configured IPs...")

	_, err = serverContainer.useVolumeAsWorkDir(serverVolume).execAction("RunHttpCliSrv")
	s.assertNil(err)

	t.Log("configured http server")

	o, err := clientContainer.useVolumeAsWorkDir(clientVolume).execAction("RunHttpCliCln /show/version")
	s.assertNil(err)

	s.assertContains(o, "<html>", "<html> not found in the result!")
}
