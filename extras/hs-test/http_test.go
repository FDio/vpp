package main

func (s *NsSuite) TestHttpTps() {
	t := s.T()
	finished := make(chan error, 1)
	server_ip := "10.0.0.2"
	port := "8080"

	container := s.getContainerByName("vpp")

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

	serverContainer := s.getContainerByName("server-vpp")
	clientContainer := s.getContainerByName("client-vpp")

	_, err := serverContainer.execAction("Configure2Veths srv")
	s.assertNil(err)

	_, err = clientContainer.execAction("Configure2Veths cln")
	s.assertNil(err)

	t.Log("configured IPs...")

	_, err = serverContainer.execAction("RunHttpCliSrv")
	s.assertNil(err)

	t.Log("configured http server")

	o, err := clientContainer.execAction("RunHttpCliCln /show/version")
	s.assertNil(err)

	s.assertContains(o, "<html>", "<html> not found in the result!")
}
