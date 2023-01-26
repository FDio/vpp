package main

func (s *VethsSuite) TestEchoBuiltin() {
	serverContainer := s.getContainerByName("server-vpp")
	_, err := serverContainer.execAction("Configure2Veths srv")
	s.assertNil(err)

	clientContainer := s.getContainerByName("client-vpp")
	_, err = clientContainer.execAction("Configure2Veths cln")
	s.assertNil(err)

	_, err = serverContainer.execAction("RunEchoSrvInternal private-segment-size 1g fifo-size 4 no-echo")
	s.assertNil(err)

	o, err := clientContainer.execAction("RunEchoClnInternal nclients 10000 bytes 1 syn-timeout 100 test-timeout 100 no-return private-segment-size 1g fifo-size 4")
	s.assertNil(err)
	s.log(o)
}

func (s *VethsSuite) TestEchoInternal() {
	var startupConfig Stanza
	startupConfig.
		NewStanza("session").
		Append("enable").
		Append("use-app-socket-api").Close()

	serverContainer := s.getContainerByName("server-vpp")

	serverVpp, _ := serverContainer.newVppInstance(startupConfig)
	s.assertNotNil(serverVpp)

	err := serverVpp.start()
	s.assertNil(err)

	// TODO replace netElement with actual implementation
	serverVeth := *s.netConfigs["vppsrv"]
	idx, err := serverVpp.createAfPacket(serverVeth)
	s.assertNil(err)
	s.assertNotEqual(0, idx)

	namespaceSecret := "1"
	err = serverVpp.addAppNamespace(1, idx, namespaceSecret)
	s.assertNil(err)

	//serverVpp.showVersion()

	// Client setup
	clientContainer := s.getContainerByName("client-vpp")

	clientVpp, _ := clientContainer.newVppInstance(startupConfig)
	s.assertNotNil(clientVpp)

	err = clientVpp.start()
	s.assertNil(err)

	clientVeth := *s.netConfigs["vppcln"]
	idx, err = clientVpp.createAfPacket(clientVeth)
	s.assertNil(err)
	s.assertNotEqual(0, idx)

	clientNamespaceSecret := "2"
	err = clientVpp.addAppNamespace(2, idx, clientNamespaceSecret)
	s.assertNil(err)

	_, err = serverContainer.execAction("RunEchoSrvInternal private-segment-size 1g fifo-size 4 no-echo")
	s.assertNil(err)

	//o, err := clientContainer.execAction("RunEchoClnInternal nclients 10000 bytes 1 syn-timeout 100 test-timeout 100 no-return private-segment-size 1g fifo-size 4")
	o, err := clientVpp.vppctl("test echo client nclients 10000 bytes 1 syn-timeout 100 test-timeout 100 no-return private-segment-size 1g fifo-size 4 uri tcp://10.10.10.1/1234")
	s.assertNil(err)
	s.log(o)
}
