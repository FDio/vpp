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
