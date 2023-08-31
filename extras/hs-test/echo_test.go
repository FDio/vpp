package main

func (s *VethsSuite) TestEchoBuiltin() {
	serverVpp := s.GetContainerByName("server-vpp").vppInstance
	serverVeth := s.netInterfaces["vppsrv"]

	serverVpp.Vppctl("test echo server " +
		" private-segment-size 1g fifo-size 4 no-echo" +
		" uri tcp://" + serverVeth.Ip4AddressString() + "/1234")

	clientVpp := s.GetContainerByName("client-vpp").vppInstance

	o := clientVpp.Vppctl("test echo client nclients 10000 bytes 1" +
		" syn-timeout 100 test-timeout 100 no-return private-segment-size 1g" +
		" fifo-size 4 uri tcp://" + serverVeth.Ip4AddressString() + "/1234")
	s.Log(o)
}
