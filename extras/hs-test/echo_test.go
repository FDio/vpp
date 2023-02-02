package main

func (s *VethsSuite) TestEchoBuiltin() {
	serverVpp := s.getContainerByName("server-vpp").vppInstance
	serverVeth := s.netInterfaces["vppsrv"]

	serverVpp.vppctl("test echo server " +
		" private-segment-size 1g fifo-size 4 no-echo" +
		" uri tcp://" + serverVeth.AddressString() + "/1234")

	clientVpp := s.getContainerByName("client-vpp").vppInstance

	o := clientVpp.vppctl("test echo client nclients 10000 bytes 1" +
		" syn-timeout 100 test-timeout 100 no-return private-segment-size 1g" +
		" fifo-size 4 uri tcp://" + serverVeth.AddressString() + "/1234")
	s.log(o)
}
