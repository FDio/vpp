package main

func (s *VethsSuite) TestVppEchoQuic() {
	s.skip("quic test skipping..")
	s.testVppEcho("quic")
}

func (s *VethsSuite) TestVppEchoUdp() {
	s.skip("udp echo currently broken in vpp, skipping..")
	s.testVppEcho("udp")
}

func (s *VethsSuite) TestVppEchoTcp() {
	s.testVppEcho("tcp")
}

func (s *VethsSuite) testVppEcho(proto string) {
	serverVethAddress := s.netInterfaces["vppsrv"].ip4AddressString()
	uri := proto + "://" + serverVethAddress + "/12344"

	echoSrvContainer := s.getContainerByName("server-app")
	serverCommand := "vpp_echo server TX=RX" +
		" socket-name " + echoSrvContainer.getContainerWorkDir() + "/var/run/app_ns_sockets/default" +
		" use-app-socket-api" +
		" uri " + uri
	s.log(serverCommand)
	echoSrvContainer.execServer(serverCommand)

	echoClnContainer := s.getContainerByName("client-app")

	clientCommand := "vpp_echo client" +
		" socket-name " + echoClnContainer.getContainerWorkDir() + "/var/run/app_ns_sockets/default" +
		" use-app-socket-api uri " + uri
	s.log(clientCommand)
	o := echoClnContainer.exec(clientCommand)
	s.log(o)
}
