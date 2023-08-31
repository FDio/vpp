package main

func (s *VethsSuite) TestVppEchoQuic() {
	s.Skip("quic test skipping..")
	s.testVppEcho("quic")
}

func (s *VethsSuite) TestVppEchoUdp() {
	s.Skip("udp echo currently broken in vpp, skipping..")
	s.testVppEcho("udp")
}

func (s *VethsSuite) TestVppEchoTcp() {
	s.testVppEcho("tcp")
}

func (s *VethsSuite) testVppEcho(proto string) {
	serverVethAddress := s.netInterfaces["vppsrv"].Ip4AddressString()
	uri := proto + "://" + serverVethAddress + "/12344"

	echoSrvContainer := s.GetContainerByName("server-app")
	serverCommand := "vpp_echo server TX=RX" +
		" socket-name " + echoSrvContainer.GetContainerWorkDir() + "/var/run/app_ns_sockets/1" +
		" use-app-socket-api" +
		" uri " + uri
	s.Log(serverCommand)
	echoSrvContainer.ExecServer(serverCommand)

	echoClnContainer := s.GetContainerByName("client-app")

	clientCommand := "vpp_echo client" +
		" socket-name " + echoClnContainer.GetContainerWorkDir() + "/var/run/app_ns_sockets/2" +
		" use-app-socket-api uri " + uri
	s.Log(clientCommand)
	o := echoClnContainer.Exec(clientCommand)
	s.Log(o)
}
