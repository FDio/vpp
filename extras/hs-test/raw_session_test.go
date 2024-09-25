package main

import . "fd.io/hs-test/infra"

func init() {
	RegisterVethTests(VppEchoQuicTest, VppEchoTcpTest)
}

func VppEchoQuicTest(s *VethsSuite) {
	testVppEcho(s, "quic")
}

// TODO: udp echo currently broken in vpp
func VppEchoUdpTest(s *VethsSuite) {
	testVppEcho(s, "udp")
}

func VppEchoTcpTest(s *VethsSuite) {
	testVppEcho(s, "tcp")
}

func testVppEcho(s *VethsSuite, proto string) {
	serverVethAddress := s.GetInterfaceByName(ServerInterfaceName).Ip4AddressString()
	uri := proto + "://" + serverVethAddress + "/12344"

	echoSrvContainer := s.GetContainerByName("server-app")
	serverCommand := "vpp_echo server TX=RX" +
		" socket-name " + echoSrvContainer.GetContainerWorkDir() + "/var/run/app_ns_sockets/default" +
		" use-app-socket-api" +
		" uri " + uri
	s.Log(serverCommand)
	echoSrvContainer.ExecServer(true, serverCommand)

	echoClnContainer := s.GetContainerByName("client-app")

	clientCommand := "vpp_echo client" +
		" socket-name " + echoClnContainer.GetContainerWorkDir() + "/var/run/app_ns_sockets/default" +
		" use-app-socket-api uri " + uri
	s.Log(clientCommand)
	o := echoClnContainer.Exec(true, clientCommand)
	s.Log(o)
}
