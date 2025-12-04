package main

import . "fd.io/hs-test/infra"

func init() {
	RegisterVethTests(VppEchoQuicTest, VppEchoTcpTest)
}

func VppEchoQuicTest(s *VethsSuite) {
	s.Skip("temp skip (broken?)")
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
	serverVethAddress := s.Interfaces.Server.Ip4AddressString()
	uri := proto + "://" + serverVethAddress + "/" + s.Ports.Port1

	serverCommand := "vpp_echo server TX=RX" +
		" socket-name " + s.Containers.ServerApp.GetContainerWorkDir() + "/var/run/app_ns_sockets/default" +
		" use-app-socket-api" +
		" uri " + uri
	s.Log(serverCommand)
	s.Containers.ServerApp.ExecServer(true, serverCommand)

	clientCommand := "vpp_echo client" +
		" socket-name " + s.Containers.ClientApp.GetContainerWorkDir() + "/var/run/app_ns_sockets/default" +
		" use-app-socket-api uri " + uri
	s.Log(clientCommand)
	o, err := s.Containers.ClientApp.Exec(true, clientCommand)
	s.AssertNil(err)
	s.Log(o)
}
