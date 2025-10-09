package main

import (
	. "fd.io/hs-test/infra"
)

func init() {
	RegisterVethTests(QuicAlpnMatchTest, QuicAlpnOverlapMatchTest, QuicAlpnServerPriorityMatchTest, QuicAlpnMismatchTest, QuicAlpnEmptyServerListTest, QuicAlpnEmptyClientListTest)
}

func QuicAlpnMatchTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	s.Log(s.Containers.ServerVpp.VppInstance.Vppctl("test alpn server alpn-proto1 3 uri quic://" + serverAddress))

	uri := "quic://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test alpn client alpn-proto1 3 uri " + uri)
	s.Log(o)
	s.AssertNotContains(o, "connect failed")
	s.AssertNotContains(o, "timeout")
	// selected based on 1:1 match
	s.AssertContains(o, "ALPN selected: h3")
}

func QuicAlpnOverlapMatchTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	s.Log(s.Containers.ServerVpp.VppInstance.Vppctl("test alpn server alpn-proto1 3 alpn-proto2 1 uri quic://" + serverAddress))

	uri := "quic://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test alpn client alpn-proto1 2 alpn-proto2 3 uri " + uri)
	s.Log(o)
	s.AssertNotContains(o, "connect failed")
	s.AssertNotContains(o, "timeout")
	// selected based on overlap
	s.AssertContains(o, "ALPN selected: h3")
}

func QuicAlpnServerPriorityMatchTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	s.Log(s.Containers.ServerVpp.VppInstance.Vppctl("test alpn server alpn-proto1 3 alpn-proto2 1 uri quic://" + serverAddress))

	uri := "quic://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test alpn client alpn-proto1 1 alpn-proto2 3 uri " + uri)
	s.Log(o)
	s.AssertNotContains(o, "connect failed")
	s.AssertNotContains(o, "timeout")
	// selected based on server priority
	s.AssertContains(o, "ALPN selected: h3")
}

func QuicAlpnMismatchTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	s.Log(serverVpp.Vppctl("test alpn server alpn-proto1 2 alpn-proto2 1 uri quic://" + serverAddress))

	uri := "quic://" + serverAddress
	o := clientVpp.Vppctl("test alpn client alpn-proto1 3 alpn-proto2 4 uri " + uri)
	s.Log(o)
	s.AssertNotContains(o, "timeout")
	s.AssertNotContains(o, "ALPN selected")
	// connection refused on mismatch
	s.AssertContains(o, "connect error failed tls handshake")
	// check if everything is cleanup
	// server should have only 2 listener sessions (udp and quic) and app no accepted connection
	o = serverVpp.Vppctl("show test alpn server")
	s.Log(o)
	s.AssertContains(o, "accepted connections 0")
	o = serverVpp.Vppctl("show session verbose 2")
	s.Log(o)
	s.AssertContains(o, "active sessions 2")
	// no session on client
	o = clientVpp.Vppctl("show session verbose 2")
	s.Log(o)
	s.AssertContains(o, "no sessions")
}

func QuicAlpnEmptyServerListTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	s.Log(s.Containers.ServerVpp.VppInstance.Vppctl("test alpn server uri quic://" + serverAddress))

	uri := "quic://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test alpn client alpn-proto1 3 alpn-proto2 2 uri " + uri)
	s.Log(o)
	s.AssertNotContains(o, "connect failed")
	s.AssertNotContains(o, "timeout")
	// no alpn negotiation
	s.AssertContains(o, "ALPN selected: none")
}

func QuicAlpnEmptyClientListTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	s.Log(s.Containers.ServerVpp.VppInstance.Vppctl("test alpn server alpn-proto1 3 alpn-proto2 1 uri quic://" + serverAddress))

	uri := "quic://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test alpn client uri " + uri)
	s.Log(o)
	s.AssertNotContains(o, "connect failed")
	s.AssertNotContains(o, "timeout")
	// no alpn negotiation
	s.AssertContains(o, "ALPN selected: none")
}
