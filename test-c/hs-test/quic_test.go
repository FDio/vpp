package main

import (
	. "fd.io/hs-test/infra"
)

func init() {
	RegisterVethTests(QuicAlpMatchTest, QuicAlpnOverlapMatchTest, QuicAlpnServerPriorityMatchTest, QuicAlpnMismatchTest, QuicAlpnEmptyServerListTest, QuicAlpnEmptyClientListTest)
}

func QuicAlpMatchTest(s *VethsSuite) {
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
	s.Skip("QUIC bug: handshake failure not reported to client app as connect error, skipping...")
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	s.Log(s.Containers.ServerVpp.VppInstance.Vppctl("test alpn server alpn-proto1 2 alpn-proto2 1 uri quic://" + serverAddress))

	uri := "quic://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test alpn client alpn-proto1 3 alpn-proto2 4 uri " + uri)
	s.Log(o)
	s.AssertNotContains(o, "timeout")
	s.AssertNotContains(o, "ALPN selected")
	// connection refused on mismatch
	s.AssertContains(o, "connect error failed quic handshake")
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
