package main

import (
	. "fd.io/hs-test/infra"
)

func init() {
	RegisterVethTests(TlsAlpMatchTest, TlsAlpnOverlapMatchTest, TlsAlpnServerPriorityMatchTest, TlsAlpnMismatchTest, TlsAlpnEmptyServerListTest, TlsAlpnEmptyClientListTest)
}

func TlsAlpMatchTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	s.Log(s.Containers.ServerVpp.VppInstance.Vppctl("test alpn server alpn-proto1 2 uri tls://" + serverAddress))

	uri := "tls://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test alpn client alpn-proto1 2 uri " + uri)
	s.Log(o)
	s.AssertNotContains(o, "connect failed")
	s.AssertNotContains(o, "timeout")
	// selected based on 1:1 match
	s.AssertContains(o, "ALPN selected: h2")
}

func TlsAlpnOverlapMatchTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	s.Log(s.Containers.ServerVpp.VppInstance.Vppctl("test alpn server alpn-proto1 2 alpn-proto2 1 uri tls://" + serverAddress))

	uri := "tls://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test alpn client alpn-proto1 3 alpn-proto2 2 uri " + uri)
	s.Log(o)
	s.AssertNotContains(o, "connect failed")
	s.AssertNotContains(o, "timeout")
	// selected based on overlap
	s.AssertContains(o, "ALPN selected: h2")
}

func TlsAlpnServerPriorityMatchTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	s.Log(s.Containers.ServerVpp.VppInstance.Vppctl("test alpn server alpn-proto1 2 alpn-proto2 1 uri tls://" + serverAddress))

	uri := "tls://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test alpn client alpn-proto1 1 alpn-proto2 2 uri " + uri)
	s.Log(o)
	s.AssertNotContains(o, "connect failed")
	s.AssertNotContains(o, "timeout")
	// selected based on server priority
	s.AssertContains(o, "ALPN selected: h2")
}

func TlsAlpnMismatchTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	s.Log(s.Containers.ServerVpp.VppInstance.Vppctl("test alpn server alpn-proto1 2 alpn-proto2 1 uri tls://" + serverAddress))

	uri := "tls://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test alpn client alpn-proto1 3 alpn-proto2 4 uri " + uri)
	s.Log(o)
	s.AssertNotContains(o, "timeout")
	s.AssertNotContains(o, "ALPN selected")
	// connection refused on mismatch
	s.AssertContains(o, "connect error failed tls handshake")
}

func TlsAlpnEmptyServerListTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	s.Log(s.Containers.ServerVpp.VppInstance.Vppctl("test alpn server uri tls://" + serverAddress))

	uri := "tls://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test alpn client alpn-proto1 1 alpn-proto2 2 uri " + uri)
	s.Log(o)
	s.AssertNotContains(o, "connect failed")
	s.AssertNotContains(o, "timeout")
	// no alpn negotiation
	s.AssertContains(o, "ALPN selected: none")
}

func TlsAlpnEmptyClientListTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	s.Log(s.Containers.ServerVpp.VppInstance.Vppctl("test alpn server alpn-proto1 2 alpn-proto2 1 uri tls://" + serverAddress))

	uri := "tls://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test alpn client uri " + uri)
	s.Log(o)
	s.AssertNotContains(o, "connect failed")
	s.AssertNotContains(o, "timeout")
	// no alpn negotiation
	s.AssertContains(o, "ALPN selected: none")
}
