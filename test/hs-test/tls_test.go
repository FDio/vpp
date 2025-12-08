package main

import (
	. "fd.io/hs-test/infra"
)

func init() {
	RegisterVethTests(TlsAlpMatchTest, TlsAlpnOverlapMatchTest, TlsAlpnServerPriorityMatchTest, TlsAlpnMismatchTest, TlsAlpnEmptyServerListTest, TlsAlpnEmptyClientListTest)
}

func TlsAlpMatchTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("test alpn server alpn-proto1 2 uri tls://" + serverAddress))

	uri := "tls://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test alpn client alpn-proto1 2 uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	// selected based on 1:1 match
	AssertContains(o, "ALPN selected: h2")
}

func TlsAlpnOverlapMatchTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("test alpn server alpn-proto1 2 alpn-proto2 1 uri tls://" + serverAddress))

	uri := "tls://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test alpn client alpn-proto1 3 alpn-proto2 2 uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	// selected based on overlap
	AssertContains(o, "ALPN selected: h2")
}

func TlsAlpnServerPriorityMatchTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("test alpn server alpn-proto1 2 alpn-proto2 1 uri tls://" + serverAddress))

	uri := "tls://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test alpn client alpn-proto1 1 alpn-proto2 2 uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	// selected based on server priority
	AssertContains(o, "ALPN selected: h2")
}

func TlsAlpnMismatchTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("test alpn server alpn-proto1 2 alpn-proto2 1 uri tls://" + serverAddress))

	uri := "tls://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test alpn client alpn-proto1 3 alpn-proto2 4 uri " + uri)
	Log(o)
	AssertNotContains(o, "timeout")
	AssertNotContains(o, "ALPN selected")
	// connection refused on mismatch
	AssertContains(o, "connect error failed tls handshake")
}

func TlsAlpnEmptyServerListTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("test alpn server uri tls://" + serverAddress))

	uri := "tls://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test alpn client alpn-proto1 1 alpn-proto2 2 uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	// no alpn negotiation
	AssertContains(o, "ALPN selected: none")
}

func TlsAlpnEmptyClientListTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("test alpn server alpn-proto1 2 alpn-proto2 1 uri tls://" + serverAddress))

	uri := "tls://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test alpn client uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	// no alpn negotiation
	AssertContains(o, "ALPN selected: none")
}
