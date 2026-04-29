package main

import (
	. "fd.io/hs-test/infra"
)

type tlsTestEngine struct {
	cliArg string
}

var (
	tlsEnginePicotls = tlsTestEngine{cliArg: "tls-engine 2"}
)

func init() {
	RegisterTlsTests(TlsAlpMatchTest, TlsAlpnOverlapMatchTest, TlsAlpnServerPriorityMatchTest, TlsAlpnMismatchTest,
		TlsAlpnEmptyServerListTest, TlsAlpnEmptyClientListTest, TlsCrlRejectThenAllowTest,
		TlsPicotlsAlpnEmptyServerListTest, TlsPicotlsAlpnEmptyClientListTest)
}

func tlsCmd(cmd string, engine tlsTestEngine) string {
	if engine.cliArg == "" {
		return cmd
	}
	return cmd + " " + engine.cliArg
}

func TlsCrlRejectThenAllowTest(s *TlsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	a := s.CreateTlsCrlTestArtifacts("tls")

	Log(serverVpp.Vppctl("test tls server cert " + a.ServerCert + " key " + a.ServerKey + " uri tls://" + serverAddress))

	uri := "tls://" + serverAddress
	o := clientVpp.Vppctl("test tls client verify peer ca-cert " + a.CaCert + " crl " + a.Crl + " uri " + uri)
	Log(o)
	AssertContains(o, "connect error failed tls handshake")

	o = serverVpp.Vppctl("show test tls server")
	Log(o)
	AssertContains(o, "accepted connections 0")

	o = clientVpp.Vppctl("test tls client verify peer ca-cert " + a.CaCert + " uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	AssertNotContains(o, "failed tls handshake")

	o = serverVpp.Vppctl("show test tls server")
	Log(o)
	AssertContains(o, "accepted connections 1")
}

func TlsAlpMatchTest(s *TlsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("test tls server alpn-proto1 2 uri tls://" + serverAddress))

	uri := "tls://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test tls client alpn-proto1 2 uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	// selected based on 1:1 match
	AssertContains(o, "ALPN selected: h2")
}

func TlsAlpnOverlapMatchTest(s *TlsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("test tls server alpn-proto1 2 alpn-proto2 1 uri tls://" + serverAddress))

	uri := "tls://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test tls client alpn-proto1 3 alpn-proto2 2 uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	// selected based on overlap
	AssertContains(o, "ALPN selected: h2")
}

func TlsAlpnServerPriorityMatchTest(s *TlsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("test tls server alpn-proto1 2 alpn-proto2 1 uri tls://" + serverAddress))

	uri := "tls://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test tls client alpn-proto1 1 alpn-proto2 2 uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	// selected based on server priority
	AssertContains(o, "ALPN selected: h2")
}

func TlsAlpnMismatchTest(s *TlsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("test tls server alpn-proto1 2 alpn-proto2 1 uri tls://" + serverAddress))

	uri := "tls://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test tls client alpn-proto1 3 alpn-proto2 4 uri " + uri)
	Log(o)
	AssertNotContains(o, "timeout")
	AssertNotContains(o, "ALPN selected")
	// connection refused on mismatch
	AssertContains(o, "connect error failed tls handshake")
}

func TlsAlpnEmptyServerListTest(s *TlsSuite) {
	tlsAlpnEmptyServerListTest(s, tlsTestEngine{})
}

func TlsPicotlsAlpnEmptyServerListTest(s *TlsSuite) {
	tlsAlpnEmptyServerListTest(s, tlsEnginePicotls)
}

func tlsAlpnEmptyServerListTest(s *TlsSuite, engine tlsTestEngine) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(s.Containers.ServerVpp.VppInstance.Vppctl(tlsCmd("test tls server uri tls://"+serverAddress, engine)))

	uri := "tls://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl(tlsCmd("test tls client alpn-proto1 1 alpn-proto2 2 uri "+uri, engine))
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	// no alpn negotiation
	AssertContains(o, "ALPN selected: none")
}

func TlsAlpnEmptyClientListTest(s *TlsSuite) {
	tlsAlpnEmptyClientListTest(s, tlsTestEngine{})
}

func TlsPicotlsAlpnEmptyClientListTest(s *TlsSuite) {
	tlsAlpnEmptyClientListTest(s, tlsEnginePicotls)
}

func tlsAlpnEmptyClientListTest(s *TlsSuite, engine tlsTestEngine) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(s.Containers.ServerVpp.VppInstance.Vppctl(tlsCmd("test tls server alpn-proto1 2 alpn-proto2 1 uri tls://"+serverAddress, engine)))

	uri := "tls://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl(tlsCmd("test tls client uri "+uri, engine))
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	// no alpn negotiation
	AssertContains(o, "ALPN selected: none")
}
