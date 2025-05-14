package main

import (
	. "fd.io/hs-test/infra"
)

func init() {
	RegisterVethTests(TlsAlpnTest)
}

func TlsAlpnTest(s *VethsSuite) {
	s.Log(s.Containers.ServerVpp.VppInstance.Vppctl("test alpn server uri tls://0.0.0.0:123"))

	uri := "tls://" + s.Interfaces.Server.Ip4AddressString() + ":123"
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test alpn client uri " + uri)
	s.Log(o)
	s.AssertNotContains(o, "connect failed")
	s.AssertNotContains(o, "timeout")
	s.AssertContains(o, "ALPN selected h2")
}
