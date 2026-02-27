package main

import (
	"context"
	"crypto/tls"
	"regexp"
	"time"

	. "fd.io/hs-test/infra"
	"github.com/quic-go/quic-go"
)

func init() {
	RegisterVethTests(QuicAlpnMatchTest, QuicAlpnOverlapMatchTest, QuicAlpnServerPriorityMatchTest, QuicAlpnMismatchTest,
		QuicAlpnEmptyServerListTest, QuicAlpnEmptyClientListTest, QuicBuiltinEchoTest, QuicCpsTest)
	RegisterNoTopoTests(QuicFailedHandshakeTest)
}

func QuicAlpnMatchTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("test alpn server alpn-proto1 3 uri quic://" + serverAddress))

	uri := "quic://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test alpn client alpn-proto1 3 uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	// selected based on 1:1 match
	AssertContains(o, "ALPN selected: h3")
}

func QuicAlpnOverlapMatchTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("test alpn server alpn-proto1 3 alpn-proto2 1 uri quic://" + serverAddress))

	uri := "quic://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test alpn client alpn-proto1 2 alpn-proto2 3 uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	// selected based on overlap
	AssertContains(o, "ALPN selected: h3")
}

func QuicAlpnServerPriorityMatchTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("test alpn server alpn-proto1 3 alpn-proto2 1 uri quic://" + serverAddress))

	uri := "quic://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test alpn client alpn-proto1 1 alpn-proto2 3 uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	// selected based on server priority
	AssertContains(o, "ALPN selected: h3")
}

func QuicAlpnMismatchTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(serverVpp.Vppctl("test alpn server alpn-proto1 2 alpn-proto2 1 uri quic://" + serverAddress))

	uri := "quic://" + serverAddress
	o := clientVpp.Vppctl("test alpn client alpn-proto1 3 alpn-proto2 4 uri " + uri)
	Log(o)
	AssertNotContains(o, "timeout")
	AssertNotContains(o, "ALPN selected")
	// connection refused on mismatch
	AssertContains(o, "connect error failed tls handshake")
	// check if everything is cleanup
	// server should have only 2 listener sessions (udp and quic) and app no accepted connection
	o = serverVpp.Vppctl("show test alpn server")
	Log(o)
	AssertContains(o, "accepted connections 0")
	o = serverVpp.Vppctl("show session verbose 2")
	Log(o)
	AssertContains(o, "active sessions 2")
	// no session on client
	o = clientVpp.Vppctl("show session verbose 2")
	Log(o)
	AssertContains(o, "no sessions")
}

func QuicAlpnEmptyServerListTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("test alpn server uri quic://" + serverAddress))

	uri := "quic://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test alpn client alpn-proto1 3 alpn-proto2 2 uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	// no alpn negotiation
	AssertContains(o, "ALPN selected: none")
}

func QuicAlpnEmptyClientListTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("test alpn server alpn-proto1 3 alpn-proto2 1 uri quic://" + serverAddress))

	uri := "quic://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test alpn client uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	// no alpn negotiation
	AssertContains(o, "ALPN selected: none")
}

func QuicFailedHandshakeTest(s *NoTopoSuite) {
	serverAddress := s.Interfaces.Tap.Ip4AddressString() + ":" + s.Ports.Http
	Log(s.Containers.Vpp.VppInstance.Vppctl("test alpn server uri quic://" + serverAddress))

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := quic.DialAddr(
		ctx,
		serverAddress,
		&tls.Config{InsecureSkipVerify: true, SessionTicketsDisabled: true},
		// set QUIC version 2 because we want failed accept
		&quic.Config{Versions: []quic.Version{quic.Version2}},
	)
	Log(err)
	// connect should fail (context deadline exceeded)
	AssertNotNil(err, "connect should failed")
	// expect only two sessions (UDP and QUIC listener)
	o := s.Containers.Vpp.VppInstance.Vppctl("show session verbose")
	Log(o)
	AssertContains(o, "active sessions 2", "expected only listeners")
}

func QuicBuiltinEchoTest(s *VethsSuite) {
	regex := regexp.MustCompile(`(\d+\.\d)-(\d+.\d)\s+(\d+\.\d+)[KMG]\s+0\s+\d+\.\d+[KMG]b/s\s+(\d?\.\d+)ms`)
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	Log(serverVpp.Vppctl("test echo server " +
		" uri quic://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1))

	o := clientVpp.Vppctl("test echo client run-time 30 report-interval " +
		" uri quic://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)
	Log(o)
	AssertContains(o, "Test started")
	AssertContains(o, "Test finished")
	if regex.MatchString(o) {
		matches := regex.FindAllStringSubmatch(o, -1)
		// check if all intervals have non-zero TX bytes
		AssertEqual(30, len(matches))
	} else {
		AssertEmpty("invalid echo test client output")
	}
}

func QuicCpsTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	Log(serverVpp.Vppctl("test echo server " +
		" uri quic://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1))

	// syn-timeout must be less than quic connection timeout (30 seconds)
	o := clientVpp.Vppctl("test echo client nclients 10000 bytes 64 syn-timeout 27" +
		" uri quic://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)
	Log(o)
	// wait a bit to be sure quic do not crash when app detached after syn-timeout
	time.Sleep(1 * time.Second)
	Log(serverVpp.Vppctl("show quic"))
	Log(clientVpp.Vppctl("show quic"))
	Log(serverVpp.Vppctl("show quic crypto context"))
	Log(clientVpp.Vppctl("show quic crypto context"))
}
