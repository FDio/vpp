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
		QuicAlpnEmptyServerListTest, QuicAlpnEmptyClientListTest, QuicBuiltinEchoTest, QuicCpsTest,
		QuicBuiltinEchoBidirectionalTest, QuicBuiltinEchoTestBytesTest, QuicBuiltinEchoTestBytesBidirectionalTest,
		QuicReorderTest, QuicCrlRejectThenAllowTest)
	RegisterNoTopoTests(QuicFailedHandshakeTest)
}

func QuicCrlRejectThenAllowTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	a := createTlsCrlTestArtifacts(s, "quic")

	Log(serverVpp.Vppctl("test tls server cert " + a.serverCert + " key " + a.serverKey + " uri quic://" + serverAddress))

	uri := "quic://" + serverAddress
	o := clientVpp.Vppctl("test tls client verify peer ca-cert " + a.caCert + " crl " + a.crl + " uri " + uri)
	Log(o)
	AssertContains(o, "connect error failed tls handshake")

	o = serverVpp.Vppctl("show test tls server")
	Log(o)
	AssertContains(o, "accepted connections 0")

	o = clientVpp.Vppctl("test tls client verify peer ca-cert " + a.caCert + " uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	AssertNotContains(o, "failed tls handshake")

	o = serverVpp.Vppctl("show test tls server")
	Log(o)
	AssertContains(o, "accepted connections 1")
}

func QuicAlpnMatchTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("test tls server alpn-proto1 3 uri quic://" + serverAddress))

	uri := "quic://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test tls client alpn-proto1 3 uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	// selected based on 1:1 match
	AssertContains(o, "ALPN selected: h3")
}

func QuicAlpnOverlapMatchTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("test tls server alpn-proto1 3 alpn-proto2 1 uri quic://" + serverAddress))

	uri := "quic://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test tls client alpn-proto1 2 alpn-proto2 3 uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	// selected based on overlap
	AssertContains(o, "ALPN selected: h3")
}

func QuicAlpnServerPriorityMatchTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("test tls server alpn-proto1 3 alpn-proto2 1 uri quic://" + serverAddress))

	uri := "quic://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test tls client alpn-proto1 1 alpn-proto2 3 uri " + uri)
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
	Log(serverVpp.Vppctl("test tls server alpn-proto1 2 alpn-proto2 1 uri quic://" + serverAddress))

	uri := "quic://" + serverAddress
	o := clientVpp.Vppctl("test tls client alpn-proto1 3 alpn-proto2 4 uri " + uri)
	Log(o)
	AssertNotContains(o, "timeout")
	AssertNotContains(o, "ALPN selected")
	// connection refused on mismatch
	AssertContains(o, "connect error failed tls handshake")
	// check if everything is cleanup
	// server should have only 2 listener sessions (udp and quic) and app no accepted connection
	o = serverVpp.Vppctl("show test tls server")
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
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("test tls server uri quic://" + serverAddress))

	uri := "quic://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test tls client alpn-proto1 3 alpn-proto2 2 uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	// no alpn negotiation
	AssertContains(o, "ALPN selected: none")
}

func QuicAlpnEmptyClientListTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("test tls server alpn-proto1 3 alpn-proto2 1 uri quic://" + serverAddress))

	uri := "quic://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test tls client uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	// no alpn negotiation
	AssertContains(o, "ALPN selected: none")
}

func QuicFailedHandshakeTest(s *NoTopoSuite) {
	serverAddress := s.Interfaces.Tap.Ip4AddressString() + ":" + s.Ports.Http
	Log(s.Containers.Vpp.VppInstance.Vppctl("test tls server uri quic://" + serverAddress))

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

func quicBuiltinEcho(s *VethsSuite, uni bool) {
	expr := `(\d+\.\d)-(\d+.\d)\s+(\d+\.\d+)[KMG]\s+0\s+\d+\.\d+[KMG]b/s\s+(\d?\.\d+)ms`
	if uni {
		expr = `(\d+\.\d)-(\d+.\d)\s+(\d+\.\d+)[KMG]\s+(\d+\.\d+)[KMG]\s+\d+\.\d+[KMG]b/s\s+(\d?\.\d+)ms`
	}
	regex := regexp.MustCompile(expr)
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	Log(serverVpp.Vppctl("test echo server " +
		" uri quic://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1))

	cmd := "test echo client run-time 30 report-interval "
	if uni {
		cmd += "echo-bytes "
	}
	cmd += "uri quic://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1

	o := clientVpp.Vppctl(cmd)
	Log(o)
	if regex.MatchString(o) {
		matches := regex.FindAllStringSubmatch(o, -1)
		// check if all intervals have non-zero TX bytes
		AssertEqual(30, len(matches))
	} else {
		AssertEmpty("invalid echo test client output")
	}
}

func QuicBuiltinEchoTest(s *VethsSuite) {
	quicBuiltinEcho(s, false)
}

func QuicBuiltinEchoBidirectionalTest(s *VethsSuite) {
	quicBuiltinEcho(s, true)
}

func QuicBuiltinEchoTestBytesTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	Log(serverVpp.Vppctl("test echo server " +
		" uri quic://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1))

	cmd := "test echo client test-bytes bytes 8388601 "
	cmd += "uri quic://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1

	o := clientVpp.Vppctl(cmd)
	Log(o)
	AssertNotContains(o, "failed")
}

func QuicBuiltinEchoTestBytesBidirectionalTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	Log(serverVpp.Vppctl("test echo server " +
		" uri quic://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1))

	cmd := "test echo client echo-bytes test-bytes bytes 8388608 "
	cmd += "uri quic://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1

	o := clientVpp.Vppctl(cmd)
	Log(o)
	AssertNotContains(o, "failed")
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

func QuicReorderTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance
	clientVpp.Vppctl("set nsim poll-main-thread delay 0.1 ms bandwidth 10 gbps packet-size 1460 packets-per-drop 100 packets-per-reorder 5")
	clientVpp.Vppctl("nsim output-feature enable-disable " + s.Interfaces.Client.VppName())
	Log(clientVpp.Vppctl("show nsim"))

	serverVpp.Vppctl("set nsim poll-main-thread delay 0.1 ms bandwidth 10 gbps packet-size 1460 packets-per-drop 100 packets-per-reorder 5")
	serverVpp.Vppctl("nsim output-feature enable-disable " + s.Interfaces.Server.VppName())
	Log(serverVpp.Vppctl("show nsim"))

	quicBuiltinEcho(s, true)
	Log(serverVpp.Vppctl("show session verbose 2"))
	Log(clientVpp.Vppctl("show session verbose 2"))
	Log(serverVpp.Vppctl("show error"))
	Log(clientVpp.Vppctl("show error"))
}
