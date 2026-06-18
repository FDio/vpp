package main

import (
	"errors"
	"io"
	"os"
	"time"

	. "fd.io/hs-test/infra"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
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
		TlsPicotlsAlpnEmptyServerListTest, TlsPicotlsAlpnEmptyClientListTest,
		TlsClientSessionResumeTest)
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

func TlsClientSessionResumeTest(s *TlsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1

	// Start TLS echo server
	Log(serverVpp.Vppctl("test tls server echo uri tls://" + serverAddress))

	// Enable session cache (disabled by default) on client
	o := clientVpp.Vppctl("tls openssl set-tls session-cache-size 128")
	Log(o)
	AssertContains(o, "TLS client session cache")
	AssertContains(o, "max-size 0 -> 128")

	// Enable pcap on client to capture handshake packets
	clientVpp.EnablePcapTrace()

	uri := "tls://" + serverAddress

	// First connection - full handshake with data exchange.
	// The echo round-trip ensures SSL_read processes the server's
	// TLS 1.3 NewSessionTicket, which triggers the new_session_cb
	// and caches the session for reuse.
	o = clientVpp.Vppctl("test tls client echo uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	AssertNotContains(o, "failed tls handshake")

	// Brief wait for connection teardown
	time.Sleep(500 * time.Millisecond)

	// Second connection - should use cached session ticket for resumption
	o = clientVpp.Vppctl("test tls client echo uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	AssertNotContains(o, "failed tls handshake")

	// Verify server accepted both connections
	o = serverVpp.Vppctl("show test tls server")
	Log(o)
	AssertContains(o, "accepted connections 2")

	// Collect pcap and verify session resumption via packet analysis
	clientVpp.CollectPcapTrace()

	// Read the pcap and find ClientHello packets (TLS content type 22,
	// handshake type 1). The second ClientHello should be larger because
	// it includes a pre_shared_key extension with the session ticket.
	pcapPath := LogDir + GetCurrentTestName() + "/" + s.GetTestId() + "/" +
		s.Containers.ClientVpp.Name + ".pcap"
	clientHellos, serverHellos, secondConnServerPkts := parseTlsHandshakePcap(pcapPath)

	// 1. Check ClientHello sizes: second must be larger (pre_shared_key extension)
	Log("Found %d ClientHello packets", len(clientHellos))
	AssertGreaterEqual(len(clientHellos), 2)
	Log("First ClientHello: %d bytes, Second ClientHello: %d bytes",
		clientHellos[0], clientHellos[1])
	AssertGreaterThan(clientHellos[1], clientHellos[0])

	// 2. Check ServerHello sizes: second must be smaller (no Certificate/CertificateVerify)
	Log("Found %d ServerHello packets", len(serverHellos))
	AssertGreaterEqual(len(serverHellos), 2)
	Log("First ServerHello: %d bytes, Second ServerHello: %d bytes",
		serverHellos[0], serverHellos[1])
	AssertGreaterThan(serverHellos[0], serverHellos[1])

	// 3. Verify no full handshake in second connection: the server should
	// send only one small TLS handshake packet (ServerHello+Finished) with
	// no additional encrypted handshake records (Certificate etc.)
	Log("Second connection server TLS packets: %d", secondConnServerPkts)
	AssertEqual(secondConnServerPkts, 1)

	// 4. Test runtime reduction of session cache size
	o = clientVpp.Vppctl("tls openssl set-tls session-cache-size 64")
	Log(o)
	AssertContains(o, "TLS client session cache")
	AssertContains(o, "max-size 128 -> 64")

	// 5. Disable session cache to exercise SSL_CTX teardown path
	o = clientVpp.Vppctl("tls openssl set-tls session-cache-size 0")
	Log(o)
	AssertContains(o, "TLS client session cache")
	AssertContains(o, "max-size 64 -> 0")
}

func parseTlsHandshakePcap(pcapPath string) (clientHellos []int, serverHellos []int, secondConnServerPkts int) {
	file, err := os.Open(pcapPath)
	if err != nil {
		Log("Failed to open pcap: %v", err)
		return
	}
	defer file.Close()

	reader, err := pcapgo.NewReader(file)
	if err != nil {
		Log("Failed to create pcap reader: %v", err)
		return
	}

	var clientIP string
	for {
		data, _, err := reader.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			break
		}

		packet := gopacket.NewPacket(data, reader.LinkType(), gopacket.NoCopy)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if tcpLayer == nil || ipLayer == nil {
			continue
		}
		tcp, _ := tcpLayer.(*layers.TCP)
		ip, _ := ipLayer.(*layers.IPv4)
		payload := tcp.LayerPayload()
		if len(payload) < 6 {
			continue
		}

		// TLS Handshake record: content_type=22 at byte 0
		if payload[0] != 22 {
			continue
		}

		// Handshake type at byte 5: 1=ClientHello, 2=ServerHello
		if payload[5] == 1 {
			clientHellos = append(clientHellos, len(data))
			clientIP = ip.SrcIP.String()
		} else if payload[5] == 2 {
			serverHellos = append(serverHellos, len(data))
		}

		// Count server TLS handshake packets in second connection
		// (after second ClientHello)
		if len(clientHellos) >= 2 && ip.SrcIP.String() != clientIP && payload[0] == 22 {
			secondConnServerPkts++
		}
	}
	return
}
