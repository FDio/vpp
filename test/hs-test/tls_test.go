package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"path/filepath"
	"time"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterVethTests(TlsAlpMatchTest, TlsAlpnOverlapMatchTest, TlsAlpnServerPriorityMatchTest, TlsAlpnMismatchTest,
		TlsAlpnEmptyServerListTest, TlsAlpnEmptyClientListTest, TlsCrlRejectThenAllowTest)
}

type tlsCrlTestArtifacts struct {
	serverCert string
	serverKey  string
	caCert     string
	crl        string
}

func tlsCrlWriteFile(c *Container, filePath, contents string) {
	_, err := c.Exec(false, "mkdir -p "+filepath.Dir(filePath))
	AssertNil(err)
	AssertNil(c.CreateFile(filePath, contents))
}

func createTlsCrlTestArtifacts(s *VethsSuite, name string) tlsCrlTestArtifacts {
	now := time.Now()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	AssertNil(err)

	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "hst-crl-root"},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caDer, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	AssertNil(err)
	caCert, err := x509.ParseCertificate(caDer)
	AssertNil(err)

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	AssertNil(err)
	serverIP := s.Interfaces.Server.Ip4AddressString()
	serverTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: serverIP},
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP(serverIP)},
		DNSNames:     []string{serverIP},
	}
	serverDer, err := x509.CreateCertificate(rand.Reader, serverTmpl, caCert, &serverKey.PublicKey, caKey)
	AssertNil(err)

	crlDer, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		SignatureAlgorithm: x509.SHA256WithRSA,
		Number:             big.NewInt(1),
		ThisUpdate:         now.Add(-1 * time.Minute),
		NextUpdate:         now.Add(1 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{
				SerialNumber:   serverTmpl.SerialNumber,
				RevocationTime: now.Add(-1 * time.Minute),
			},
		},
	}, caCert, caKey)
	AssertNil(err)

	serverKeyDer, err := x509.MarshalPKCS8PrivateKey(serverKey)
	AssertNil(err)

	serverCertPem := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDer}))
	serverKeyPem := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDer}))
	caCertPem := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDer}))
	crlPem := string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDer}))

	baseDir := fmt.Sprintf("/tmp/hst-tls-crl-%s-%s", s.GetTestId(), name)
	a := tlsCrlTestArtifacts{
		serverCert: baseDir + "/server.crt",
		serverKey:  baseDir + "/server.key",
		caCert:     baseDir + "/ca.crt",
		crl:        baseDir + "/ca.crl",
	}

	containers := []*Container{s.Containers.ServerVpp, s.Containers.ClientVpp}
	for _, c := range containers {
		tlsCrlWriteFile(c, a.serverCert, serverCertPem)
		tlsCrlWriteFile(c, a.serverKey, serverKeyPem)
		tlsCrlWriteFile(c, a.caCert, caCertPem)
		tlsCrlWriteFile(c, a.crl, crlPem)
	}

	return a
}

func TlsCrlRejectThenAllowTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	a := createTlsCrlTestArtifacts(s, "tls")

	Log(serverVpp.Vppctl("test tls server cert " + a.serverCert + " key " + a.serverKey + " uri tls://" + serverAddress))

	uri := "tls://" + serverAddress
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

func TlsAlpMatchTest(s *VethsSuite) {
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

func TlsAlpnOverlapMatchTest(s *VethsSuite) {
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

func TlsAlpnServerPriorityMatchTest(s *VethsSuite) {
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

func TlsAlpnMismatchTest(s *VethsSuite) {
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

func TlsAlpnEmptyServerListTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("test tls server uri tls://" + serverAddress))

	uri := "tls://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test tls client alpn-proto1 1 alpn-proto2 2 uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	// no alpn negotiation
	AssertContains(o, "ALPN selected: none")
}

func TlsAlpnEmptyClientListTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("test tls server alpn-proto1 2 alpn-proto2 1 uri tls://" + serverAddress))

	uri := "tls://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test tls client uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	// no alpn negotiation
	AssertContains(o, "ALPN selected: none")
}
