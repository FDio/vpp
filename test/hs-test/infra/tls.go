package hst

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

type TlsCrlTestArtifacts struct {
	ServerCert string
	ServerKey  string
	CaCert     string
	Crl        string
}

func (s *HstSuite) CreateTlsCrlTestArtifacts(name, serverIP string, containers ...*Container) TlsCrlTestArtifacts {
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
	a := TlsCrlTestArtifacts{
		ServerCert: baseDir + "/server.crt",
		ServerKey:  baseDir + "/server.key",
		CaCert:     baseDir + "/ca.crt",
		Crl:        baseDir + "/ca.crl",
	}

	for _, c := range containers {
		tlsCrlWriteFile(c, a.ServerCert, serverCertPem)
		tlsCrlWriteFile(c, a.ServerKey, serverKeyPem)
		tlsCrlWriteFile(c, a.CaCert, caCertPem)
		tlsCrlWriteFile(c, a.Crl, crlPem)
	}

	return a
}
