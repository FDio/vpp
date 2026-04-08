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
	"reflect"
	"runtime"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
)

var vethTests = map[string][]func(s *VethsSuite){}
var vethSoloTests = map[string][]func(s *VethsSuite){}
var vethMWTests = map[string][]func(s *VethsSuite){}

type VethsSuite struct {
	HstSuite
	Interfaces struct {
		Server *NetInterface
		Client *NetInterface
	}
	Containers struct {
		ServerVpp *Container
		ClientVpp *Container
		ServerApp *Container
		ClientApp *Container
	}
	Ports struct {
		Port1 string
		Port2 string
	}
}

func RegisterVethTests(tests ...func(s *VethsSuite)) {
	vethTests[GetTestFilename()] = tests
}
func RegisterSoloVethTests(tests ...func(s *VethsSuite)) {
	vethSoloTests[GetTestFilename()] = tests
}
func RegisterVethMWTests(tests ...func(s *VethsSuite)) {
	vethMWTests[GetTestFilename()] = tests
}

type TlsCrlTestArtifacts struct {
	ServerCert string
	ServerKey  string
	CaCert     string
	Crl        string
}

func (s *VethsSuite) CreateTlsCrlTestArtifacts(name string) TlsCrlTestArtifacts {
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
	a := TlsCrlTestArtifacts{
		ServerCert: baseDir + "/server.crt",
		ServerKey:  baseDir + "/server.key",
		CaCert:     baseDir + "/ca.crt",
		Crl:        baseDir + "/ca.crl",
	}

	containers := []*Container{s.Containers.ServerVpp, s.Containers.ClientVpp}
	for _, c := range containers {
		tlsCrlWriteFile(c, a.ServerCert, serverCertPem)
		tlsCrlWriteFile(c, a.ServerKey, serverKeyPem)
		tlsCrlWriteFile(c, a.CaCert, caCertPem)
		tlsCrlWriteFile(c, a.Crl, crlPem)
	}

	return a
}

func (s *VethsSuite) SetupSuite() {
	time.Sleep(1 * time.Second)
	s.HstSuite.SetupSuite()
	s.ConfigureNetworkTopology("2peerVeth")
	s.LoadContainerTopology("2peerVeth")
	s.Interfaces.Client = s.GetInterfaceByName("cln")
	s.Interfaces.Server = s.GetInterfaceByName("srv")
	s.Containers.ServerVpp = s.GetContainerByName("server-vpp")
	s.Containers.ClientVpp = s.GetContainerByName("client-vpp")
	s.Containers.ServerApp = s.GetContainerByName("server-app")
	s.Containers.ClientApp = s.GetContainerByName("client-app")
	s.Ports.Port1 = s.GeneratePort()
	s.Ports.Port2 = s.GeneratePort()
}

func (s *VethsSuite) SetupTest(startupConf ...Stanza) {
	s.HstSuite.SetupTest()

	var customStartupConf1 Stanza
	var customStartupConf2 Stanza
	if len(startupConf) > 0 {
		customStartupConf1 = startupConf[0]
		if len(startupConf) > 1 {
			customStartupConf2 = startupConf[1]
		}
	}

	// Setup test conditions
	var sessionConfig Stanza
	sessionConfig.
		NewStanza("session").
		Append("enable").
		Append("use-app-socket-api").
		Append("event-queue-length 100000")

	if strings.Contains(CurrentSpecReport().LeafNodeText, "InterruptMode") {
		sessionConfig.Append("use-private-rx-mqs").Close()
		Log("**********************INTERRUPT MODE**********************")
	} else {
		sessionConfig.Close()
	}
	// For http/2 continuation frame test between http tps and http client
	var httpConfig Stanza
	httpConfig.NewStanza("http").NewStanza("http2").Append("max-header-list-size 65536").Close().Close()

	// ... For server
	serverVpp, err := s.Containers.ServerVpp.newVppInstance(s.Containers.ServerVpp.AllocatedCpus, sessionConfig, customStartupConf1, customStartupConf2)
	AssertNotNil(serverVpp, fmt.Sprint(err))

	// ... For client
	clientVpp, err := s.Containers.ClientVpp.newVppInstance(s.Containers.ClientVpp.AllocatedCpus, sessionConfig, httpConfig, customStartupConf1, customStartupConf2)
	AssertNotNil(clientVpp, fmt.Sprint(err))

	s.SetupServerVpp()
	s.SetupClientVpp()
	if *DryRun {
		s.LogStartedContainers()
		s.Skip("Dry run mode = true")
	}
}

func (s *VethsSuite) TeardownTest() {
	defer s.HstSuite.TeardownTest()
	clientVpp := s.Containers.ClientVpp.VppInstance
	serverVpp := s.Containers.ServerVpp.VppInstance
	if CurrentSpecReport().Failed() {
		CollectVclTestSrvLogs(s.Containers.ServerApp)
		CollectVclTestClnLogs(s.Containers.ClientApp)
		Log(clientVpp.Vppctl("show session verbose 2"))
		Log(clientVpp.Vppctl("show error"))
		Log(serverVpp.Vppctl("show session verbose 2"))
		Log(serverVpp.Vppctl("show error"))
	}
}

func (s *VethsSuite) SetupServerVpp() {
	serverVpp := s.Containers.ServerVpp.VppInstance
	AssertNil(serverVpp.Start())

	numCpus := uint16(len(serverVpp.Container.AllocatedCpus))
	numWorkers := uint16(max(numCpus-1, 1))
	idx, err := serverVpp.createAfPacket(s.Interfaces.Server, false, WithNumRxQueues(numWorkers), WithNumTxQueues(numCpus))
	AssertNil(err, fmt.Sprint(err))
	AssertNotEqual(0, idx)
}

func (s *VethsSuite) SetupClientVpp() {
	clientVpp := s.Containers.ClientVpp.VppInstance
	AssertNil(clientVpp.Start())

	numCpus := uint16(len(clientVpp.Container.AllocatedCpus))
	numWorkers := uint16(max(numCpus-1, 1))
	idx, err := clientVpp.createAfPacket(s.Interfaces.Client, false, WithNumRxQueues(numWorkers), WithNumTxQueues(numCpus))
	AssertNil(err, fmt.Sprint(err))
	AssertNotEqual(0, idx)
}

func (s *VethsSuite) SetupAppContainers() {
	s.Containers.ClientApp.Run()
	s.Containers.ServerApp.Run()
}

var _ = Describe("VethsSuite", Ordered, ContinueOnFailure, Label("Veth"), func() {
	var s VethsSuite
	BeforeAll(func() {
		s.SetupSuite()
	})
	BeforeEach(func() {
		s.SetupTest()
	})
	AfterAll(func() {
		s.TeardownSuite()

	})
	AfterEach(func() {
		s.TeardownTest()
	})

	// https://onsi.github.io/ginkgo/#dynamically-generating-specs
	for filename, tests := range vethTests {
		for _, test := range tests {
			test := test
			pc := reflect.ValueOf(test).Pointer()
			funcValue := runtime.FuncForPC(pc)
			testName := filename + "/" + strings.Split(funcValue.Name(), ".")[2]
			It(testName, func(ctx SpecContext) {
				Log("[* TEST BEGIN]: " + testName)
				test(&s)
			}, SpecTimeout(TestTimeout))
		}
	}
})

var _ = Describe("VethsSuiteSolo", Ordered, ContinueOnFailure, Serial, Label("Veth"), func() {
	var s VethsSuite
	BeforeAll(func() {
		s.SetupSuite()
	})
	BeforeEach(func() {
		s.SetupTest()
	})
	AfterAll(func() {
		s.TeardownSuite()
	})
	AfterEach(func() {
		s.TeardownTest()
	})

	// https://onsi.github.io/ginkgo/#dynamically-generating-specs
	for filename, tests := range vethSoloTests {
		for _, test := range tests {
			test := test
			pc := reflect.ValueOf(test).Pointer()
			funcValue := runtime.FuncForPC(pc)
			testName := filename + "/" + strings.Split(funcValue.Name(), ".")[2]
			It(testName, func(ctx SpecContext) {
				Log("[* TEST BEGIN]: " + testName)
				test(&s)
			}, SpecTimeout(TestTimeout))
		}
	}
})

var _ = Describe("VethsSuiteMW", Ordered, ContinueOnFailure, Serial, Label("Veth", "MW"), func() {
	var s VethsSuite
	BeforeAll(func() {
		s.SetupSuite()
	})
	BeforeEach(func() {
		s.SkipIfNotEnoughCpus = true
	})
	AfterAll(func() {
		s.TeardownSuite()
	})
	AfterEach(func() {
		s.TeardownTest()
	})

	// https://onsi.github.io/ginkgo/#dynamically-generating-specs
	for filename, tests := range vethMWTests {
		for _, test := range tests {
			test := test
			pc := reflect.ValueOf(test).Pointer()
			funcValue := runtime.FuncForPC(pc)
			testName := filename + "/" + strings.Split(funcValue.Name(), ".")[2]
			It(testName, Label("SOLO", "VPP Multi-Worker"), func(ctx SpecContext) {
				Log("[* TEST BEGIN]: " + testName)
				test(&s)
			}, SpecTimeout(TestTimeout))
		}
	}
})
