package main

import (
	. "fd.io/hs-test/infra"
	"fmt"
	"github.com/edwarnicke/exechelper"
	. "github.com/onsi/ginkgo/v2"
	"os"
)

func init() {
	RegisterNsTests(VppProxyHttpTcpTest, VppProxyHttpTlsTest, EnvoyProxyHttpTcpTest)
}

func testProxyHttpTcp(s *NsSuite, proto string) error {
	var outputFile string = s.ProcessIndex + "test" + s.Ppid + ".data"
	var srcFilePpid string = s.ProcessIndex + "httpTestFile" + s.Ppid
	const srcFileNoPpid = "httpTestFile"
	const fileSize string = "10M"
	stopServer := make(chan struct{}, 1)
	serverRunning := make(chan struct{}, 1)
	serverNetns := s.GetNetNamespaceByName("srv")
	clientNetns := s.GetNetNamespaceByName("cln")

	// create test file
	err := exechelper.Run(fmt.Sprintf("ip netns exec %s truncate -s %s %s", serverNetns, fileSize, srcFilePpid))
	s.AssertNil(err, "failed to run truncate command: "+fmt.Sprint(err))
	defer func() { os.Remove(srcFilePpid) }()

	s.Log("test file created...")

	go func() {
		defer GinkgoRecover()
		s.StartHttpServer(serverRunning, stopServer, ":666", serverNetns)
	}()
	// TODO better error handling and recovery
	<-serverRunning

	defer func(chan struct{}) {
		stopServer <- struct{}{}
	}(stopServer)

	s.Log("http server started...")

	clientVeth := s.GetInterfaceByName(ClientInterface)
	c := fmt.Sprintf("ip netns exec %s wget --no-proxy --retry-connrefused"+
		" --retry-on-http-error=503 --tries=10 -O %s ", clientNetns, outputFile)
	if proto == "tls" {
		c += " --secure-protocol=TLSv1_3 --no-check-certificate https://"
	}
	c += fmt.Sprintf("%s:555/%s", clientVeth.Ip4AddressString(), srcFileNoPpid)
	s.Log(c)
	_, err = exechelper.CombinedOutput(c)

	defer func() { os.Remove(outputFile) }()

	s.AssertNil(err, "failed to run wget: '%s', cmd: %s", err, c)
	stopServer <- struct{}{}

	s.AssertNil(AssertFileSize(outputFile, srcFilePpid))
	return nil
}

func configureVppProxy(s *NsSuite, proto string) {
	serverVeth := s.GetInterfaceByName(ServerInterface)
	clientVeth := s.GetInterfaceByName(ClientInterface)

	testVppProxy := s.GetContainerByName("vpp").VppInstance
	output := testVppProxy.Vppctl(
		"test proxy server server-uri %s://%s/555 client-uri tcp://%s/666",
		proto,
		clientVeth.Ip4AddressString(),
		serverVeth.Peer.Ip4AddressString(),
	)
	s.Log("proxy configured: " + output)
}

func VppProxyHttpTcpTest(s *NsSuite) {
	proto := "tcp"
	configureVppProxy(s, proto)
	err := testProxyHttpTcp(s, proto)
	s.AssertNil(err, fmt.Sprint(err))
}

func VppProxyHttpTlsTest(s *NsSuite) {
	proto := "tls"
	configureVppProxy(s, proto)
	err := testProxyHttpTcp(s, proto)
	s.AssertNil(err, fmt.Sprint(err))
}

func configureEnvoyProxy(s *NsSuite) {
	envoyContainer := s.GetContainerByName("envoy")
	s.AssertNil(envoyContainer.Create())

	serverVeth := s.GetInterfaceByName(ServerInterface)
	address := struct {
		Server string
	}{
		Server: serverVeth.Peer.Ip4AddressString(),
	}
	envoyContainer.CreateConfig(
		"/etc/envoy/envoy.yaml",
		"resources/envoy/proxy.yaml",
		address,
	)
	s.AssertNil(envoyContainer.Start())
}

func EnvoyProxyHttpTcpTest(s *NsSuite) {
	configureEnvoyProxy(s)
	err := testProxyHttpTcp(s, "tcp")
	s.AssertNil(err, fmt.Sprint(err))
}
