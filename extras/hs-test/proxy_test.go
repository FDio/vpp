package main

import (
	"fmt"
	"os"

	"github.com/edwarnicke/exechelper"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	registerNsTests(VppProxyHttpTcpTest, VppProxyHttpTlsTest, EnvoyProxyHttpTcpTest)
}

func testProxyHttpTcp(s *NsSuite, proto string) error {
	var outputFile string = "test" + s.pid + ".data"
	var srcFilePid string = "httpTestFile" + s.pid
	const srcFileNoPid = "httpTestFile"
	const fileSize string = "10M"
	stopServer := make(chan struct{}, 1)
	serverRunning := make(chan struct{}, 1)
	serverNetns := s.getNetNamespaceByName("srv")
	clientNetns := s.getNetNamespaceByName("cln")

	// create test file
	err := exechelper.Run(fmt.Sprintf("ip netns exec %s truncate -s %s %s", serverNetns, fileSize, srcFilePid))
	s.assertNil(err, "failed to run truncate command: "+fmt.Sprint(err))
	defer func() { os.Remove(srcFilePid) }()

	s.log("test file created...")

	go func() {
		defer GinkgoRecover()
		s.startHttpServer(serverRunning, stopServer, ":666", serverNetns)
	}()
	// TODO better error handling and recovery
	<-serverRunning

	defer func(chan struct{}) {
		stopServer <- struct{}{}
	}(stopServer)

	s.log("http server started...")

	clientVeth := s.getInterfaceByName(clientInterface)
	c := fmt.Sprintf("ip netns exec %s wget --no-proxy --retry-connrefused"+
		" --retry-on-http-error=503 --tries=10 -O %s ", clientNetns, outputFile)
	if proto == "tls" {
		c += " --secure-protocol=TLSv1_3 --no-check-certificate https://"
	}
	c += fmt.Sprintf("%s:555/%s", clientVeth.ip4AddressString(), srcFileNoPid)
	s.log(c)
	_, err = exechelper.CombinedOutput(c)

	defer func() { os.Remove(outputFile) }()

	s.assertNil(err, "failed to run wget: '%s', cmd: %s", err, c)
	stopServer <- struct{}{}

	s.assertNil(assertFileSize(outputFile, srcFilePid))
	return nil
}

func configureVppProxy(s *NsSuite, proto string) {
	serverVeth := s.getInterfaceByName(serverInterface)
	clientVeth := s.getInterfaceByName(clientInterface)

	testVppProxy := s.getContainerByName("vpp").vppInstance
	output := testVppProxy.vppctl(
		"test proxy server server-uri %s://%s/555 client-uri tcp://%s/666",
		proto,
		clientVeth.ip4AddressString(),
		serverVeth.peer.ip4AddressString(),
	)
	s.log("proxy configured: " + output)
}

func VppProxyHttpTcpTest(s *NsSuite) {
	proto := "tcp"
	configureVppProxy(s, proto)
	err := testProxyHttpTcp(s, proto)
	s.assertNil(err, fmt.Sprint(err))
}

func VppProxyHttpTlsTest(s *NsSuite) {
	proto := "tls"
	configureVppProxy(s, proto)
	err := testProxyHttpTcp(s, proto)
	s.assertNil(err, fmt.Sprint(err))
}

func configureEnvoyProxy(s *NsSuite) {
	envoyContainer := s.getContainerByName("envoy")
	err := envoyContainer.create()
	s.assertNil(err, "Error creating envoy container: %s", err)

	serverVeth := s.getInterfaceByName(serverInterface)
	address := struct {
		Server string
	}{
		Server: serverVeth.peer.ip4AddressString(),
	}
	envoyContainer.createConfig(
		"/etc/envoy/envoy.yaml",
		"resources/envoy/proxy.yaml",
		address,
	)
	s.assertNil(envoyContainer.start())
}

func EnvoyProxyHttpTcpTest(s *NsSuite) {
	configureEnvoyProxy(s)
	err := testProxyHttpTcp(s, "tcp")
	s.assertNil(err, fmt.Sprint(err))
}
