package main

import (
	"fmt"
	"os"

	"github.com/edwarnicke/exechelper"
)

func testProxyHttpTcp(s *NsSuite) error {
	const outputFile = "test.data"
	const srcFile = "10M"
	stopServer := make(chan struct{}, 1)
	serverRunning := make(chan struct{}, 1)

	// create test file
	err := exechelper.Run(fmt.Sprintf("ip netns exec server truncate -s %s %s", srcFile, srcFile))
	s.assertNil(err, "failed to run truncate command")
	defer func() { os.Remove(srcFile) }()

	s.log("test file created...")

	go startHttpServer(serverRunning, stopServer, ":666", "server")
	// TODO better error handling and recovery
	<-serverRunning

	defer func(chan struct{}) {
		stopServer <- struct{}{}
	}(stopServer)

	s.log("http server started...")

	clientVeth := s.netInterfaces[clientInterface]
	c := fmt.Sprintf("ip netns exec client wget --no-proxy --retry-connrefused"+
		" --retry-on-http-error=503 --tries=10"+
		" -O %s %s:555/%s",
		outputFile,
		clientVeth.ip4AddressString(),
		srcFile,
	)
	s.log(c)
	_, err = exechelper.CombinedOutput(c)
	s.assertNil(err, "failed to run wget")
	stopServer <- struct{}{}

	defer func() { os.Remove(outputFile) }()

	s.assertNil(assertFileSize(outputFile, srcFile))
	return nil
}

func configureVppProxy(s *NsSuite) {
	serverVeth := s.netInterfaces[serverInterface]
	clientVeth := s.netInterfaces[clientInterface]

	testVppProxy := s.getContainerByName("vpp").vppInstance
	output := testVppProxy.vppctl(
		"test proxy server server-uri tcp://%s/555 client-uri tcp://%s/666",
		clientVeth.ip4AddressString(),
		serverVeth.getPeer().ip4AddressString(),
	)
	s.log("proxy configured...", output)
}

func (s *NsSuite) TestVppProxyHttpTcp() {
	configureVppProxy(s)
	err := testProxyHttpTcp(s)
	s.assertNil(err)
}

func configureEnvoyProxy(s *NsSuite) {
	envoyContainer := s.getContainerByName("envoy")
	envoyContainer.create()

	serverVeth := s.netInterfaces[serverInterface]
	address := struct {
		Server string
	}{
		Server: serverVeth.getPeer().ip4AddressString(),
	}
	envoyContainer.createConfig(
		"/etc/envoy/envoy.yaml",
		"resources/envoy/proxy.yaml",
		address,
	)

	envoyContainer.start()
}

func (s *NsSuite) TestEnvoyProxyHttpTcp() {
	configureEnvoyProxy(s)
	err := testProxyHttpTcp(s)
	s.assertNil(err)
}
