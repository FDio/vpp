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
	s.AssertNil(err, "failed to run truncate command")
	defer func() { os.Remove(srcFile) }()

	s.Log("test file created...")

	go s.StartHttpServer(serverRunning, stopServer, ":666", "server")
	// TODO better error handling and recovery
	<-serverRunning

	defer func(chan struct{}) {
		stopServer <- struct{}{}
	}(stopServer)

	s.Log("http server started...")

	clientVeth := s.netInterfaces[clientInterface]
	c := fmt.Sprintf("ip netns exec client wget --no-proxy --retry-connrefused"+
		" --retry-on-http-error=503 --tries=10"+
		" -O %s %s:555/%s",
		outputFile,
		clientVeth.Ip4AddressString(),
		srcFile,
	)
	s.Log(c)
	_, err = exechelper.CombinedOutput(c)
	s.AssertNil(err, "failed to run wget")
	stopServer <- struct{}{}

	defer func() { os.Remove(outputFile) }()

	s.AssertFileSize(outputFile, srcFile)
	return nil
}

func configureVppProxy(s *NsSuite) {
	serverVeth := s.netInterfaces[serverInterface]
	clientVeth := s.netInterfaces[clientInterface]

	testVppProxy := s.GetContainerByName("vpp").vppInstance
	output := testVppProxy.Vppctl(
		"test proxy server server-uri tcp://%s/555 client-uri tcp://%s/666",
		clientVeth.Ip4AddressString(),
		serverVeth.peer.Ip4AddressString(),
	)
	s.Log("proxy configured...", output)
}

func (s *NsSuite) TestVppProxyHttpTcp() {
	configureVppProxy(s)
	err := testProxyHttpTcp(s)
	s.AssertNil(err)
}

func configureEnvoyProxy(s *NsSuite) {
	envoyContainer := s.GetContainerByName("envoy")
	envoyContainer.Create()

	serverVeth := s.netInterfaces[serverInterface]
	address := struct {
		Server string
	}{
		Server: serverVeth.peer.Ip4AddressString(),
	}
	envoyContainer.CreateConfig(
		"/etc/envoy/envoy.yaml",
		"resources/envoy/proxy.yaml",
		address,
	)
	s.AssertNil(envoyContainer.Start())
}

func (s *NsSuite) TestEnvoyProxyHttpTcp() {
	configureEnvoyProxy(s)
	err := testProxyHttpTcp(s)
	s.AssertNil(err)
}
