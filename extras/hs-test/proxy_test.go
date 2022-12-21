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

	s.log("Test file created...")

	go startHttpServer(serverRunning, stopServer, ":666", "server")
	// TODO better error handling and recovery
	<-serverRunning

	defer func(chan struct{}) {
		stopServer <- struct{}{}
	}(stopServer)

	s.log("http server started...")

	c := fmt.Sprintf("ip netns exec client wget --retry-connrefused --retry-on-http-error=503 --tries=10 -O %s 10.0.0.2:555/%s", outputFile, srcFile)
	_, err = exechelper.CombinedOutput(c)
	s.assertNil(err, "failed to run wget")
	stopServer <- struct{}{}

	defer func() { os.Remove(outputFile) }()

	s.assertNil(assertFileSize(outputFile, srcFile))
	return nil
}

func configureVppProxy(s *NsSuite) error {
	container := s.getContainerByName("vpp")
	testVppProxy := NewVppInstance(container)
	testVppProxy.setVppProxy()
	err := testVppProxy.start()
	s.assertNil(err, "failed to start and configure VPP")
	s.log("VPP running and configured...")

	output, err := testVppProxy.vppctl("test proxy server server-uri tcp://10.0.0.2/555 client-uri tcp://10.0.1.1/666")
	s.log("Proxy configured...", string(output))
	return err
}

func (s *NsSuite) TestVppProxyHttpTcp() {
	err := configureVppProxy(s)
	s.assertNil(err)
	err = testProxyHttpTcp(s)
	s.assertNil(err)
}

func configureEnvoyProxy(s *NsSuite) error {
	vppContainer := s.getContainerByName("vpp")
	testVppForEnvoyProxy := NewVppInstance(vppContainer)
	testVppForEnvoyProxy.setEnvoyProxy()
	err := testVppForEnvoyProxy.start()
	s.assertNil(err, "failed to start and configure VPP")

	envoyContainer := s.getContainerByName("envoy")
	return envoyContainer.run()
}

func (s *NsSuite) TestEnvoyProxyHttpTcp() {
	err := configureEnvoyProxy(s)
	s.assertNil(err)
	err = testProxyHttpTcp(s)
	s.assertNil(err)
}
