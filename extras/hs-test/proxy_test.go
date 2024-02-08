package main

import (
	"fmt"
	"os"

	"github.com/edwarnicke/exechelper"
)

func testProxyHttpTcp(s *NsSuite, proto string) error {
	var outputFile string = "test" + pid + ".data"
	var srcFile string = "10M" + pid
	stopServer := make(chan struct{}, 1)
	serverRunning := make(chan struct{}, 1)

	// create test file
	err := exechelper.Run(fmt.Sprintf("ip netns exec srv%s truncate -s %s %s", pid, "10M", srcFile))
	s.assertNil(err, "failed to run truncate command: " + fmt.Sprint(err))
	defer func() { os.Remove(srcFile) }()
	defer func() { os.Remove(outputFile) }()

	s.log("test file created...")

	go s.startHttpServer(serverRunning, stopServer, ":" + "666", "srv" + pid)
	// TODO better error handling and recovery
	<-serverRunning

	defer func(chan struct{}) {
		stopServer <- struct{}{}
	}(stopServer)

	s.log("http server started...")

	clientVeth := s.netInterfaces[clientInterface]
	c := fmt.Sprintf("ip netns exec cln%s wget --no-proxy --retry-connrefused"+
		" --retry-on-http-error=503 --tries=10 -O %s ", pid, outputFile)
	if proto == "tls" {
		c += " --secure-protocol=TLSv1_3 --no-check-certificate https://"
	}

	c += fmt.Sprintf("%s:555/10M", clientVeth.ip4AddressString())
	s.log(c)
	_, err = exechelper.CombinedOutput(c)
	s.assertNil(err, "failed to run wget: '%s', cmd: %s", err, c)
	stopServer <- struct{}{}

	s.assertNil(assertFileSize(outputFile, srcFile))
	return nil
}

func configureVppProxy(s *NsSuite, proto string) {
	serverVeth := s.netInterfaces[serverInterface]
	clientVeth := s.netInterfaces[clientInterface]

	testVppProxy := s.getContainerByName("vpp" + pid).vppInstance
	output := testVppProxy.vppctl(
		"test proxy server server-uri %s://%s/555 client-uri tcp://%s/666",
		proto,
		clientVeth.ip4AddressString(),
		serverVeth.peer.ip4AddressString(),
	)
	s.log("proxy configured...", output)
}

func (s *NsSuite) TestVppProxyHttpTcp() {
	proto := "tcp"
	configureVppProxy(s, proto)
	err := testProxyHttpTcp(s, proto)
	s.assertNil(err, err)
}

func (s *NsSuite) TestVppProxyHttpTls() {
	proto := "tls"
	configureVppProxy(s, proto)
	err := testProxyHttpTcp(s, proto)
	s.assertNil(err, err)
}

func configureEnvoyProxy(s *NsSuite) {
	envoyContainer := s.getContainerByName("envoy" + pid)
	err := envoyContainer.create()
	s.assertNil(err, "Error creating envoy container: %s", err)

	serverVeth := s.netInterfaces[serverInterface]
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

// Does not work when running multiple test instances side-by-side
func (s *NsSuite) TestEnvoyProxyHttpTcp() {
	s.skip("Not working when running multiple instances")
	configureEnvoyProxy(s)
	err := testProxyHttpTcp(s, "tcp")
	s.assertNil(err, err)
}
