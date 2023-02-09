package main

import (
	"fmt"
	"os"

	"github.com/edwarnicke/exechelper"
)

func (s *MirroringSuite) TestMirroring() {
	// Create test file
	const outputFile = "test.data"
	const srcFile = "10M"
	serverVeth := s.netInterfaces[mirroringServerInterfaceName].(*NetworkInterfaceVeth)
	serverNamespace := serverVeth.peerNetworkNamespace
	err := exechelper.Run(fmt.Sprintf("ip netns exec %s truncate -s %s %s", serverNamespace, srcFile, srcFile))
	s.assertNil(err, "failed to run truncate command")
	defer func() { os.Remove(srcFile) }()

	s.log("test file created...")

	// Start servers
	stopServer := make(chan struct{}, 1)
	serverRunning := make(chan struct{}, 1)

	go startHttpServer(serverRunning, stopServer, ":8081", serverNamespace)
	go startHttpServer(serverRunning, stopServer, ":8082", serverNamespace)
	go startHttpServer(serverRunning, stopServer, ":8083", serverNamespace)
	<-serverRunning

	defer func(chan struct{}) {
		stopServer <- struct{}{}
	}(stopServer)

	s.log("http server started...")

	// Start client
	finished := make(chan error, 1)

	proxyAddress := s.netInterfaces[mirroringProxyInterfaceName].IP4AddressString()
	clientNamespace := s.netInterfaces[mirroringClientInterfaceName].(*NetworkInterfaceVeth).peerNetworkNamespace

	go startWget(finished, proxyAddress, "80", srcFile, clientNamespace)
	s.assertNil(<-finished)
}
