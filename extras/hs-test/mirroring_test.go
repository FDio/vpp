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

	go startHttpServer(serverRunning, stopServer, serverNamespace, ":8081", ":8082", ":8083")
	<-serverRunning

	defer func(chan struct{}) {
		stopServer <- struct{}{}
	}(stopServer)

	s.log("http server started...")

	proxyAddress := s.netInterfaces[mirroringProxyInterfaceName].IP4AddressString()
	clientNamespace := s.netInterfaces[mirroringClientInterfaceName].(*NetworkInterfaceVeth).peerNetworkNamespace

	testCommand := "wrk -c 20 -t 10 -d 40 http://" + proxyAddress + ":80" + "/" + srcFile
	testCommand = "ip netns exec " + clientNamespace + " " + testCommand
	s.log(testCommand)
	o, err := exechelper.Output(testCommand)
	s.log(string(o))
	s.assertNotEmpty(o)

	// Check if log output from VPP contains 'no lcl port' warnings
	logContent := s.getContainerByName(singleTopoContainerVpp).log()
	s.log(logContent)
	s.assertNotContains(logContent, "no lcl port")
}
