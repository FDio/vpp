package main

import (
	"github.com/edwarnicke/exechelper"
)

func (s *MirroringSuite) TestMirroring() {
	proxyAddress := s.netInterfaces[mirroringProxyInterfaceName].IP4AddressString()
	clientNamespace := s.netInterfaces[mirroringClientInterfaceName].(*NetworkInterfaceVeth).networkNamespace

	path := "/64B.json"

	testCommand := "wrk -c 20 -t 10 -d 40 http://" + proxyAddress + ":80" + path
	testCommand = "ip netns exec " + clientNamespace + " " + testCommand
	s.log(testCommand)
	o, _ := exechelper.Output(testCommand)
	s.log(string(o))
	s.assertNotEmpty(o)

	// Check if log output from VPP contains 'no lcl port' warnings
	logContent := s.getContainerByName(vppProxyContainerName).log()
	s.assertNotContains(logContent, "no lcl port")
}
