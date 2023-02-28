package main

import (
	"github.com/edwarnicke/exechelper"
)

func (s *NginxSuite) TestMirroring() {
	proxyAddress := s.netInterfaces[mirroringClientInterfaceName].getPeer().ip4AddressString()

	path := "/64B.json"

	testCommand := "wrk -c 20 -t 10 -d 40 http://" + proxyAddress + ":80" + path
	s.log(testCommand)
	o, _ := exechelper.Output(testCommand)
	s.log(string(o))
	s.assertNotEmpty(o)

	// Check if log output from VPP contains 'no lcl port' warnings
	// TODO: Need to change after adding session worker counter
	vppProxyContainer := s.getContainerByName(vppProxyContainerName)
	logContent := vppProxyContainer.log()
	s.assertNotContains(logContent, "no lcl port")
}
