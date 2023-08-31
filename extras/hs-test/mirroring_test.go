package main

import (
	"github.com/edwarnicke/exechelper"
)

func (s *NginxSuite) TestMirroring() {
	proxyAddress := s.netInterfaces[mirroringClientInterfaceName].peer.Ip4AddressString()

	path := "/64B.json"

	testCommand := "wrk -c 20 -t 10 -d 10 http://" + proxyAddress + ":80" + path
	s.Log(testCommand)
	o, _ := exechelper.Output(testCommand)
	s.Log(string(o))
	s.AssertNotEmpty(o)

	vppProxyContainer := s.GetContainerByName(vppProxyContainerName)
	s.AssertEqual(0, vppProxyContainer.vppInstance.GetSessionStat("no lcl port"))
}
