package main

import (
	"github.com/edwarnicke/exechelper"
)

func (s *NginxSuite) TestMirroring() {
	proxyAddress := s.netInterfaces[mirroringClientInterfaceName].peer.ip4AddressString()

	path := "/64B.json"

	testCommand := "wrk -c 20 -t 10 -d 10 http://" + proxyAddress + ":80" + path
	s.log(testCommand)
	o, _ := exechelper.Output(testCommand)
	s.log(string(o))
	s.assertNotEmpty(o)

	vppProxyContainer := s.getContainerByName(vppProxyContainerName)
	s.assertEqual(0, vppProxyContainer.vppInstance.GetSessionStat("no lcl port"))
}
