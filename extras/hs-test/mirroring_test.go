package main

import (
	. "fd.io/hs-test/infra"
	"github.com/edwarnicke/exechelper"
)

func init() {
	RegisterNginxTests(MirroringTest)
}

// broken when CPUS > 1
func MirroringTest(s *NginxSuite) {
	s.SkipIfMultiWorker()
	proxyAddress := s.GetInterfaceByName(MirroringClientInterfaceName).Peer.Ip4AddressString()

	path := "/64B.json"

	testCommand := "wrk -c 20 -t 10 -d 10 http://" + proxyAddress + ":80" + path
	s.Log(testCommand)
	o, _ := exechelper.Output(testCommand)
	s.Log(string(o))
	s.AssertNotEmpty(o)

	vppProxyContainer := s.GetContainerByName(VppProxyContainerName)
	s.AssertEqual(0, vppProxyContainer.VppInstance.GetSessionStat("no lcl port"))
}
