package main

import (
	"os"
	"strconv"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterHsiSoloTests(HsiTransparentProxyTest)
}

func HsiTransparentProxyTest(s *HsiSuite) {
	s.SetupNginxServer()
	vpp := s.Containers.Vpp.VppInstance
	s.Log(vpp.Vppctl("set interface feature host-" + s.Interfaces.Client.Name() + " hsi4-in arc ip4-unicast"))
	s.Log(vpp.Vppctl("set interface feature host-" + s.Interfaces.Server.Name() + " hsi4-in arc ip4-unicast"))
	s.Log(vpp.Vppctl("test proxy server server-uri tcp://0.0.0.0:%d client-uri tcp://%s:%d",
		s.Ports.Server, s.ServerAddr(), s.Ports.Server))

	query := "httpTestFile"
	finished := make(chan error, 1)
	defer os.Remove(query)
	go func() {
		defer GinkgoRecover()
		s.StartWget(finished, s.ServerAddr(), strconv.Itoa(int(s.Ports.Server)), query, s.NetNamespaces.Client)
	}()
	s.AssertNil(<-finished)
}
