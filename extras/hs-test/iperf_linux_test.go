package main

import (
	"fmt"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterTapTests(IperfLinuxTest)
}

func IperfLinuxTest(s *TapSuite) {
	serverContainer := s.GetContainerByName("server-vpp")
	clientContainer := s.GetContainerByName("client-vpp")

	clnCh := make(chan error)
	stopServerCh := make(chan struct{})
	srvCh := make(chan error, 1)
	clnRes := make(chan string, 1)

	defer func() {
		stopServerCh <- struct{}{}
	}()

	go func() {
		defer GinkgoRecover()
		s.StartServerApp(serverContainer, nil, srvCh, stopServerCh)
	}()
	err := <-srvCh
	s.AssertNil(err, fmt.Sprint(err))
	s.Log("server running")

	ipAddress := s.GetInterfaceByName(TapInterfaceName).Ip4AddressString()
	go func() {
		defer GinkgoRecover()
		s.StartClientApp(clientContainer, ipAddress, nil, clnCh, clnRes)
	}()

	s.Log(<-clnRes)
	err = <-clnCh
	s.AssertNil(err, "err: '%s', ip: '%s'", err, ipAddress)
}
