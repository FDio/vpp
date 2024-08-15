package main

import (
	. "fd.io/hs-test/infra"
	"fmt"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterTapTests(LinuxIperfTest)
}

func LinuxIperfTest(s *TapSuite) {
	clnCh := make(chan error)
	stopServerCh := make(chan struct{})
	srvCh := make(chan error, 1)
	clnRes := make(chan string, 1)
	defer func() {
		stopServerCh <- struct{}{}
	}()

	go func() {
		defer GinkgoRecover()
		s.StartIperfServerApp(srvCh, stopServerCh, nil)
	}()
	err := <-srvCh
	s.AssertNil(err, fmt.Sprint(err))
	s.Log("server running")

	ipAddress := s.GetInterfaceByName(TapInterfaceName).Ip4AddressString()
	go func() {
		defer GinkgoRecover()
		s.StartIperfClientApp(ipAddress, nil, clnCh, clnRes)
	}()
	s.Log("client running")
	s.Log(<-clnRes)
	err = <-clnCh
	s.AssertNil(err, "err: '%s', ip: '%s'", err, ipAddress)
	s.Log("Test completed")
}
