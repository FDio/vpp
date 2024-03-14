package main

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
)

func init() {
	registerTapTests(LinuxIperfTest)
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
		s.startServerApp(srvCh, stopServerCh, nil)
	}()
	err := <-srvCh
	s.assertNil(err, fmt.Sprint(err))
	s.log("server running")

	ipAddress := s.getInterfaceByName(tapInterfaceName).ip4AddressString()
	go func() {
		defer GinkgoRecover()
		s.startClientApp(ipAddress, nil, clnCh, clnRes)
	}()
	s.log("client running")
	s.log(<-clnRes)
	err = <-clnCh
	s.assertNil(err, "err: '%s', ip: '%s'", err, ipAddress)
	s.log("Test completed")
}
