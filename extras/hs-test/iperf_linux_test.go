package main

import (
	"fmt"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterIperfTests(IperfLinuxTest)
}

func IperfLinuxTest(s *IperfSuite) {
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
		cmd := "iperf3 -4 -s -p " + s.GetPortFromPpid()
		s.StartServerApp(serverContainer, "iperf3", cmd, srvCh, stopServerCh)
	}()
	err := <-srvCh
	s.AssertNil(err, fmt.Sprint(err))
	s.Log("server running")

	ipAddress := s.GetInterfaceByName(TapInterfaceName).Ip4AddressString()
	go func() {
		defer GinkgoRecover()
		cmd := "iperf3 -c " + ipAddress + " -u -l 1460 -b 10g -p " + s.GetPortFromPpid()
		s.StartClientApp(clientContainer, cmd, clnCh, clnRes)
	}()

	s.Log(<-clnRes)
	err = <-clnCh
	s.AssertNil(err, "err: '%s', ip: '%s'", err, ipAddress)
}
