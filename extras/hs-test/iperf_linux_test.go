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
	serverContainer := s.GetContainerByName(ServerIperfContainerName)
	serverIpAddress := s.GetInterfaceByName(ServerIperfInterfaceName).Ip4AddressString()
	clientContainer := s.GetContainerByName(ClientIperfContainerName)
	clientIpAddress := s.GetInterfaceByName(ClientIperfInterfaceName).Ip4AddressString()

	clnCh := make(chan error)
	stopServerCh := make(chan struct{})
	srvCh := make(chan error, 1)
	clnRes := make(chan string, 1)

	defer func() {
		stopServerCh <- struct{}{}
	}()

	go func() {
		defer GinkgoRecover()
		cmd := "iperf3 -4 -s -B " + serverIpAddress + " -p " + s.GetPortFromPpid()
		s.StartServerApp(serverContainer, "iperf3", cmd, srvCh, stopServerCh)
	}()
	err := <-srvCh
	s.AssertNil(err, fmt.Sprint(err))
	s.Log("server running")

	go func() {
		defer GinkgoRecover()
		cmd := "iperf3 -c " + serverIpAddress + " -B " + clientIpAddress +
			" -u -l 1460 -b 10g -p " + s.GetPortFromPpid()
		s.StartClientApp(clientContainer, cmd, clnCh, clnRes)
	}()
	s.AssertChannelClosed(TestTimeout, clnCh)
	s.Log(<-clnRes)
}
