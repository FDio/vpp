package main

import (
	"fmt"
	"time"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterIperfTests(IperfUdpLinuxTest)
}

func IperfUdpLinuxTest(s *IperfSuite) {
	serverIpAddress := s.Interfaces.Server.Ip4AddressString()
	clientIpAddress := s.Interfaces.Client.Ip4AddressString()

	clnCh := make(chan error)
	stopServerCh := make(chan struct{})
	srvCh := make(chan error, 1)
	clnRes := make(chan []byte, 1)

	defer func() {
		stopServerCh <- struct{}{}
	}()

	go func() {
		defer GinkgoRecover()
		cmd := "iperf3 -4 -s -B " + serverIpAddress + " -p " + s.GetPortFromPpid()
		s.StartServerApp(s.Containers.Server, "iperf3", cmd, srvCh, stopServerCh)
	}()
	err := <-srvCh
	s.AssertNil(err, fmt.Sprint(err))
	s.Log("server running")

	go func() {
		defer GinkgoRecover()
		cmd := "iperf3 -c " + serverIpAddress + " -B " + clientIpAddress +
			" -u -l 1460 -b 10g -J -p " + s.GetPortFromPpid()
		s.StartClientApp(s.Containers.Client, cmd, clnCh, clnRes)
	}()
	s.AssertChannelClosed(time.Minute*3, clnCh)
	output := <-clnRes
	result := s.ParseJsonIperfOutput(output)
	s.LogJsonIperfOutput(result)
	s.AssertIperfMinTransfer(result, 400)
}
