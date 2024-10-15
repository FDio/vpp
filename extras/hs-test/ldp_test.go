package main

import (
	"fmt"
	"time"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterLdpTests(LDPreloadIperfVppTest, LDPreloadIperfVppInterruptModeTest, RedisBenchmarkTest)
}

func LDPreloadIperfVppInterruptModeTest(s *LdpSuite) {
	LDPreloadIperfVppTest(s)
}

func LDPreloadIperfVppTest(s *LdpSuite) {
	clientContainer := s.GetContainerByName("client-vpp")
	serverContainer := s.GetContainerByName("server-vpp")

	stopServerCh := make(chan struct{}, 1)
	srvCh := make(chan error, 1)
	clnCh := make(chan error)
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

	serverVethAddress := s.GetInterfaceByName(ServerInterfaceName).Ip4AddressString()
	go func() {
		defer GinkgoRecover()
		cmd := "iperf3 -c " + serverVethAddress + " -u -l 1460 -b 10g -p " + s.GetPortFromPpid()
		s.StartClientApp(clientContainer, cmd, clnCh, clnRes)
	}()

	s.AssertChannelClosed(time.Minute*3, clnCh)
	s.Log(<-clnRes)
}

func RedisBenchmarkTest(s *LdpSuite) {
	s.SkipIfMultiWorker()

	serverContainer := s.GetContainerByName("server-vpp")
	clientContainer := s.GetContainerByName("client-vpp")

	serverVethAddress := s.GetInterfaceByName(ServerInterfaceName).Ip4AddressString()
	runningSrv := make(chan error)
	doneSrv := make(chan struct{})
	clnCh := make(chan error)
	clnRes := make(chan string, 1)

	defer func() {
		doneSrv <- struct{}{}
	}()

	go func() {
		defer GinkgoRecover()
		cmd := "redis-server --daemonize yes --protected-mode no --bind " + serverVethAddress
		s.StartServerApp(serverContainer, "redis-server", cmd, runningSrv, doneSrv)
	}()

	err := <-runningSrv
	s.AssertNil(err)

	go func() {
		defer GinkgoRecover()
		var cmd string
		if *NConfiguredCpus == 1 {
			cmd = "redis-benchmark --threads 1 -h " + serverVethAddress
		} else {
			cmd = "redis-benchmark --threads " + fmt.Sprint(*NConfiguredCpus) + "-h " + serverVethAddress
		}
		s.StartClientApp(clientContainer, cmd, clnCh, clnRes)

	}()

	// 4.5 minutes
	s.AssertChannelClosed(time.Second*270, clnCh)
	s.Log(<-clnRes)
}
