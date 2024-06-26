package main

import (
	"fmt"
	"os"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterTapTests(IperfTest)
}

func IperfTest(s *TapSuite) {
	var vclConf Stanza

	vppContainer := s.GetContainerByName("vpp")
	vclFileName := vppContainer.GetHostWorkDir() + "/vcl.conf"

	serverAppSocketApi := fmt.Sprintf("app-socket-api %s/var/run/app_ns_sockets/default",
		vppContainer.GetHostWorkDir())
	err := vclConf.
		NewStanza("vcl").
		Append("rx-fifo-size 4000000").
		Append("tx-fifo-size 4000000").
		Append("app-scope-local").
		Append("app-scope-global").
		Append("use-mq-eventfd").
		Append(serverAppSocketApi).Close().
		SaveToFile(vclFileName)
	s.AssertNil(err, fmt.Sprint(err))

	clnCh := make(chan error)
	stopServerCh := make(chan struct{})
	srvCh := make(chan error, 1)
	clnRes := make(chan string, 1)

	srvEnv := append(os.Environ(), "VCL_CONFIG="+vclFileName)
	defer func() {
		stopServerCh <- struct{}{}
	}()

	go func() {
		defer GinkgoRecover()
		s.StartServerApp(srvCh, stopServerCh, srvEnv)
	}()
	err = <-srvCh
	s.AssertNil(err, fmt.Sprint(err))
	s.Log("server running")

	ipAddress := s.GetInterfaceByName(TapInterfaceName).Ip4AddressString()
	go func() {
		defer GinkgoRecover()
		s.StartClientApp(ipAddress, nil, clnCh, clnRes)
	}()
	s.Log("client running")
	s.Log(<-clnRes)
	err = <-clnCh
	s.AssertNil(err, "err: '%s', ip: '%s'", err, ipAddress)
	s.Log("Test completed")
}
