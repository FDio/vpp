package main

import (
	"fmt"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterTapTests(IperfTest)
}

func IperfTest(s *TapSuite) {
	var vclConf Stanza
	serverContainer := s.GetContainerByName("server-vpp")
	clientContainer := s.GetContainerByName("client-vpp")
	vclFileName := serverContainer.GetHostWorkDir() + "/vcl.conf"
	vclFileNameCont := serverContainer.GetContainerWorkDir() + "/vcl.conf"

	env := make(map[string]string)
	defer delete(serverContainer.EnvVars, "VCL_CONFIG")
	defer delete(clientContainer.EnvVars, "VCL_CONFIG")

	appSocketApi := fmt.Sprintf("app-socket-api %s/var/run/app_ns_sockets/default",
		serverContainer.GetContainerWorkDir())
	err := vclConf.
		NewStanza("vcl").
		Append("rx-fifo-size 4000000").
		Append("tx-fifo-size 4000000").
		Append("app-scope-local").
		Append("app-scope-global").
		Append("use-mq-eventfd").
		Append(appSocketApi).Close().
		SaveToFile(vclFileName)
	s.AssertNil(err, fmt.Sprint(err))

	clnCh := make(chan error)
	stopServerCh := make(chan struct{})
	srvCh := make(chan error, 1)
	clnRes := make(chan string, 1)

	env["VCL_CONFIG"] = vclFileNameCont

	defer func() {
		stopServerCh <- struct{}{}
	}()

	go func() {
		defer GinkgoRecover()
		s.StartServerApp(serverContainer, env, srvCh, stopServerCh)
	}()
	err = <-srvCh
	s.AssertNil(err, fmt.Sprint(err))
	s.Log("server running")

	ipAddress := s.GetInterfaceByName("htaphost").Ip4AddressString()
	go func() {
		defer GinkgoRecover()
		s.StartClientApp(clientContainer, ipAddress, env, clnCh, clnRes)
	}()

	s.Log(<-clnRes)
	err = <-clnCh
	s.AssertNil(err, "err: '%s', ip: '%s'", err, ipAddress)
}
