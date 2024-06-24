package main

import (
	"fmt"
	"os"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterVethTests(LDPreloadIperfVppTest, LDPreloadIperfVppInterruptModeTest)
}

func LDPreloadIperfVppInterruptModeTest(s *VethsSuite) {
	LDPreloadIperfVppTest(s)
}

func LDPreloadIperfVppTest(s *VethsSuite) {
	var clnVclConf, srvVclConf Stanza
	var ldpreload string

	serverContainer := s.GetContainerByName("server-vpp")
	serverVclFileName := serverContainer.GetHostWorkDir() + "/vcl_srv.conf"

	clientContainer := s.GetContainerByName("client-vpp")
	clientVclFileName := clientContainer.GetHostWorkDir() + "/vcl_cln.conf"

	if *IsDebugBuild {
		ldpreload = "LD_PRELOAD=../../build-root/build-vpp_debug-native/vpp/lib/x86_64-linux-gnu/libvcl_ldpreload.so"
	} else {
		ldpreload = "LD_PRELOAD=../../build-root/build-vpp-native/vpp/lib/x86_64-linux-gnu/libvcl_ldpreload.so"
	}

	stopServerCh := make(chan struct{}, 1)
	srvCh := make(chan error, 1)
	clnCh := make(chan error)

	s.Log("starting VPPs")

	clientAppSocketApi := fmt.Sprintf("app-socket-api %s/var/run/app_ns_sockets/default",
		clientContainer.GetHostWorkDir())
	err := clnVclConf.
		NewStanza("vcl").
		Append("rx-fifo-size 4000000").
		Append("tx-fifo-size 4000000").
		Append("app-scope-local").
		Append("app-scope-global").
		Append("use-mq-eventfd").
		Append(clientAppSocketApi).Close().
		SaveToFile(clientVclFileName)
	s.AssertNil(err, fmt.Sprint(err))

	serverAppSocketApi := fmt.Sprintf("app-socket-api %s/var/run/app_ns_sockets/default",
		serverContainer.GetHostWorkDir())
	err = srvVclConf.
		NewStanza("vcl").
		Append("rx-fifo-size 4000000").
		Append("tx-fifo-size 4000000").
		Append("app-scope-local").
		Append("app-scope-global").
		Append("use-mq-eventfd").
		Append(serverAppSocketApi).Close().
		SaveToFile(serverVclFileName)
	s.AssertNil(err, fmt.Sprint(err))

	s.Log("attaching server to vpp")

	srvEnv := append(os.Environ(), ldpreload, "VCL_CONFIG="+serverVclFileName)
	go func() {
		defer GinkgoRecover()
		s.StartServerApp(srvCh, stopServerCh, srvEnv)
	}()

	err = <-srvCh
	s.AssertNil(err, fmt.Sprint(err))

	s.Log("attaching client to vpp")
	var clnRes = make(chan string, 1)
	clnEnv := append(os.Environ(), ldpreload, "VCL_CONFIG="+clientVclFileName)
	serverVethAddress := s.GetInterfaceByName(ServerInterfaceName).Ip4AddressString()
	go func() {
		defer GinkgoRecover()
		s.StartClientApp(serverVethAddress, clnEnv, clnCh, clnRes)
	}()
	s.Log(<-clnRes)

	// wait for client's result
	err = <-clnCh
	s.AssertNil(err, fmt.Sprint(err))

	// stop server
	stopServerCh <- struct{}{}
}
