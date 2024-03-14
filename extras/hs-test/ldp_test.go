package main

import (
	"fmt"
	"os"

	. "github.com/onsi/ginkgo/v2"
)

func init() {
	registerVethTests(LDPreloadIperfVppTest)
}

func LDPreloadIperfVppTest(s *VethsSuite) {
	var clnVclConf, srvVclConf Stanza

	serverContainer := s.getContainerByName("server-vpp")
	serverVclFileName := serverContainer.getHostWorkDir() + "/vcl_srv.conf"

	clientContainer := s.getContainerByName("client-vpp")
	clientVclFileName := clientContainer.getHostWorkDir() + "/vcl_cln.conf"

	ldpreload := "LD_PRELOAD=../../build-root/build-vpp-native/vpp/lib/x86_64-linux-gnu/libvcl_ldpreload.so"

	stopServerCh := make(chan struct{}, 1)
	srvCh := make(chan error, 1)
	clnCh := make(chan error)

	s.log("starting VPPs")

	clientAppSocketApi := fmt.Sprintf("app-socket-api %s/var/run/app_ns_sockets/default",
		clientContainer.getHostWorkDir())
	err := clnVclConf.
		newStanza("vcl").
		append("rx-fifo-size 4000000").
		append("tx-fifo-size 4000000").
		append("app-scope-local").
		append("app-scope-global").
		append("use-mq-eventfd").
		append(clientAppSocketApi).close().
		saveToFile(clientVclFileName)
	s.assertNil(err, fmt.Sprint(err))

	serverAppSocketApi := fmt.Sprintf("app-socket-api %s/var/run/app_ns_sockets/default",
		serverContainer.getHostWorkDir())
	err = srvVclConf.
		newStanza("vcl").
		append("rx-fifo-size 4000000").
		append("tx-fifo-size 4000000").
		append("app-scope-local").
		append("app-scope-global").
		append("use-mq-eventfd").
		append(serverAppSocketApi).close().
		saveToFile(serverVclFileName)
	s.assertNil(err, fmt.Sprint(err))

	s.log("attaching server to vpp")

	srvEnv := append(os.Environ(), ldpreload, "VCL_CONFIG="+serverVclFileName)
	go func() {
		defer GinkgoRecover()
		s.startServerApp(srvCh, stopServerCh, srvEnv)
	}()

	err = <-srvCh
	s.assertNil(err, fmt.Sprint(err))

	s.log("attaching client to vpp")
	var clnRes = make(chan string, 1)
	clnEnv := append(os.Environ(), ldpreload, "VCL_CONFIG="+clientVclFileName)
	serverVethAddress := s.getInterfaceByName(serverInterfaceName).ip4AddressString()
	go func() {
		defer GinkgoRecover()
		s.startClientApp(serverVethAddress, clnEnv, clnCh, clnRes)
	}()
	s.log(<-clnRes)

	// wait for client's result
	err = <-clnCh
	s.assertNil(err, fmt.Sprint(err))

	// stop server
	stopServerCh <- struct{}{}
}
