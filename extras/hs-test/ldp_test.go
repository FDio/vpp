package main

import (
	"fmt"
	"os"
)

func (s *VethsSuite) TestLDPreloadIperfVpp() {
	var clnVclConf, srvVclConf Stanza

	serverContainer := s.getContainerByName("server-vpp")
	serverVclFileName := serverContainer.getHostWorkDir() + "/vcl_srv.conf"

	clientContainer := s.getContainerByName("client-vpp")
	clientVclFileName := clientContainer.getHostWorkDir() + "/vcl_cln.conf"

	ldpreload := os.Getenv("HST_LDPRELOAD")
	s.assertNotEqual("", ldpreload)

	ldpreload = "LD_PRELOAD=" + ldpreload

	stopServerCh := make(chan struct{}, 1)
	srvCh := make(chan error, 1)
	clnCh := make(chan error)

	s.log("starting VPPs")

	clientAppSocketApi := fmt.Sprintf("app-socket-api %s/var/run/app_ns_sockets/2",
		clientContainer.getContainerWorkDir())
	err := clnVclConf.
		newStanza("vcl").
		append("rx-fifo-size 4000000").
		append("tx-fifo-size 4000000").
		append("app-scope-local").
		append("app-scope-global").
		append("use-mq-eventfd").
		append(clientAppSocketApi).close().
		saveToFile(clientVclFileName)
	s.assertNil(err)

	serverAppSocketApi := fmt.Sprintf("app-socket-api %s/var/run/app_ns_sockets/1",
		serverContainer.getContainerWorkDir())
	err = srvVclConf.
		newStanza("vcl").
		append("rx-fifo-size 4000000").
		append("tx-fifo-size 4000000").
		append("app-scope-local").
		append("app-scope-global").
		append("use-mq-eventfd").
		append(serverAppSocketApi).close().
		saveToFile(serverVclFileName)
	s.assertNil(err)

	s.log("attaching server to vpp")

	srvEnv := append(os.Environ(), ldpreload, "VCL_CONFIG="+serverVclFileName)
	go startServerApp(srvCh, stopServerCh, srvEnv)

	err = <-srvCh
	s.assertNil(err)

	s.log("attaching client to vpp")
	var clnRes = make(chan string, 1)
	clnEnv := append(os.Environ(), ldpreload, "VCL_CONFIG="+clientVclFileName)
	serverVethAddress := s.netInterfaces[serverInterfaceName].ip4AddressString()
	go startClientApp(serverVethAddress, clnEnv, clnCh, clnRes)
	s.log(<-clnRes)

	// wait for client's result
	err = <-clnCh
	s.assertNil(err)

	// stop server
	stopServerCh <- struct{}{}
}
