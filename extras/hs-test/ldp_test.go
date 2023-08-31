package main

import (
	"fmt"
	"os"
)

func (s *VethsSuite) TestLDPreloadIperfVpp() {
	var clnVclConf, srvVclConf Stanza

	serverContainer := s.GetContainerByName("server-vpp")
	serverVclFileName := serverContainer.GetHostWorkDir() + "/vcl_srv.conf"

	clientContainer := s.GetContainerByName("client-vpp")
	clientVclFileName := clientContainer.GetHostWorkDir() + "/vcl_cln.conf"

	ldpreload := os.Getenv("HST_LDPRELOAD")
	s.AssertNotEqual("", ldpreload)

	ldpreload = "LD_PRELOAD=" + ldpreload

	stopServerCh := make(chan struct{}, 1)
	srvCh := make(chan error, 1)
	clnCh := make(chan error)

	s.Log("starting VPPs")

	clientAppSocketApi := fmt.Sprintf("app-socket-api %s/var/run/app_ns_sockets/2",
		clientContainer.GetContainerWorkDir())
	err := clnVclConf.
		NewStanza("vcl").
		Append("rx-fifo-size 4000000").
		Append("tx-fifo-size 4000000").
		Append("app-scope-local").
		Append("app-scope-global").
		Append("use-mq-eventfd").
		Append(clientAppSocketApi).Close().
		SaveToFile(clientVclFileName)
	s.AssertNil(err)

	serverAppSocketApi := fmt.Sprintf("app-socket-api %s/var/run/app_ns_sockets/1",
		serverContainer.GetContainerWorkDir())
	err = srvVclConf.
		NewStanza("vcl").
		Append("rx-fifo-size 4000000").
		Append("tx-fifo-size 4000000").
		Append("app-scope-local").
		Append("app-scope-global").
		Append("use-mq-eventfd").
		Append(serverAppSocketApi).Close().
		SaveToFile(serverVclFileName)
	s.AssertNil(err)

	s.Log("attaching server to vpp")

	srvEnv := append(os.Environ(), ldpreload, "VCL_CONFIG="+serverVclFileName)
	go s.StartServerApp(srvCh, stopServerCh, srvEnv)

	err = <-srvCh
	s.AssertNil(err)

	s.Log("attaching client to vpp")
	var clnRes = make(chan string, 1)
	clnEnv := append(os.Environ(), ldpreload, "VCL_CONFIG="+clientVclFileName)
	serverVethAddress := s.netInterfaces[serverInterfaceName].Ip4AddressString()
	go s.StartClientApp(serverVethAddress, clnEnv, clnCh, clnRes)
	s.Log(<-clnRes)

	// wait for client's result
	err = <-clnCh
	s.AssertNil(err)

	// stop server
	stopServerCh <- struct{}{}
}
