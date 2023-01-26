package main

import (
	"fmt"
	"os"
	"time"
)

func (s *VethsSuite) TestLDPreloadIperfVpp() {
	var clnVclConf, srvVclConf Stanza

	serverContainer := s.getContainerByName("server-vpp")
	srvVcl := serverContainer.GetHostWorkDir() + "/vcl_srv.conf"

	clientContainer := s.getContainerByName("client-vpp")
	clnVcl := clientContainer.GetHostWorkDir() + "/vcl_cln.conf"

	ldpreload := os.Getenv("HST_LDPRELOAD")
	s.assertNotEqual("", ldpreload)

	ldpreload = "LD_PRELOAD=" + ldpreload

	stopServerCh := make(chan struct{}, 1)
	srvCh := make(chan error, 1)
	clnCh := make(chan error)

	s.log("starting VPPs")

	_, err := serverContainer.execAction("Configure2Veths srv")
	s.assertNil(err)

	_, err = clientContainer.execAction("Configure2Veths cln")
	s.assertNil(err)

	clientAppSocketApi := fmt.Sprintf("app-socket-api %s/var/run/app_ns_sockets/2",
		clientContainer.GetContainerWorkDir())
	err = clnVclConf.
		NewStanza("vcl").
		Append("rx-fifo-size 4000000").
		Append("tx-fifo-size 4000000").
		Append("app-scope-local").
		Append("app-scope-global").
		Append("use-mq-eventfd").
		Append(clientAppSocketApi).Close().
		SaveToFile(clnVcl)
	s.assertNil(err)

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
		SaveToFile(srvVcl)
	s.assertNil(err)

	s.log("attaching server to vpp")

	// FIXME
	time.Sleep(5 * time.Second)

	srvEnv := append(os.Environ(), ldpreload, "VCL_CONFIG="+srvVcl)
	go StartServerApp(srvCh, stopServerCh, srvEnv)

	err = <-srvCh
	s.assertNil(err)

	s.log("attaching client to vpp")
	var clnRes = make(chan string, 1)
	clnEnv := append(os.Environ(), ldpreload, "VCL_CONFIG="+clnVcl)
	go StartClientApp(clnEnv, clnCh, clnRes)
	s.log(<-clnRes)

	// wait for client's result
	err = <-clnCh
	s.assertNil(err)

	// stop server
	stopServerCh <- struct{}{}
}
