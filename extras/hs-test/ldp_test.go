package main

import (
	"fmt"
	"os"
	"time"
)

func (s *VethsSuite) TestLDPreloadIperfVpp() {
	var clnVclConf, srvVclConf Stanza

	serverContainer := s.containers[0]
	serverVolume := serverContainer.getVolumeByName("/tmp/server")
	srvVcl := serverVolume.containerDir + "/vcl_srv.conf"

	clientContainer := s.containers[1]
	clientVolume := clientContainer.getVolumeByName("/tmp/client")
	clnVcl := clientVolume.containerDir + "/vcl_cln.conf"

	ldpreload := os.Getenv("HST_LDPRELOAD")
	s.assertNotEqual("", ldpreload)

	ldpreload = "LD_PRELOAD=" + ldpreload

	stopServerCh := make(chan struct{}, 1)
	srvCh := make(chan error, 1)
	clnCh := make(chan error)

	fmt.Println("starting VPPs")

	_, err := serverContainer.useVolumeAsWorkDir(serverVolume.hostDir).execAction("Configure2Veths srv")
	s.assertNil(err)

	_, err = clientContainer.useVolumeAsWorkDir(clientVolume.hostDir).execAction("Configure2Veths cln")
	s.assertNil(err)

	clientAppSocketApi := fmt.Sprintf("app-socket-api %s/var/run/app_ns_sockets/2",
		clientVolume.containerDir)
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
		serverVolume.containerDir)
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

	fmt.Printf("attaching server to vpp")

	// FIXME
	time.Sleep(5 * time.Second)

	srvEnv := append(os.Environ(), ldpreload, "VCL_CONFIG="+srvVcl)
	go StartServerApp(srvCh, stopServerCh, srvEnv)

	err = <-srvCh
	s.assertNil(err)

	fmt.Println("attaching client to vpp")
	clnEnv := append(os.Environ(), ldpreload, "VCL_CONFIG="+clnVcl)
	go StartClientApp(clnEnv, clnCh)

	// wait for client's result
	err = <-clnCh
	s.assertNil(err)

	// stop server
	stopServerCh <- struct{}{}
}
