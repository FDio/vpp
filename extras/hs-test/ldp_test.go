package main

import (
	"fmt"
	"os"
	"time"
)

func (s *VethsSuite) TestLDPreloadIperfVpp() {
	var clnVclConf, srvVclConf Stanza

	serverContainer := s.getContainerByName("server-vpp")
	serverVolume := serverContainer.getVolumeByHostDir("/tmp/server")
	srvVcl := serverVolume.containerDir + "/vcl_srv.conf"

	clientContainer := s.getContainerByName("client-vpp")
	clientVolume := clientContainer.getVolumeByHostDir("/tmp/client")
	clnVcl := clientVolume.containerDir + "/vcl_cln.conf"

	ldpreload := os.Getenv("HST_LDPRELOAD")
	s.assertNotEqual("", ldpreload)

	ldpreload = "LD_PRELOAD=" + ldpreload

	stopServerCh := make(chan struct{}, 1)
	srvCh := make(chan error, 1)
	clnCh := make(chan error)

	fmt.Println("starting VPPs")

	originalWorkDir := serverContainer.workDir
	serverContainer.workDir = serverVolume.containerDir
	_, err := serverContainer.execAction("Configure2Veths srv")
	s.assertNil(err)
	serverContainer.workDir = originalWorkDir

	originalWorkDir = clientContainer.workDir
	clientContainer.workDir = clientVolume.containerDir
	_, err = clientContainer.execAction("Configure2Veths cln")
	s.assertNil(err)
	clientContainer.workDir = originalWorkDir

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
