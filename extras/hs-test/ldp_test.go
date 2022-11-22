package main

import (
	"fmt"
	"os"
	"time"

	"github.com/edwarnicke/exechelper"
)

func (s *Veths2Suite) TestLDPreloadIperfVpp() {
	t := s.T()
	var clnVclConf, srvVclConf Stanza

	srvInstance := "vpp-ldp-srv"
	clnInstance := "vpp-ldp-cln"
	srvPath := "/tmp/" + srvInstance
	clnPath := "/tmp/" + clnInstance
	srvVcl := srvPath + "/vcl_srv.conf"
	clnVcl := clnPath + "/vcl_cln.conf"

	exechelper.Run("mkdir " + srvPath)
	exechelper.Run("mkdir " + clnPath)

	ldpreload := os.Getenv("HST_LDPRELOAD")
	s.Assert().NotEqual("", ldpreload)

	ldpreload = "LD_PRELOAD=" + ldpreload

	stopServerCh := make(chan struct{}, 1)
	srvCh := make(chan error, 1)
	clnCh := make(chan error)

	fmt.Println("starting VPPs")

	err := dockerRun(srvInstance, fmt.Sprintf("-v /tmp/%s:/tmp", srvInstance))
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer func() { exechelper.Run("docker stop " + srvInstance) }()

	err = dockerRun(clnInstance, fmt.Sprintf("-v /tmp/%s:/tmp", clnInstance))
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer func() { exechelper.Run("docker stop " + clnInstance) }()

	_, err = hstExec("Configure2Veths srv", srvInstance)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	_, err = hstExec("Configure2Veths cln", clnInstance)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	err = clnVclConf.
		NewStanza("vcl").
		Append("rx-fifo-size 4000000").
		Append("tx-fifo-size 4000000").
		Append("app-scope-local").
		Append("app-scope-global").
		Append("use-mq-eventfd").
		Append(fmt.Sprintf("app-socket-api /tmp/%s/Configure2Veths/var/run/app_ns_sockets/2", clnInstance)).Close().
		SaveToFile(clnVcl)
	if err != nil {
		t.Errorf("%v", err)
		t.FailNow()
	}

	err = srvVclConf.
		NewStanza("vcl").
		Append("rx-fifo-size 4000000").
		Append("tx-fifo-size 4000000").
		Append("app-scope-local").
		Append("app-scope-global").
		Append("use-mq-eventfd").
		Append(fmt.Sprintf("app-socket-api /tmp/%s/Configure2Veths/var/run/app_ns_sockets/1", srvInstance)).Close().
		SaveToFile(srvVcl)
	if err != nil {
		t.Errorf("%v", err)
		t.FailNow()
	}
	fmt.Printf("attaching server to vpp")

	// FIXME
	time.Sleep(5 * time.Second)

	srvEnv := append(os.Environ(), ldpreload, "VCL_CONFIG="+srvVcl)
	go StartServerApp(srvCh, stopServerCh, srvEnv)

	err = <-srvCh
	if err != nil {
		s.FailNow("vcl server", "%v", err)
	}

	fmt.Println("attaching client to vpp")
	clnEnv := append(os.Environ(), ldpreload, "VCL_CONFIG="+clnVcl)
	go StartClientApp(clnEnv, clnCh)

	// wait for client's result
	err = <-clnCh
	if err != nil {
		s.Failf("client", "%v", err)
	}

	// stop server
	stopServerCh <- struct{}{}
}
