package main

import (
	"fmt"

	"github.com/edwarnicke/exechelper"
)

func (s *Veths2Suite) TestVclEchoQuic() {
	s.T().Skip("quic test skipping..")
	s.testVclEcho("quic")
}

func (s *Veths2Suite) TestVclEchoUdp() {
	s.T().Skip("udp echo currently broken in vpp, skipping..")
	s.testVclEcho("udp")
}

func (s *Veths2Suite) TestVclEchoTcp() {
	s.testVclEcho("tcp")
}

func (s *Veths2Suite) testVclEcho(proto string) {
	t := s.T()

	exechelper.Run("docker volume create --name=echo-srv-vol")
	exechelper.Run("docker volume create --name=echo-cln-vol")

	srvInstance := "vpp-echo-srv"
	clnInstance := "vpp-echo-cln"
	echoSrv := "echo-srv"
	echoCln := "echo-cln"

	err := dockerRun(srvInstance, "-v echo-srv-vol:/tmp/2veths")
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer func() { exechelper.Run("docker stop " + srvInstance) }()

	err = dockerRun(clnInstance, "-v echo-cln-vol:/tmp/2veths")
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer func() { exechelper.Run("docker stop " + clnInstance) }()

	err = dockerRun(echoSrv, fmt.Sprintf("-v echo-srv-vol:/tmp/%s", echoSrv))
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer func() { exechelper.Run("docker stop " + echoSrv) }()

	err = dockerRun(echoCln, fmt.Sprintf("-v echo-cln-vol:/tmp/%s", echoCln))
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer func() { exechelper.Run("docker stop " + echoCln) }()

	_, err = hstExec("2veths srv", srvInstance)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	_, err = hstExec("2veths cln", clnInstance)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	// run server app
	_, err = hstExec("echo-server "+proto, echoSrv)
	if err != nil {
		t.Errorf("echo server: %v", err)
		return
	}

	o, err := hstExec("echo-client "+proto, echoCln)
	if err != nil {
		t.Errorf("echo client: %v", err)
	}
	fmt.Println(o)
}
