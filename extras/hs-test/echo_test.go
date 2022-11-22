package main

import (
	"fmt"

	"github.com/edwarnicke/exechelper"
)

func (s *Veths2Suite) TestEchoBuiltin() {
	t := s.T()
	srvInstance := "echo-srv-internal"
	clnInstance := "echo-cln-internal"
	err := dockerRun(srvInstance, "")
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer func() { exechelper.Run("docker stop " + srvInstance) }()

	err = dockerRun(clnInstance, "")
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

	_, err = hstExec("RunEchoSrvInternal private-segment-size 1g fifo-size 4 no-echo", srvInstance)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	o, err := hstExec("RunEchoClnInternal nclients 10000 bytes 1 syn-timeout 100 test-timeout 100 no-return private-segment-size 1g fifo-size 4", clnInstance)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	fmt.Println(o)
}
