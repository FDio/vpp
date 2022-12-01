package main

import (
	"fmt"

	"github.com/edwarnicke/exechelper"
)

func (s *VethsSuite) TestEchoBuiltin() {
	srvInstance := "echo-srv-internal"
	clnInstance := "echo-cln-internal"

	s.assertNil(dockerRun(srvInstance, ""), "failed to start docker (srv)")
	defer func() { exechelper.Run("docker stop " + srvInstance) }()

	s.assertNil(dockerRun(clnInstance, ""), "failed to start docker (cln)")
	defer func() { exechelper.Run("docker stop " + clnInstance) }()

	_, err := hstExec("Configure2Veths srv", srvInstance)
	s.assertNil(err)

	_, err = hstExec("Configure2Veths cln", clnInstance)
	s.assertNil(err)

	_, err = hstExec("RunEchoSrvInternal private-segment-size 1g fifo-size 4 no-echo", srvInstance)
	s.assertNil(err)

	o, err := hstExec("RunEchoClnInternal nclients 10000 bytes 1 syn-timeout 100 test-timeout 100 no-return private-segment-size 1g fifo-size 4", clnInstance)
	s.assertNil(err)
	fmt.Println(o)
}
