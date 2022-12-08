package main

import (
	"fmt"
)

func (s *VethsSuite) TestEchoBuiltin() {

	serverContainer := s.GetContainers()[0]
	clientContainer := s.GetContainers()[1]

	_, err := hstExec("Configure2Veths srv", serverContainer.name)
	s.assertNil(err)

	_, err = hstExec("Configure2Veths cln", clientContainer.name)
	s.assertNil(err)

	_, err = hstExec(
		"RunEchoSrvInternal private-segment-size 1g fifo-size 4 no-echo",
		serverContainer.name)
	s.assertNil(err)

	o, err := hstExec(
		"RunEchoClnInternal nclients 10000 bytes 1 syn-timeout 100 test-timeout 100 no-return private-segment-size 1g fifo-size 4",
		clientContainer.name)
	s.assertNil(err)
	fmt.Println(o)
}
