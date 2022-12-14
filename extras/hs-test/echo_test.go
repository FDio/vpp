package main

import (
	"fmt"
)

func (s *VethsSuite) TestEchoBuiltin() {
	serverContainer := s.containers[0]
	serverVolume := s.volumes[0]
	_, err := serverContainer.useVolumeAsWorkDir(serverVolume).execAction("Configure2Veths srv")
	s.assertNil(err)

	clientContainer := s.containers[1]
	clientVolume := s.volumes[1]
	_, err = clientContainer.useVolumeAsWorkDir(clientVolume).execAction("Configure2Veths cln")
	s.assertNil(err)

	_, err = serverContainer.useVolumeAsWorkDir(serverVolume).execAction("RunEchoSrvInternal private-segment-size 1g fifo-size 4 no-echo")
	s.assertNil(err)

	o, err := clientContainer.useVolumeAsWorkDir(clientVolume).execAction("RunEchoClnInternal nclients 10000 bytes 1 syn-timeout 100 test-timeout 100 no-return private-segment-size 1g fifo-size 4")
	s.assertNil(err)
	fmt.Println(o)
}
