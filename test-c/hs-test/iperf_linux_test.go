package main

import (
	"fmt"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterIperfSoloTests(IperfUdpLinuxTest)
}

func IperfUdpLinuxTest(s *IperfSuite) {
	serverIpAddress := s.Interfaces.Server.Ip4AddressString()
	clientIpAddress := s.Interfaces.Client.Ip4AddressString()

	cmd := fmt.Sprintf("iperf3 -4 -s -1 -D -B %s -p %s --logfile %s",
		serverIpAddress, s.Ports.Port1, s.IperfLogFileName(s.Containers.Server))
	o, err := s.Containers.Server.Exec(false, cmd)
	s.AssertNil(err, o)
	s.Log("server running")

	cmd = "iperf3 -c " + serverIpAddress + " -B " + clientIpAddress +
		" -u -l 1460 -b 10g -J -p " + s.Ports.Port1
	o, err = s.Containers.Client.Exec(false, cmd)

	s.AssertNil(err, o)
	result := s.ParseJsonIperfOutput([]byte(o))
	s.LogJsonIperfOutput(result)
	s.AssertIperfMinTransfer(result, 400)
}
