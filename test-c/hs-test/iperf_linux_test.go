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

	cmd := fmt.Sprintf("iperf3 -4 -s --one-off -D -B %s -p %s --logfile %s",
		serverIpAddress, s.Ports.Port1, s.IperfLogFileName(s.Containers.Server))
	o, err := s.Containers.Server.Exec(false, cmd)
	s.AssertNil(err, o)
	s.Log("server running")

	cmd = "iperf3 -c " + serverIpAddress + " -B " + clientIpAddress +
		" -u -l 1460 -b 10g -p " + s.Ports.Port1
	o, err = s.Containers.Client.Exec(false, cmd)

	fileLog, _ := s.Containers.Server.Exec(false, "cat "+s.IperfLogFileName(s.Containers.Server))
	s.Log("*** Server logs: \n%s\n***", fileLog)

	s.Log(o)
	s.AssertNil(err, o)
	result, err := ParseIperfText(o)
	s.AssertNil(err)

	s.AssertGreaterEqual(result.BitrateMbps, 400)
}
