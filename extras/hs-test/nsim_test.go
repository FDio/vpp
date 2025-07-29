package main

import (
	. "fd.io/hs-test/infra"
	"strings"
)

func init() {
	RegisterVethTests(NsimTest)
}
func NsimTest(s *VethsSuite) {
	clientVpp := s.Containers.ClientVpp.VppInstance

	s.Log(clientVpp.Vppctl("set nsim poll-main-thread delay 0.01 ms bandwidth 40 gbit packet-size 1400 drop-fraction 0.1"))
	s.Log(clientVpp.Vppctl("nsim output-feature enable-disable host-" + s.Interfaces.Client.Name()))
	o := clientVpp.Vppctl("show nsim")
	s.AssertNotContains(o, "nsim not enabled")
	o = clientVpp.Vppctl("ping " + s.Interfaces.Server.Ip4AddressString() + " repeat 10000 interval 0.0001")
	lines := strings.Split(o, "\n")
	stats := lines[len(lines)-2]
	s.Log(stats)
	s.AssertContains(stats, "10% packet loss")
}
