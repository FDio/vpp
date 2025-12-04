package main

import (
	"errors"
	"regexp"
	"strconv"
	"strings"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterVethTests(NsimLossTest)
}
func NsimLossTest(s *VethsSuite) {
	clientVpp := s.Containers.ClientVpp.VppInstance

	s.Log(clientVpp.Vppctl("set nsim poll-main-thread delay 0.01 ms bandwidth 40 gbit packet-size 1400 drop-fraction 0.1"))
	s.Log(clientVpp.Vppctl("nsim output-feature enable-disable host-" + s.Interfaces.Client.Name()))
	o := clientVpp.Vppctl("show nsim")
	s.AssertNotContains(o, "nsim not enabled")
	o = clientVpp.Vppctl("ping " + s.Interfaces.Server.Ip4AddressString() + " repeat 10000 interval 0.0001")
	lines := strings.Split(o, "\n")
	stats := lines[len(lines)-2]
	s.Log(stats)

	re := regexp.MustCompile(`(\d+\.?\d*)\s*%\s*packet loss`)
	matches := re.FindStringSubmatch(stats)
	if len(matches) < 2 {
		s.AssertNil(errors.New("Error when parsing stats."))
	}
	packetLossStr := matches[1]
	packetLoss, err := strconv.ParseFloat(packetLossStr, 64)
	s.AssertNil(err)
	if !s.CoverageRun {
		s.AssertEqual(packetLoss, float64(10), "Packet loss != 10%%")
	}
}
