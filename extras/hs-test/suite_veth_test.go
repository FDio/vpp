package main

import (
	"time"
)

type VethsSuite struct {
	HstSuite
}

func (s *VethsSuite) SetupSuite() {
	time.Sleep(1 * time.Second)
	// s.teardownSuite = setupSuite(&s.Suite, "2peerVeth")
	s.configureNetworkTopology("2peerVeth")
	s.loadContainerTopology("2peerVeth")
}
