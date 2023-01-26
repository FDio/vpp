package main

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

func setupSuite(s *suite.Suite, topologyName string) func() {
	t := s.T()
	topology, err := LoadTopology(NetworkTopologyDir, topologyName)
	if err != nil {
		t.Fatalf("error on loading topology '%s': %v", topologyName, err)
	}
	err = topology.Configure()
	if err != nil {
		t.Fatalf("failed to configure %s: %v", topologyName, err)
	}

	return func() {
		if IsPersistent() {
			return
		}
		topology.Unconfigure()
	}
}

func TestTapSuite(t *testing.T) {
	var m TapSuite
	suite.Run(t, &m)
}

func TestNs(t *testing.T) {
	var m NsSuite
	suite.Run(t, &m)
}

func TestVeths(t *testing.T) {
	var m VethsSuite
	suite.Run(t, &m)
}

func TestNoTopo(t *testing.T) {
	var m NoTopoSuite
	suite.Run(t, &m)
}
