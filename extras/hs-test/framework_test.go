package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type TapSuite struct {
	suite.Suite
	teardownSuite func()
}

func (s *TapSuite) SetupSuite() {
	time.Sleep(1 * time.Second)
	s.teardownSuite = setupSuite(&s.Suite, "tap")
}

func (s *TapSuite) TearDownSuite() {
	s.teardownSuite()
}

type Veths2Suite struct {
	suite.Suite
	teardownSuite func()
}

func (s *Veths2Suite) SetupSuite() {
	time.Sleep(1 * time.Second)
	s.teardownSuite = setupSuite(&s.Suite, "2peerVeth")
}

func (s *Veths2Suite) TearDownSuite() {
	s.teardownSuite()
}

type NsSuite struct {
	suite.Suite
	teardownSuite func()
}

func (s *NsSuite) SetupSuite() {
	s.teardownSuite = setupSuite(&s.Suite, "ns")
}

func (s *NsSuite) TearDownSuite() {
	s.teardownSuite()
}

func setupSuite(s *suite.Suite, topologyName string) func() {
	t := s.T()
	topology, err := LoadTopology(TopologyDir, topologyName)
	if err != nil {
		t.Fatalf("error on loading topology '%s': %v", topologyName, err)
	}
	err = topology.Configure()
	if err != nil {
		t.Fatalf("failed to configure %s: %v", topologyName, err)
	}

	t.Logf("topo %s loaded", topologyName)
	return func() {
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

func TestVeths2(t *testing.T) {
	var m Veths2Suite
	suite.Run(t, &m)
}
