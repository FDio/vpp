package main

import (
	"testing"
	"time"
	"fmt"

	"github.com/stretchr/testify/suite"
	"github.com/edwarnicke/exechelper"
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
	containers []string
	volumes []string
}

func (s *Veths2Suite) SetupSuite() {
	time.Sleep(1 * time.Second)
	s.teardownSuite = setupSuite(&s.Suite, "2peerVeth")
}

func (s *Veths2Suite) TearDownSuite() {
	s.teardownSuite()
	fmt.Println("Stop containers here") // TODO
	for _, containerName := range s.containers {
		fmt.Println("Container: ", containerName)
		exechelper.Run("docker stop " + containerName)
	}
	fmt.Println("Delete volumes here") // TODO
}

// TODO think how to make it so that NewContainer wouldn't need to be re-implemented for each suite
// ...  F.T.: toto mozeme asi tiez abstrahovat do novej parent suity napr. HsSuite a ta bude embednuta v ostatnych
// TODO does it have to be like this, to be able to delete the containers from suite tear-down?
func (s *Veths2Suite) NewContainer(name string) *Container {
	fmt.Println("Create container: ", name)
	if (s.containers == nil) {
		s.containers = make([]string, 0)
	}
	s.containers = append(s.containers, name)

	container := new(Container)
	container.name = name
	return container
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
