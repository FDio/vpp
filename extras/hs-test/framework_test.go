package main

import (
	"testing"
	"time"
	"fmt"

	"github.com/stretchr/testify/suite"
	"github.com/edwarnicke/exechelper"
)

type HsSuite struct {
	test *testing.T
	containers []string
	volumes []string
}

func NewHsSuite(t *testing.T) *HsSuite {
	return &HsSuite{t, make([]string, 0), make([]string, 0)}
}

func (s *HsSuite) NewContainer(name string) (*Container, error) {
	if name == "" {
		return nil, fmt.Errorf("creating container failed: name must not be blank")
	}

	s.containers = append(s.containers, name)

	container := new(Container)
	container.name = name
	return container, nil
}

func (s *HsSuite) StopContainers() {
	for _, containerName := range s.containers {
		exechelper.Run("docker stop " + containerName)
	}
}

func (s *HsSuite) RemoveVolumes() {
	for _, volumeName := range s.volumes {
		exechelper.Run("docker volume rm " + volumeName)
	}
}

func (s *HsSuite) AssertIsBlank(testObject any, message string, err ...error) {
	if testObject == nil {
		return
	}

	if (err == nil) {
		s.test.Errorf(message)
	} else {
		s.test.Errorf(fmt.Sprintf("%s: %v", message, err[0]))
	}
}

func (s *HsSuite) AssertIsNotBlank(testObject any, message string, err ...error) {
	if testObject != nil {
		return
	}

	if (err == nil) {
		s.test.Errorf(message)
	} else {
		s.test.Errorf(fmt.Sprintf("%s: %v", message, err[0]))
	}
}

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
	*HsSuite
}

func (s *Veths2Suite) SetupSuite() {
	time.Sleep(1 * time.Second)
	s.teardownSuite = setupSuite(&s.Suite, "2peerVeth")
}

func (s *Veths2Suite) TearDownSuite() {
	s.teardownSuite()
	s.StopContainers()
	s.RemoveVolumes()
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
	m := Veths2Suite{suite.Suite{}, nil, NewHsSuite(t)}
	suite.Run(t, &m)

}
