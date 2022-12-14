package main

import (
	"fmt"
	"testing"
	"io/ioutil"

	"github.com/edwarnicke/exechelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"gopkg.in/yaml.v3"
)

type HstSuite struct {
	suite.Suite
	teardownSuite func()
	containers    map[string]*Container
	volumes       []string
}

func (s *HstSuite) TearDownSuite() {
	s.teardownSuite()
}

func (s *HstSuite) TearDownTest() {
	s.ResetContainers()
	s.RemoveVolumes()
}

func (s *HstSuite) SetupTest() {
	for _, volume := range s.volumes {
		cmd := "docker volume create --name=" + volume
		fmt.Println(cmd)
		exechelper.Run(cmd)
	}
	for _, container := range s.containers {
		if container.isOptional == false {
			container.run()
		}
	}
}

func (s *HstSuite) hstFail() {
	s.T().FailNow()
}

func (s *HstSuite) assertNil(object interface{}, msgAndArgs ...interface{}) {
	if !assert.Nil(s.T(), object, msgAndArgs...) {
		s.hstFail()
	}
}

func (s *HstSuite) assertNotNil(object interface{}, msgAndArgs ...interface{}) {
	if !assert.NotNil(s.T(), object, msgAndArgs...) {
		s.hstFail()
	}
}

func (s *HstSuite) assertEqual(expected, actual interface{}, msgAndArgs ...interface{}) {
	if !assert.Equal(s.T(), expected, actual, msgAndArgs...) {
		s.hstFail()
	}
}

func (s *HstSuite) assertNotEqual(expected, actual interface{}, msgAndArgs ...interface{}) {
	if !assert.NotEqual(s.T(), expected, actual, msgAndArgs...) {
		s.hstFail()
	}
}

func (s *HstSuite) assertContains(testString, contains interface{}, msgAndArgs ...interface{}) {
	if !assert.Contains(s.T(), testString, contains, msgAndArgs...) {
		s.hstFail()
	}
}

func (s *HstSuite) assertNotContains(testString, contains interface{}, msgAndArgs ...interface{}) {
	if !assert.NotContains(s.T(), testString, contains, msgAndArgs...) {
		s.hstFail()
	}
}

func (s *HstSuite) ResetContainers() {
	for _, container := range s.containers {
		container.stop()
	}
}

func (s *HstSuite) NewVolume(name string) error {
	err := exechelper.Run(fmt.Sprintf("docker volume create --name=%s", name))
	if err != nil {
		return err
	}

	s.volumes = append(s.volumes, name)
	return nil
}

func (s *HstSuite) RemoveVolumes() {
	for _, volumeName := range s.volumes {
		cmd := "docker volume rm " + volumeName
		exechelper.Run(cmd)
	}
}

func (s *HstSuite) getContainerByName(name string) *Container {
	return s.containers[name]
}

func (s *HstSuite) loadContainerTopology(topologyName string) {
	data, err := ioutil.ReadFile(ContainerTopologyDir + topologyName + ".yaml")
	if err != nil {
		s.T().Fatalf("read error: %v", err)
	}
	var yamlTopo YamlTopology
	err = yaml.Unmarshal(data, &yamlTopo)
	if err != nil {
		s.T().Fatalf("unmarshal error: %v", err)
	}

	for _, elem := range yamlTopo.Volumes {
		s.volumes = append(s.volumes, elem)
	}

	s.containers = make(map[string]*Container)
	for _, elem := range yamlTopo.Containers {
		newContainer, err := NewContainer(elem)
		if err != nil {
			s.T().Fatalf("config error: %v", err)
		}
		s.containers[newContainer.name] = newContainer
	}
}

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

func TestVeths(t *testing.T) {
	var m VethsSuite
	suite.Run(t, &m)
}
