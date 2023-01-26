package main

import (
	"fmt" // TODO remove this
	"io/ioutil"
	"os"
	"testing"

	"github.com/edwarnicke/exechelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"gopkg.in/yaml.v3"
)

func IsPersistent() bool {
	return os.Getenv("HST_PERSIST") == "1"
}

func IsVerbose() bool {
	return os.Getenv("HST_VERBOSE") == "1"
}

type HstSuite struct {
	suite.Suite
	teardownSuite func()
	netConfigKeys []string
	netConfigs    map[string]*NetConfig
	containers    map[string]*Container
	volumes       []string
}

func (s *HstSuite) TearDownSuite() {
	// s.teardownSuite() // TODO remove this

	s.unconfigureNetworkTopology()
}

func (s *HstSuite) TearDownTest() {
	if IsPersistent() {
		return
	}
	s.ResetContainers()
	s.RemoveVolumes()
	// TODO remove directories used by volumes on host system
}

func (s *HstSuite) SetupTest() {
	for _, volume := range s.volumes {
		cmd := "docker volume create --name=" + volume
		s.log(cmd)
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

func (s *HstSuite) log(args ...any) {
	if IsVerbose() {
		s.T().Log(args...)
	}
}

func (s *HstSuite) skip(args ...any) {
	s.log(args...)
	s.T().SkipNow()
}

func (s *HstSuite) ResetContainers() {
	for _, container := range s.containers {
		container.stop()
	}
}

func (s *HstSuite) RemoveVolumes() {
	for _, volumeName := range s.volumes {
		cmd := "docker volume rm " + volumeName
		exechelper.Run(cmd)
		fmt.Println("Deleting volume:", volumeName)
		os.RemoveAll(volumeName)
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
		volumeMap := elem["volume"].(VolumeConfig)
		hostDir := volumeMap["host-dir"].(string)
		s.volumes = append(s.volumes, hostDir)
	}

	s.containers = make(map[string]*Container)
	for _, elem := range yamlTopo.Containers {
		newContainer, err := NewContainer(elem)
		if err != nil {
			s.T().Fatalf("container config error: %v", err)
		}
		s.log(newContainer.getRunCommand())
		s.containers[newContainer.name] = newContainer
	}
}

func (s *HstSuite) loadNetworkTopology(topologyName string) {
	data, err := ioutil.ReadFile(NetworkTopologyDir + topologyName + ".yaml")
	if err != nil {
		s.T().Fatalf("read error: %v", err)
	}
	var yamlTopo YamlTopology
	err = yaml.Unmarshal(data, &yamlTopo)
	if err != nil {
		s.T().Fatalf("unmarshal error: %v", err)
	}

	s.netConfigs = make(map[string]*NetConfig)
	for _, elem := range yamlTopo.Devices {
		newNetConfig, err := NewNetConfig(elem)
		if err != nil {
			s.T().Fatalf("network config error: %v", err)
		}
		// TODO s.log(newNetConfig.GetCommand()) // this could be useful for dry-run mode
		s.netConfigKeys = append(s.netConfigKeys, newNetConfig.GetName())
		s.netConfigs[s.netConfigKeys[len(s.netConfigKeys)-1]] = &newNetConfig
	}
}

func (s *HstSuite) configureNetworkTopology(topologyName string) {
	s.loadNetworkTopology(topologyName)

	fmt.Printf("Network topology: %+v\n", s.netConfigKeys)

	for _, key := range s.netConfigKeys {
		netConfig := *s.netConfigs[key] // TODO should the map hold just the actual type instead of pointer to the type?
		if err := netConfig.Configure(); err != nil {
			s.T().Fatalf("network config error: %v", err)
		}
	}
}

func (s *HstSuite) unconfigureNetworkTopology() {
	if IsPersistent() {
		return
	}
	for _, key := range s.netConfigKeys {
		netConfig := *s.netConfigs[key] // TODO should the map hold just the actual type instead of pointer to the type?
		netConfig.Unconfigure()
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
