package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/edwarnicke/exechelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"gopkg.in/yaml.v3"
)

const (
	defaultNetworkNumber int = 1
)

var IsPersistent = flag.Bool("persist", false, "persists topology config")
var IsVerbose = flag.Bool("verbose", false, "verbose test output")

type HstSuite struct {
	suite.Suite
	containers    map[string]*Container
	volumes       []string
	netConfigs    []NetConfig
	netInterfaces map[string]*NetInterface
	addresser     *Addresser
	testIds       map[string]string
}

func (s *HstSuite) TearDownSuite() {
	s.unconfigureNetworkTopology()
}

func (s *HstSuite) TearDownTest() {
	if *IsPersistent {
		return
	}
	s.ResetContainers()
	s.RemoveVolumes()
}

func (s *HstSuite) SetupTest() {
	s.SetupVolumes()
	s.SetupContainers()
}

func (s *HstSuite) SetupVolumes() {
	for _, volume := range s.volumes {
		cmd := "docker volume create --name=" + volume
		s.log(cmd)
		exechelper.Run(cmd)
	}
}

func (s *HstSuite) SetupContainers() {
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

func (s *HstSuite) assertNotEmpty(object interface{}, msgAndArgs ...interface{}) {
	if !assert.NotEmpty(s.T(), object, msgAndArgs...) {
		s.hstFail()
	}
}

func (s *HstSuite) log(args ...any) {
	if *IsVerbose {
		s.T().Helper()
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
		os.RemoveAll(volumeName)
	}
}

func (s *HstSuite) getContainerByName(name string) *Container {
	return s.containers[name]
}

/*
 * Create a copy and return its address, so that individial tests which call this
 * are not able to modify the original container and affect other tests by doing that
 */
func (s *HstSuite) getTransientContainerByName(name string) *Container {
	containerCopy := *s.containers[name]
	return &containerCopy
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
		newContainer.suite = s
		if err != nil {
			s.T().Fatalf("container config error: %v", err)
		}
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

	s.addresser = NewAddresser(s)
	s.netInterfaces = make(map[string]*NetInterface)
	for _, elem := range yamlTopo.Devices {
		switch elem["type"].(string) {
		case NetNs:
			{
				if namespace, err := NewNetNamespace(elem); err == nil {
					s.netConfigs = append(s.netConfigs, &namespace)
				} else {
					s.T().Fatalf("network config error: %v", err)
				}
			}
		case Veth, Tap:
			{
				if netIf, err := NewNetworkInterface(elem, s.addresser); err == nil {
					s.netConfigs = append(s.netConfigs, netIf)
					s.netInterfaces[netIf.Name()] = netIf
				} else {
					s.T().Fatalf("network config error: %v", err)
				}
			}
		case Bridge:
			{
				if bridge, err := NewBridge(elem); err == nil {
					s.netConfigs = append(s.netConfigs, &bridge)
				} else {
					s.T().Fatalf("network config error: %v", err)
				}
			}
		}
	}
}

func (s *HstSuite) configureNetworkTopology(topologyName string) {
	s.loadNetworkTopology(topologyName)

	for _, nc := range s.netConfigs {
		if err := nc.Configure(); err != nil {
			s.T().Fatalf("network config error: %v", err)
		}
	}
}

func (s *HstSuite) unconfigureNetworkTopology() {
	if *IsPersistent {
		return
	}
	for _, nc := range s.netConfigs {
		nc.Unconfigure()
	}
}

func (s *HstSuite) getTestId() string {
	testName := s.T().Name()

	if s.testIds == nil {
		s.testIds = map[string]string{}
	}

	if _, ok := s.testIds[testName]; !ok {
		s.testIds[testName] = time.Now().Format(time.RFC3339)
	}

	return s.testIds[testName]
}

type AddressCounter = int

type Addresser struct {
	networks map[int]AddressCounter
	suite    *HstSuite
}

func (a *Addresser) AddNetwork(networkNumber int) {
	a.networks[networkNumber] = 1
}

func (a *Addresser) NewIp4Address(inputNetworkNumber ...int) (string, error) {
	var networkNumber int = 0
	if len(inputNetworkNumber) > 0 {
		networkNumber = inputNetworkNumber[0]
	}

	if _, ok := a.networks[networkNumber]; !ok {
		a.AddNetwork(networkNumber)
	}

	numberOfAddresses := a.networks[networkNumber]

	if numberOfAddresses == 254 {
		return "", fmt.Errorf("no available IPv4 addresses")
	}

	address := fmt.Sprintf("10.10.%v.%v/24", networkNumber, numberOfAddresses)
	a.networks[networkNumber] = numberOfAddresses + 1

	return address, nil
}

func NewAddresser(suite *HstSuite) *Addresser {
	var addresser = new(Addresser)
	addresser.suite = suite
	addresser.networks = make(map[int]AddressCounter)
	addresser.AddNetwork(0)
	return addresser
}
