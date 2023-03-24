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

var isPersistent = flag.Bool("persist", false, "persists topology config")
var isVerbose = flag.Bool("verbose", false, "verbose test output")
var isUnconfiguring = flag.Bool("unconfigure", false, "remove topology")
var isVppDebug = flag.Bool("debug", false, "attach gdb to vpp")

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
	if *isPersistent {
		return
	}
	s.resetContainers()
	s.removeVolumes()
}

func (s *HstSuite) skipIfUnconfiguring() {
	if *isUnconfiguring {
		s.skip("skipping to unconfigure")
	}
}

func (s *HstSuite) SetupTest() {
	s.skipIfUnconfiguring()
	s.setupVolumes()
	s.setupContainers()
}

func (s *HstSuite) setupVolumes() {
	for _, volume := range s.volumes {
		cmd := "docker volume create --name=" + volume
		s.log(cmd)
		exechelper.Run(cmd)
	}
}

func (s *HstSuite) setupContainers() {
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
	if *isVerbose {
		s.T().Helper()
		s.T().Log(args...)
	}
}

func (s *HstSuite) skip(args ...any) {
	s.log(args...)
	s.T().SkipNow()
}

func (s *HstSuite) resetContainers() {
	for _, container := range s.containers {
		container.stop()
	}
}

func (s *HstSuite) removeVolumes() {
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
	data, err := ioutil.ReadFile(containerTopologyDir + topologyName + ".yaml")
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
		newContainer, err := newContainer(elem)
		newContainer.suite = s
		if err != nil {
			s.T().Fatalf("container config error: %v", err)
		}
		s.containers[newContainer.name] = newContainer
	}
}

func (s *HstSuite) loadNetworkTopology(topologyName string) {
	data, err := ioutil.ReadFile(networkTopologyDir + topologyName + ".yaml")
	if err != nil {
		s.T().Fatalf("read error: %v", err)
	}
	var yamlTopo YamlTopology
	err = yaml.Unmarshal(data, &yamlTopo)
	if err != nil {
		s.T().Fatalf("unmarshal error: %v", err)
	}

	s.addresser = newAddresser(s)
	s.netInterfaces = make(map[string]*NetInterface)
	for _, elem := range yamlTopo.Devices {
		switch elem["type"].(string) {
		case NetNs:
			{
				if namespace, err := newNetNamespace(elem); err == nil {
					s.netConfigs = append(s.netConfigs, &namespace)
				} else {
					s.T().Fatalf("network config error: %v", err)
				}
			}
		case Veth, Tap:
			{
				if netIf, err := newNetworkInterface(elem, s.addresser); err == nil {
					s.netConfigs = append(s.netConfigs, netIf)
					s.netInterfaces[netIf.Name()] = netIf
				} else {
					s.T().Fatalf("network config error: %v", err)
				}
			}
		case Bridge:
			{
				if bridge, err := newBridge(elem); err == nil {
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

	if *isUnconfiguring {
		return
	}

	for _, nc := range s.netConfigs {
		if err := nc.configure(); err != nil {
			s.T().Fatalf("network config error: %v", err)
		}
	}
}

func (s *HstSuite) unconfigureNetworkTopology() {
	if *isPersistent {
		return
	}
	for _, nc := range s.netConfigs {
		nc.unconfigure()
	}
}

func (s *HstSuite) getTestId() string {
	testName := s.T().Name()

	if s.testIds == nil {
		s.testIds = map[string]string{}
	}

	if _, ok := s.testIds[testName]; !ok {
		s.testIds[testName] = time.Now().Format("2006-01-02_15-04-05")
	}

	return s.testIds[testName]
}

type AddressCounter = int

type Addresser struct {
	networks map[int]AddressCounter
	suite    *HstSuite
}

func (a *Addresser) addNetwork(networkNumber int) {
	a.networks[networkNumber] = 1
}

func (a *Addresser) newIp4Address(inputNetworkNumber ...int) (string, error) {
	var networkNumber int = 0
	if len(inputNetworkNumber) > 0 {
		networkNumber = inputNetworkNumber[0]
	}

	if _, ok := a.networks[networkNumber]; !ok {
		a.addNetwork(networkNumber)
	}

	numberOfAddresses := a.networks[networkNumber]

	if numberOfAddresses == 254 {
		return "", fmt.Errorf("no available IPv4 addresses")
	}

	address := fmt.Sprintf("10.10.%v.%v/24", networkNumber, numberOfAddresses)
	a.networks[networkNumber] = numberOfAddresses + 1

	return address, nil
}

func newAddresser(suite *HstSuite) *Addresser {
	var addresser = new(Addresser)
	addresser.suite = suite
	addresser.networks = make(map[int]AddressCounter)
	addresser.addNetwork(0)
	return addresser
}
