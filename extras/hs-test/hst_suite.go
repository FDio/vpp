package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/edwarnicke/exechelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"go.fd.io/govpp/binapi/ip_types"
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
	teardownSuite     func()
	containers        map[string]*Container
	volumes           []string
	networkNamespaces map[string]*NetworkNamespace
	veths             map[string]*NetworkInterfaceVeth
	taps              map[string]*NetworkInterfaceTap
	bridges           map[string]*NetworkBridge
	numberOfAddresses int
}

func (s *HstSuite) TearDownSuite() {
	if s.teardownSuite != nil {
		s.teardownSuite() // TODO remove this after config moved to SetupTest() for each suite
	}

	s.unconfigureNetworkTopology()
}

func (s *HstSuite) TearDownTest() {
	if IsPersistent() {
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
		os.RemoveAll(volumeName)
	}
}

func (s *HstSuite) getContainerByName(name string) *Container {
	return s.containers[name]
}

func (s *HstSuite) getContainerCopyByName(name string) *Container {
	// Create a copy and return its address, so that individial tests which call this
	// are not able to modify the original container and affect other tests by doing that
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

	s.networkNamespaces = make(map[string]*NetworkNamespace)
	s.veths = make(map[string]*NetworkInterfaceVeth)
	s.taps = make(map[string]*NetworkInterfaceTap)
	s.bridges = make(map[string]*NetworkBridge)
	for _, elem := range yamlTopo.Devices {
		switch elem["type"].(string) {
		case NetNs:
			{
				if namespace, err := NewNetNamespace(elem); err == nil {
					s.networkNamespaces[namespace.Name()] = &namespace
				} else {
					s.T().Fatalf("network config error: %v", err)
				}
			}
		case Veth:
			{
				if veth, err := NewVeth(elem); err == nil {
					s.veths[veth.Name()] = &veth
				} else {
					s.T().Fatalf("network config error: %v", err)
				}
			}
		case Tap:
			{
				if tap, err := NewTap(elem); err == nil {
					s.taps[tap.Name()] = &tap
				} else {
					s.T().Fatalf("network config error: %v", err)
				}
			}
		case Bridge:
			{
				if bridge, err := NewBridge(elem); err == nil {
					s.bridges[bridge.Name()] = &bridge
				} else {
					s.T().Fatalf("network config error: %v", err)
				}
			}
		}
	}
}

func (s *HstSuite) configureNetworkTopology(topologyName string) {
	s.loadNetworkTopology(topologyName)

	for _, ns := range s.networkNamespaces {
		if err := ns.Configure(); err != nil {
			s.T().Fatalf("network config error: %v", err)
		}
	}
	for _, veth := range s.veths {
		if err := veth.Configure(); err != nil {
			s.T().Fatalf("network config error: %v", err)
		}
	}
	for _, tap := range s.taps {
		if err := tap.Configure(); err != nil {
			s.T().Fatalf("network config error: %v", err)
		}
	}
	for _, bridge := range s.bridges {
		if err := bridge.Configure(); err != nil {
			s.T().Fatalf("network config error: %v", err)
		}
	}
}

func (s *HstSuite) unconfigureNetworkTopology() {
	if IsPersistent() {
		return
	}
	for _, ns := range s.networkNamespaces {
		ns.Unconfigure()
	}
	for _, veth := range s.veths {
		veth.Unconfigure()
	}
	for _, tap := range s.taps {
		tap.Unconfigure()
	}
	for _, bridge := range s.bridges {
		bridge.Unconfigure()
	}
}

func (s *HstSuite) NewAddress() (AddressWithPrefix, error) {
	var ipPrefix AddressWithPrefix
	var err error

	if s.numberOfAddresses == 255 {
		s.T().Fatalf("no available IPv4 addresses")
	}

	address := fmt.Sprintf("10.10.10.%v/24", s.numberOfAddresses+1)
	ipPrefix, err = ip_types.ParseAddressWithPrefix(address)
	if err != nil {
		return AddressWithPrefix{}, err
	}
	s.numberOfAddresses++

	return ipPrefix, nil
}
