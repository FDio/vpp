package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/edwarnicke/exechelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"gopkg.in/yaml.v3"
)

const (
	DEFAULT_NETWORK_NUM int = 1
)

var isPersistent = flag.Bool("persist", false, "persists topology config")
var isVerbose = flag.Bool("verbose", false, "verbose test output")
var isUnconfiguring = flag.Bool("unconfigure", false, "remove topology")
var isVppDebug = flag.Bool("debug", false, "attach gdb to vpp")
var nConfiguredCpus = flag.Int("cpus", 1, "number of CPUs assigned to vpp")

type HstSuite struct {
	suite.Suite
	containers       map[string]*Container
	volumes          []string
	netConfigs       []NetConfig
	netInterfaces    map[string]*NetInterface
	ip4AddrAllocator *Ip4AddressAllocator
	testIds          map[string]string
	cpuAllocator     *CpuAllocatorT
	cpuContexts      []*CpuContext
	cpuPerVpp        int
}

func (s *HstSuite) SetupSuite() {
	var err error
	s.cpuAllocator, err = CpuAllocator()
	if err != nil {
		s.FailNow("failed to init cpu allocator: %v", err)
	}
	s.cpuPerVpp = *nConfiguredCpus
}

func (s *HstSuite) AllocateCpus() []int {
	cpuCtx, err := s.cpuAllocator.Allocate(s.cpuPerVpp)
	s.AssertNil(err)
	s.AddCpuContext(cpuCtx)
	return cpuCtx.cpus
}

func (s *HstSuite) AddCpuContext(cpuCtx *CpuContext) {
	s.cpuContexts = append(s.cpuContexts, cpuCtx)
}

func (s *HstSuite) TearDownSuite() {
	s.UnconfigureNetworkTopology()
}

func (s *HstSuite) TearDownTest() {
	if *isPersistent {
		return
	}
	for _, c := range s.cpuContexts {
		c.Release()
	}
	s.ResetContainers()
	s.RemoveVolumes()
}

func (s *HstSuite) SkipIfUnconfiguring() {
	if *isUnconfiguring {
		s.Skip("skipping to unconfigure")
	}
}

func (s *HstSuite) SetupTest() {
	s.SkipIfUnconfiguring()
	s.setupVolumes()
	s.SetupContainers()
}

func (s *HstSuite) setupVolumes() {
	for _, volume := range s.volumes {
		cmd := "docker volume create --name=" + volume
		s.Log(cmd)
		exechelper.Run(cmd)
	}
}

func (s *HstSuite) SetupContainers() {
	for _, container := range s.containers {
		if !container.isOptional {
			container.Run()
		}
	}
}

func (s *HstSuite) HstFail() {
	s.T().FailNow()
}

func (s *HstSuite) AssertNil(object interface{}, msgAndArgs ...interface{}) {
	if !assert.Nil(s.T(), object, msgAndArgs...) {
		s.HstFail()
	}
}

func (s *HstSuite) AssertNotNil(object interface{}, msgAndArgs ...interface{}) {
	if !assert.NotNil(s.T(), object, msgAndArgs...) {
		s.HstFail()
	}
}

func (s *HstSuite) AssertEqual(expected, actual interface{}, msgAndArgs ...interface{}) {
	if !assert.Equal(s.T(), expected, actual, msgAndArgs...) {
		s.HstFail()
	}
}

func (s *HstSuite) AssertNotEqual(expected, actual interface{}, msgAndArgs ...interface{}) {
	if !assert.NotEqual(s.T(), expected, actual, msgAndArgs...) {
		s.HstFail()
	}
}

func (s *HstSuite) AssertContains(testString, contains interface{}, msgAndArgs ...interface{}) {
	if !assert.Contains(s.T(), testString, contains, msgAndArgs...) {
		s.HstFail()
	}
}

func (s *HstSuite) AssertNotContains(testString, contains interface{}, msgAndArgs ...interface{}) {
	if !assert.NotContains(s.T(), testString, contains, msgAndArgs...) {
		s.HstFail()
	}
}

func (s *HstSuite) AssertNotEmpty(object interface{}, msgAndArgs ...interface{}) {
	if !assert.NotEmpty(s.T(), object, msgAndArgs...) {
		s.HstFail()
	}
}

func (s *HstSuite) AssertFileSize(f1, f2 string) {
	fi1, err := os.Stat(f1)
	s.AssertNil(err)

	fi2, err1 := os.Stat(f2)
	s.AssertNil(err1)

	s.AssertEqual(fi1.Size(), fi2.Size(), fmt.Errorf("file sizes differ (%d vs %d)", fi1.Size(), fi2.Size()))
}

func (s *HstSuite) Log(args ...any) {
	if *isVerbose {
		s.T().Helper()
		s.T().Log(args...)
	}
}

func (s *HstSuite) Skip(args ...any) {
	s.Log(args...)
	s.T().SkipNow()
}

func (s *HstSuite) SkipIfMultiWorker(args ...any) {
	if *nConfiguredCpus > 1 {
		s.Skip("test case not supported with multiple vpp workers")
	}
}

func (s *HstSuite) SkipUnlessExtendedTestsBuilt() {
	imageName := "hs-test/nginx-http3"

	cmd := exec.Command("docker", "images", imageName)
	byteOutput, err := cmd.CombinedOutput()
	if err != nil {
		s.Log("error while searching for docker image")
		return
	}
	if !strings.Contains(string(byteOutput), imageName) {
		s.Skip("extended tests not built")
	}
}

func (s *HstSuite) ResetContainers() {
	for _, container := range s.containers {
		container.Stop()
	}
}

func (s *HstSuite) RemoveVolumes() {
	for _, volumeName := range s.volumes {
		cmd := "docker volume rm " + volumeName
		exechelper.Run(cmd)
		os.RemoveAll(volumeName)
	}
}

func (s *HstSuite) GetContainerByName(name string) *Container {
	return s.containers[name]
}

/*
 * Create a copy and return its address, so that individial tests which call this
 * are not able to modify the original container and affect other tests by doing that
 */
func (s *HstSuite) GetTransientContainerByName(name string) *Container {
	containerCopy := *s.containers[name]
	return &containerCopy
}

func (s *HstSuite) LoadContainerTopology(topologyName string) {
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
		newContainer, err := NewContainer(elem)
		newContainer.suite = s
		if err != nil {
			s.T().Fatalf("container config error: %v", err)
		}
		s.containers[newContainer.name] = newContainer
	}
}

func (s *HstSuite) LoadNetworkTopology(topologyName string) {
	data, err := ioutil.ReadFile(networkTopologyDir + topologyName + ".yaml")
	if err != nil {
		s.T().Fatalf("read error: %v", err)
	}
	var yamlTopo YamlTopology
	err = yaml.Unmarshal(data, &yamlTopo)
	if err != nil {
		s.T().Fatalf("unmarshal error: %v", err)
	}

	s.ip4AddrAllocator = NewIp4AddressAllocator()
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
				if netIf, err := NewNetworkInterface(elem, s.ip4AddrAllocator); err == nil {
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

func (s *HstSuite) ConfigureNetworkTopology(topologyName string) {
	s.LoadNetworkTopology(topologyName)

	if *isUnconfiguring {
		return
	}

	for _, nc := range s.netConfigs {
		if err := nc.Configure(); err != nil {
			s.T().Fatalf("network config error: %v", err)
		}
	}
}

func (s *HstSuite) UnconfigureNetworkTopology() {
	if *isPersistent {
		return
	}
	for _, nc := range s.netConfigs {
		nc.Unconfigure()
	}
}

func (s *HstSuite) GetTestId() string {
	testName := s.T().Name()

	if s.testIds == nil {
		s.testIds = map[string]string{}
	}

	if _, ok := s.testIds[testName]; !ok {
		s.testIds[testName] = time.Now().Format("2006-01-02_15-04-05")
	}

	return s.testIds[testName]
}
