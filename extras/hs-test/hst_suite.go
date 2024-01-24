package main

import (
	"errors"
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
var vppSourceFileDir = flag.String("vppsrc", "", "vpp source file directory")

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
	s.assertNil(err)
	s.AddCpuContext(cpuCtx)
	return cpuCtx.cpus
}

func (s *HstSuite) AddCpuContext(cpuCtx *CpuContext) {
	s.cpuContexts = append(s.cpuContexts, cpuCtx)
}

func (s *HstSuite) TearDownSuite() {
	s.unconfigureNetworkTopology()
}

func (s *HstSuite) TearDownTest() {
	if *isPersistent {
		return
	}
	for _, c := range s.cpuContexts {
		c.Release()
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
		if !container.isOptional {
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

func (s *HstSuite) SkipIfMultiWorker(args ...any) {
	if *nConfiguredCpus > 1 {
		s.skip("test case not supported with multiple vpp workers")
	}
}

func (s *HstSuite) SkipUnlessExtendedTestsBuilt() {
	imageName := "hs-test/nginx-http3"

	cmd := exec.Command("docker", "images", imageName)
	byteOutput, err := cmd.CombinedOutput()
	if err != nil {
		s.log("error while searching for docker image")
		return
	}
	if !strings.Contains(string(byteOutput), imageName) {
		s.skip("extended tests not built")
	}
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
		workingVolumeDir := logDir + s.T().Name() + volumeDir
		volDirReplacer := strings.NewReplacer("$HST_VOLUME_DIR", workingVolumeDir)
                hostDir = volDirReplacer.Replace(hostDir)
		s.volumes = append(s.volumes, hostDir)
	}

	s.containers = make(map[string]*Container)
	for _, elem := range yamlTopo.Containers {
		newContainer, err := newContainer(s, elem)
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

	s.ip4AddrAllocator = NewIp4AddressAllocator()
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
				if netIf, err := newNetworkInterface(elem, s.ip4AddrAllocator); err == nil {
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

func (s *HstSuite) startServerApp(running chan error, done chan struct{}, env []string) {
	cmd := exec.Command("iperf3", "-4", "-s")
	if env != nil {
		cmd.Env = env
	}
	s.log(cmd)
	err := cmd.Start()
	if err != nil {
		msg := fmt.Errorf("failed to start iperf server: %v", err)
		running <- msg
		return
	}
	running <- nil
	<-done
	cmd.Process.Kill()
}

func (s *HstSuite) startClientApp(ipAddress string, env []string, clnCh chan error, clnRes chan string) {
	defer func() {
		clnCh <- nil
	}()

	nTries := 0

	for {
		cmd := exec.Command("iperf3", "-c", ipAddress, "-u", "-l", "1460", "-b", "10g")
		if env != nil {
			cmd.Env = env
		}
		s.log(cmd)
		o, err := cmd.CombinedOutput()
		if err != nil {
			if nTries > 5 {
				clnCh <- fmt.Errorf("failed to start client app '%s'.\n%s", err, o)
				return
			}
			time.Sleep(1 * time.Second)
			nTries++
			continue
		} else {
			clnRes <- fmt.Sprintf("Client output: %s", o)
		}
		break
	}
}

func (s *HstSuite) startHttpServer(running chan struct{}, done chan struct{}, addressPort, netNs string) {
	cmd := newCommand([]string{"./http_server", addressPort}, netNs)
	err := cmd.Start()
	s.log(cmd)
	if err != nil {
		fmt.Println("Failed to start http server")
		return
	}
	running <- struct{}{}
	<-done
	cmd.Process.Kill()
}

func (s *HstSuite) startWget(finished chan error, server_ip, port, query, netNs string) {
	defer func() {
		finished <- errors.New("wget error")
	}()

	cmd := newCommand([]string{"wget", "--timeout=10", "--no-proxy", "--tries=5", "-O", "/dev/null", server_ip + ":" + port + "/" + query},
		netNs)
	s.log(cmd)
	o, err := cmd.CombinedOutput()
	if err != nil {
		finished <- fmt.Errorf("wget error: '%v\n\n%s'", err, o)
		return
	} else if !strings.Contains(string(o), "200 OK") {
		finished <- fmt.Errorf("wget error: response not 200 OK")
		return
	}
	finished <- nil
}
