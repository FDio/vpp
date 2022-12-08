package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/edwarnicke/exechelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type HstSuite struct {
	suite.Suite
	teardownSuite func()
	containers    []*Container
	volumes       []string
}

func (s *HstSuite) TearDownSuite() {
	s.teardownSuite()
}

func (s *HstSuite) TearDownTest() {
	s.StopContainers()
	s.RemoveVolumes()
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

func (s *HstSuite) NewContainer(name string) (*Container, error) {
	if name == "" {
		return nil, fmt.Errorf("creating container failed: name must not be blank")
	}

	container := new(Container)
	container.name = name

	s.containers = append(s.containers, container)

	return container, nil
}

func (s *HstSuite) GetContainers() []*Container {
	return s.containers
}

func (s *HstSuite) StopContainers() {
	for _, container := range s.containers {
		container.stop()
		container = nil
	}
	s.containers = nil
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
		exechelper.Run("docker volume rm " + volumeName)
	}
}

type TapSuite struct {
	HstSuite
}

func (s *TapSuite) SetupSuite() {
	time.Sleep(1 * time.Second)
	s.teardownSuite = setupSuite(&s.Suite, "tap")
}

type VethsSuite struct {
	HstSuite
}

func (s *VethsSuite) SetupSuite() {
	time.Sleep(1 * time.Second)
	s.teardownSuite = setupSuite(&s.Suite, "2peerVeth")
}

func (s *VethsSuite) SetupTest() {
	serverVolume := "echo-srv-vol"
	s.NewVolume(serverVolume)

	clientVolume := "echo-cln-vol"
	s.NewVolume(clientVolume)

	srvInstance := "vpp-vcl-test-srv"
	serverVppContainer, err := s.NewContainer(srvInstance)
	s.assertNil(err)
	serverVppContainer.addVolume(serverVolume, "/tmp/Configure2Veths")
	s.assertNil(serverVppContainer.run())

	clnInstance := "vpp-vcl-test-cln"
	clientVppContainer, err := s.NewContainer(clnInstance)
	s.assertNil(err)
	clientVppContainer.addVolume(clientVolume, "/tmp/Configure2Veths")
	s.assertNil(clientVppContainer.run())

	echoSrv := "echo-srv"
	serverEchoContainer, err := s.NewContainer(echoSrv)
	s.assertNil(err)
	serverEchoContainer.addVolume(serverVolume, "/tmp/" + echoSrv)
	s.assertNil(serverEchoContainer.run())

	echoCln := "echo-cln"
	clientEchoContainer, err := s.NewContainer(echoCln)
	s.assertNil(err)
	clientEchoContainer.addVolume(clientVolume, "/tmp/" + echoCln)
	s.assertNil(clientEchoContainer.run())
}

type NsSuite struct {
	HstSuite
}

func (s *NsSuite) SetupSuite() {
	s.teardownSuite = setupSuite(&s.Suite, "ns")
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

func TestVeths(t *testing.T) {
	var m VethsSuite
	suite.Run(t, &m)
}
