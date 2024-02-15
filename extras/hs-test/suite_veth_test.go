package main

import (
	"time"
)

const (
	// These correspond to names used in yaml config
	serverInterfaceName = "srv"
	clientInterfaceName = "cln"
)

type VethsSuite struct {
	HstSuite
}

func (s *VethsSuite) SetupSuite() {
	time.Sleep(1 * time.Second)
	s.HstSuite.SetupSuite()
	s.configureNetworkTopology("2peerVeth")
	s.loadContainerTopology("2peerVeth")
}

func (s *VethsSuite) SetupTest() {
	s.HstSuite.SetupTest()

	// Setup test conditions

	var sessionConfig Stanza
	sessionConfig.
		newStanza("session").
		append("enable").
		append("use-app-socket-api").close()

	// ... For server
	serverContainer := s.getContainerByName("server-vpp")

	cpus := s.AllocateCpus()
	serverVpp, err := serverContainer.newVppInstance(cpus, sessionConfig)
	s.assertNotNil(serverVpp, err)

	s.setupServerVpp()

	// ... For client
	clientContainer := s.getContainerByName("client-vpp")

	cpus = s.AllocateCpus()
	clientVpp, err := clientContainer.newVppInstance(cpus, sessionConfig)
	s.assertNotNil(clientVpp, err)

	s.setupClientVpp()
}

func (s *VethsSuite) setupServerVpp() {
	serverVpp := s.getContainerByName("server-vpp").vppInstance
	s.assertNil(serverVpp.start())

	serverVeth := s.netInterfaces[serverInterfaceName]
	idx, err := serverVpp.createAfPacket(serverVeth)
	s.assertNil(err, err)
	s.assertNotEqual(0, idx)
}

func (s *VethsSuite) setupClientVpp() {
	clientVpp := s.getContainerByName("client-vpp").vppInstance
	s.assertNil(clientVpp.start())

	clientVeth := s.netInterfaces[clientInterfaceName]
	idx, err := clientVpp.createAfPacket(clientVeth)
	s.assertNil(err, err)
	s.assertNotEqual(0, idx)
}
