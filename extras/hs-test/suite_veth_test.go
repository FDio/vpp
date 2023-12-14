package main

import (
	"time"
)

const (
	// These correspond to names used in yaml config
	serverInterfaceName = "vppsrv"
	clientInterfaceName = "vppcln"
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
	serverVpp, _ := serverContainer.newVppInstance(cpus, sessionConfig)
	s.assertNotNil(serverVpp)

	s.setupServerVpp()

	// ... For client
	clientContainer := s.getContainerByName("client-vpp")

	cpus = s.AllocateCpus()
	clientVpp, _ := clientContainer.newVppInstance(cpus, sessionConfig)
	s.assertNotNil(clientVpp)

	s.setupClientVpp()
}

func (s *VethsSuite) setupServerVpp() {
	serverVpp := s.getContainerByName("server-vpp").vppInstance

	err := serverVpp.start()
	s.assertNil(err)

	serverVeth := s.netInterfaces[serverInterfaceName]
	idx, err := serverVpp.createAfPacket(serverVeth)
	s.assertNil(err)
	s.assertNotEqual(0, idx)
}

func (s *VethsSuite) setupClientVpp() {
	clientVpp := s.getContainerByName("client-vpp").vppInstance

	err := clientVpp.start()
	s.assertNil(err)

	clientVeth := s.netInterfaces[clientInterfaceName]
	idx, err := clientVpp.createAfPacket(clientVeth)
	s.assertNil(err)
	s.assertNotEqual(0, idx)
}
