package main

import (
	"time"
)

// These correspond to names used in yaml config ('srv', 'cln')
var serverInterfaceName string = "srv" + pid
var clientInterfaceName string = "cln" + pid

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
	serverContainer := s.getContainerByName("server-vpp" + pid)

	cpus := s.AllocateCpus()
	serverVpp, err := serverContainer.newVppInstance(cpus, sessionConfig)
	s.assertNotNil(serverVpp, err)

	s.setupServerVpp(pid)

	// ... For client
	clientContainer := s.getContainerByName("client-vpp" + pid)

	cpus = s.AllocateCpus()
	clientVpp, err := clientContainer.newVppInstance(cpus, sessionConfig)
	s.assertNotNil(clientVpp, err)

	s.setupClientVpp(pid)
}

func (s *VethsSuite) setupServerVpp(pid string) {
	serverVpp := s.getContainerByName("server-vpp" + pid).vppInstance
	s.assertNil(serverVpp.start())

	serverVeth := s.netInterfaces[serverInterfaceName]
	idx, err := serverVpp.createAfPacket(serverVeth)
	s.assertNil(err, err)
	s.assertNotEqual(0, idx)
}

func (s *VethsSuite) setupClientVpp(pid string) {
	clientVpp := s.getContainerByName("client-vpp" + pid).vppInstance
	s.assertNil(clientVpp.start())

	clientVeth := s.netInterfaces[clientInterfaceName]
	idx, err := clientVpp.createAfPacket(clientVeth)
	s.assertNil(err, err)
	s.assertNotEqual(0, idx)
}
