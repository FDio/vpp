package main

import (
	"time"
)

type VethsSuite struct {
	HstSuite
}

func (s *VethsSuite) SetupSuite() {
	time.Sleep(1 * time.Second)
	// s.teardownSuite = setupSuite(&s.Suite, "2peerVeth")
	s.configureNetworkTopology("2peerVeth")
	s.loadContainerTopology("2peerVeth")
}

func (s *VethsSuite) SetupTest() {
	s.SetupVolumes()
	s.SetupContainers()

	if s.T().Name() != "TestVeths/TestEchoBuiltin" {
		return
	}

	// Setup test conditions

	var startupConfig Stanza
	startupConfig.
		NewStanza("session").
		Append("enable").
		Append("use-app-socket-api").Close()

	// ... For server
	serverContainer := s.getContainerByName("server-vpp")

	serverVpp, _ := serverContainer.newVppInstance(startupConfig)
	s.assertNotNil(serverVpp)

	err := serverVpp.start()
	s.assertNil(err)

	serverVeth := s.veths["vppsrv"]
	idx, err := serverVpp.createAfPacket(serverVeth)
	s.assertNil(err)
	s.assertNotEqual(0, idx)

	namespaceSecret := "1"
	err = serverVpp.addAppNamespace(1, idx, namespaceSecret)
	s.assertNil(err)

	// ... For client
	clientContainer := s.getContainerByName("client-vpp")

	clientVpp, _ := clientContainer.newVppInstance(startupConfig)
	s.assertNotNil(clientVpp)

	err = clientVpp.start()
	s.assertNil(err)

	clientVeth := s.veths["vppcln"]
	idx, err = clientVpp.createAfPacket(clientVeth)
	s.assertNil(err)
	s.assertNotEqual(0, idx)

	clientNamespaceSecret := "2"
	err = clientVpp.addAppNamespace(2, idx, clientNamespaceSecret)
	s.assertNil(err)
}
