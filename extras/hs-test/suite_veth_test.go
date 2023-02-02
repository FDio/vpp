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

	s.configureNetworkTopology("2peerVeth")

	s.loadContainerTopology("2peerVeth")
}

func (s *VethsSuite) SetupTest() {
	s.SetupVolumes()
	s.SetupContainers()

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

	s.setupServerVpp()

	// ... For client
	clientContainer := s.getContainerByName("client-vpp")

	clientVpp, _ := clientContainer.newVppInstance(startupConfig)
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

	namespaceSecret := "1"
	err = serverVpp.addAppNamespace(1, idx, namespaceSecret)
	s.assertNil(err)

}

func (s *VethsSuite) setupClientVpp() {
	clientVpp := s.getContainerByName("client-vpp").vppInstance

	err := clientVpp.start()
	s.assertNil(err)

	clientVeth := s.netInterfaces[clientInterfaceName]
	idx, err := clientVpp.createAfPacket(clientVeth)
	s.assertNil(err)
	s.assertNotEqual(0, idx)

	clientNamespaceSecret := "2"
	err = clientVpp.addAppNamespace(2, idx, clientNamespaceSecret)
	s.assertNil(err)
}
