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
	s.ConfigureNetworkTopology("2peerVeth")
	s.LoadContainerTopology("2peerVeth")
}

func (s *VethsSuite) SetupTest() {
	s.HstSuite.SetupTest()

	// Setup test conditions

	var sessionConfig Stanza
	sessionConfig.
		NewStanza("session").
		Append("enable").
		Append("use-app-socket-api").Close()

	// ... For server
	serverContainer := s.GetContainerByName("server-vpp")

	cpus := s.AllocateCpus()
	serverVpp, _ := serverContainer.NewVppInstance(cpus, sessionConfig)
	s.AssertNotNil(serverVpp)

	s.SetupServerVpp()

	// ... For client
	clientContainer := s.GetContainerByName("client-vpp")

	cpus = s.AllocateCpus()
	clientVpp, _ := clientContainer.NewVppInstance(cpus, sessionConfig)
	s.AssertNotNil(clientVpp)

	s.SetupClientVpp()
}

func (s *VethsSuite) SetupServerVpp() {
	serverVpp := s.GetContainerByName("server-vpp").vppInstance

	err := serverVpp.Start()
	s.AssertNil(err)

	serverVeth := s.netInterfaces[serverInterfaceName]
	idx, err := serverVpp.CreateAfPacket(serverVeth)
	s.AssertNil(err)
	s.AssertNotEqual(0, idx)

	namespaceSecret := "1"
	err = serverVpp.AddAppNamespace(1, idx, namespaceSecret)
	s.AssertNil(err)
}

func (s *VethsSuite) SetupClientVpp() {
	clientVpp := s.GetContainerByName("client-vpp").vppInstance

	err := clientVpp.Start()
	s.AssertNil(err)

	clientVeth := s.netInterfaces[clientInterfaceName]
	idx, err := clientVpp.CreateAfPacket(clientVeth)
	s.AssertNil(err)
	s.AssertNotEqual(0, idx)

	clientNamespaceSecret := "2"
	err = clientVpp.AddAppNamespace(2, idx, clientNamespaceSecret)
	s.AssertNil(err)
}
