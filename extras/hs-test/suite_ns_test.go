package main

const (
	// These correspond to names used in yaml config
	clientInterface = "hst_client_vpp"
	serverInterface = "hst_server_vpp"
)

type NsSuite struct {
	HstSuite
}

func (s *NsSuite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.configureNetworkTopology("ns")
	s.loadContainerTopology("ns")
}

func (s *NsSuite) SetupTest() {
	s.HstSuite.SetupTest()

	// Setup test conditions
	var sessionConfig Stanza
	sessionConfig.
		newStanza("session").
		append("enable").
		append("use-app-socket-api").
		append("evt_qs_memfd_seg").
		append("event-queue-length 100000").close()

	cpus := s.AllocateCpus()
	container := s.getContainerByName("vpp")
	vpp, _ := container.newVppInstance(cpus, sessionConfig)
	vpp.start()

	idx, err := vpp.createAfPacket(s.netInterfaces[serverInterface])
	s.assertNil(err)
	s.assertNotEqual(0, idx)

	idx, err = vpp.createAfPacket(s.netInterfaces[clientInterface])
	s.assertNil(err)
	s.assertNotEqual(0, idx)

	container.exec("chmod 777 -R %s", container.getContainerWorkDir())
}
