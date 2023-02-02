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
	s.configureNetworkTopology("ns")

	s.loadContainerTopology("ns")
}

func (s *NsSuite) SetupTest() {
	s.SetupVolumes()
	s.SetupContainers()

	// Setup test conditions
	var startupConfig Stanza
	startupConfig.
		NewStanza("session").
		Append("enable").
		Append("use-app-socket-api").
		Append("evt_qs_memfd_seg").
		Append("event-queue-length 100000").Close()

	container := s.getContainerByName("vpp")
	vpp, _ := container.newVppInstance(startupConfig)
	vpp.start()

	idx, err := vpp.createAfPacket(s.netInterfaces[serverInterface])
	s.assertNil(err)
	s.assertNotEqual(0, idx)

	idx, err = vpp.createAfPacket(s.netInterfaces[clientInterface])
	s.assertNil(err)
	s.assertNotEqual(0, idx)

	container.exec("chmod 777 -R %s", container.GetContainerWorkDir())
}
