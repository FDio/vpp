package main

const (
	singleTopoContainerVpp   = "vpp"
	singleTopoContainerNginx = "nginx"

	tapInterfaceName = "hst_tap_host"
)

type NoTopoSuite struct {
	HstSuite
}

func (s *NoTopoSuite) SetupSuite() {
	s.loadNetworkTopology("tap")

	s.loadContainerTopology("single")
}

func (s *NoTopoSuite) SetupTest() {
	s.SetupVolumes()
	s.SetupContainers()

	// Setup test conditions
	var startupConfig Stanza
	startupConfig.
		NewStanza("session").
		Append("enable").
		Append("use-app-socket-api").Close()

	container := s.getContainerByName(singleTopoContainerVpp)
	vpp, _ := container.newVppInstance(startupConfig)
	vpp.start()

	tapInterface := s.netInterfaces[tapInterfaceName]

	vpp.createTap(1, tapInterface)
}
