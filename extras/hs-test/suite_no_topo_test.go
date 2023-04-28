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
	s.skipIfUnconfiguring()
	s.setupVolumes()
	s.setupContainers()

	// Setup test conditions
	var startupConfig, cpuConfig Stanza
	startupConfig.
		newStanza("session").
		append("enable").
		append("use-app-socket-api").close()

	cpuConfig = GenerateCpuConfig(3)
	container := s.getContainerByName(singleTopoContainerVpp)
	vpp, _ := container.newVppInstance(startupConfig, cpuConfig)
	vpp.start()

	tapInterface := s.netInterfaces[tapInterfaceName]

	vpp.createTap(tapInterface)
}
