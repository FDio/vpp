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
	s.HstSuite.SetupSuite()
	s.loadNetworkTopology("tap")
	s.loadContainerTopology("single")
}

func (s *NoTopoSuite) SetupTest() {
	s.HstSuite.SetupTest()

	// Setup test conditions
	var sessionConfig Stanza
	sessionConfig.
		newStanza("session").
		append("enable").
		append("use-app-socket-api").close()

	cpus := s.AllocateCpus()
	container := s.getContainerByName(singleTopoContainerVpp)
	vpp, _ := container.newVppInstance(cpus, sessionConfig)
	s.assertNil(vpp.start())

	tapInterface := s.netInterfaces[tapInterfaceName]

	s.assertNil(vpp.createTap(tapInterface), "failed to create tap interface")
}
