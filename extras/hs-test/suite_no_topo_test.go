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
	s.LoadNetworkTopology("tap")
	s.LoadContainerTopology("single")
}

func (s *NoTopoSuite) SetupTest() {
	s.HstSuite.SetupTest()

	// Setup test conditions
	var sessionConfig Stanza
	sessionConfig.
		NewStanza("session").
		Append("enable").
		Append("use-app-socket-api").Close()

	cpus := s.AllocateCpus()
	container := s.GetContainerByName(singleTopoContainerVpp)
	vpp, _ := container.NewVppInstance(cpus, sessionConfig)
	vpp.Start()

	tapInterface := s.netInterfaces[tapInterfaceName]

	vpp.CreateTap(tapInterface)
}
