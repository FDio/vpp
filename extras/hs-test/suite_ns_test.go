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
	s.ConfigureNetworkTopology("ns")
	s.LoadContainerTopology("ns")
}

func (s *NsSuite) SetupTest() {
	s.HstSuite.SetupTest()

	// Setup test conditions
	var sessionConfig Stanza
	sessionConfig.
		NewStanza("session").
		Append("enable").
		Append("use-app-socket-api").
		Append("evt_qs_memfd_seg").
		Append("event-queue-length 100000").Close()

	cpus := s.AllocateCpus()
	container := s.GetContainerByName("vpp")
	vpp, _ := container.NewVppInstance(cpus, sessionConfig)
	vpp.Start()

	idx, err := vpp.CreateAfPacket(s.netInterfaces[serverInterface])
	s.AssertNil(err)
	s.AssertNotEqual(0, idx)

	idx, err = vpp.CreateAfPacket(s.netInterfaces[clientInterface])
	s.AssertNil(err)
	s.AssertNotEqual(0, idx)

	container.Exec("chmod 777 -R %s", container.GetContainerWorkDir())
}
