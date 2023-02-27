package main

const (
	singleTopoContainerVpp   = "vpp"
	singleTopoContainerNginx = "nginx"

	tapNameVpp = "hst_tap"
)

type NoTopoSuite struct {
	HstSuite
}

func (s *NoTopoSuite) SetupSuite() {
	s.loadContainerTopology("single")

	s.addresser = NewAddresser(&s.HstSuite)

	var tapDevConfig = NetDevConfig{
		"name": tapNameVpp,
		"ip4": NetDevConfig{
			"network": 1,
		},
		"peer": NetDevConfig{
			"name": "peer" + tapNameVpp,
			"ip4": NetDevConfig{
				"network": 1,
			},
		},
	}
	tap, _ := NewVeth(tapDevConfig, s.addresser)

	s.netInterfaces = make(map[string]NetInterface)
	s.netInterfaces[tap.Name()] = &tap
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

	tapInterface := s.netInterfaces[tapNameVpp].(*NetworkInterfaceVeth)

	vpp.createTap(tapInterface)
}
