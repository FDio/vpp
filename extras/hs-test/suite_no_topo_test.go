package main

const (
	singleTopoContainerVpp   = "vpp"
	singleTopoContainerNginx = "nginx"

	tapNameVpp  = "vppTap"
	tapNameHost = "hostTap"
)

type NoTopoSuite struct {
	HstSuite
}

func (s *NoTopoSuite) SetupSuite() {
	s.loadContainerTopology("single")

	s.addresser = NewAddresser(&s.HstSuite)

	var vppTapDevConfig = NetDevConfig{"name": tapNameVpp}
	vppTap, _ := NewTap(vppTapDevConfig, s.addresser)

	var hostTapDevConfig = NetDevConfig{"name": tapNameHost}
	hostTap, _ := NewTap(hostTapDevConfig, s.addresser)

	s.netInterfaces = make(map[string]NetInterface)
	s.netInterfaces[vppTap.Name()] = &vppTap
	s.netInterfaces[hostTap.Name()] = &hostTap
}

func (s *NoTopoSuite) SetupTest() {
	s.skipIfUnconfiguring()
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

	vppTapAddress := s.netInterfaces[tapNameVpp].AddressWithPrefix()
	hostTapAddress := s.netInterfaces[tapNameHost].IP4AddressWithPrefix()

	vpp.createTap("tap0", hostTapAddress, vppTapAddress)
}
