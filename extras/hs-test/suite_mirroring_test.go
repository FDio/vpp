package main

const (
	// These correspond to names used in yaml config
	mirroringClientInterfaceName = "hst_client"
	mirroringProxyInterfaceName  = "hst_proxy"
	mirroringServerInterfaceName = "hst_server"
)

type MirroringSuite struct {
	HstSuite
}

func (s *MirroringSuite) SetupSuite() {
	s.configureNetworkTopology("3peerVeth")

	s.loadContainerTopology("single")
}

func (s *MirroringSuite) SetupTest() {
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

	// create host-interface in VPP
	proxyVeth := s.netInterfaces[mirroringProxyInterfaceName]
	vpp.createAfPacket(proxyVeth)

	// copy nginx config to nginx container and start it
	nginxContainer := s.getTransientContainerByName("nginx")
	nginxContainer.create()
	nginxContainer.copy("./resources/nginx/mirroring_proxy.conf", "/nginx.conf")
	nginxContainer.start()

	vpp.waitForApp("-app", 5)
}
