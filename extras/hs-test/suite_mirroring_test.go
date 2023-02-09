package main

const (
	// These correspond to names used in yaml config
	mirroringClientInterfaceName = "hst_client"
	mirroringProxyInterfaceName  = "hst_proxy"
	mirroringServerInterfaceName = "hst_server"
	vppProxyContainerName        = "vpp-proxy"
	nginxProxyContainerName      = "nginx-proxy"
	vppServerContainerName       = "vpp-server"
	nginxServerContainerName     = "nginx-server"
)

type MirroringSuite struct {
	HstSuite
}

func (s *MirroringSuite) SetupSuite() {
	s.configureNetworkTopology("3peerVeth")

	s.loadContainerTopology("doubleNginx")
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

	// ... for proxy
	container := s.getContainerByName(vppProxyContainerName)
	vpp, _ := container.newVppInstance(startupConfig)
	vpp.start()

	proxyVeth := s.netInterfaces[mirroringProxyInterfaceName]
	vpp.createAfPacket(proxyVeth)

	nginxContainer := s.getTransientContainerByName(nginxProxyContainerName)
	nginxContainer.create()
	nginxContainer.copy("./resources/nginx/mirroring_proxy.conf", "/nginx.conf")
	nginxContainer.start()

	vpp.waitForApp("-app", 5)

	// ... for server
	vppServerContainer := s.getContainerByName(vppServerContainerName)
	serverVpp, _ := vppServerContainer.newVppInstance(startupConfig)
	serverVpp.start()

	serverVeth := s.netInterfaces[mirroringServerInterfaceName]
	serverVpp.createAfPacket(serverVeth)

	nginxServerContainer := s.getContainerByName(nginxServerContainerName)
	nginxServerContainer.run()

	serverVpp.waitForApp("-app", 5)
}
