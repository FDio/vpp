package main

const (
	// These correspond to names used in yaml config
	mirroringClientInterfaceName = "hst_client"
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
	s.loadContainerTopology("doubleNginx")

	s.addresser = NewAddresser(&s.HstSuite)

	var clientTapDevConfig = NetDevConfig{
		"name": mirroringClientInterfaceName,
		"ip4": NetDevConfig{
			"network": 1,
		},
		"peer": NetDevConfig{
			"name":  "peer" + mirroringClientInterfaceName,
			"netns": "hst_ns_client",
			"ip4": NetDevConfig{
				"network": 1,
			},
		},
	}
	clientTap, _ := NewVeth(clientTapDevConfig, s.addresser)

	var serverTapDevConfig = NetDevConfig{
		"name": mirroringServerInterfaceName,
		"ip4": NetDevConfig{
			"network": 2,
		},
		"peer": NetDevConfig{
			"name":  "peer" + mirroringServerInterfaceName,
			"netns": "hst_ns_server",
			"ip4": NetDevConfig{
				"network": 2,
			},
		},
	}
	serverTap, _ := NewVeth(serverTapDevConfig, s.addresser)

	s.netInterfaces = make(map[string]NetInterface)
	s.netInterfaces[clientTap.Name()] = &clientTap
	s.netInterfaces[serverTap.Name()] = &serverTap
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

        // ... for client
	vppProxyContainer := s.getContainerByName(vppProxyContainerName)
	proxyVpp, _ := vppProxyContainer.newVppInstance(startupConfig)
	proxyVpp.start()

	clientVeth := s.netInterfaces[mirroringClientInterfaceName].(*NetworkInterfaceVeth)
	proxyVpp.createTap(clientVeth, "1")

 	serverVeth := s.netInterfaces[mirroringServerInterfaceName].(*NetworkInterfaceVeth)
	proxyVpp.createTap(serverVeth, "2")

	nginxContainer := s.getTransientContainerByName(nginxProxyContainerName)
	nginxContainer.create()
	nginxContainer.copy("./resources/nginx/mirroring_proxy.conf", "/nginx.conf")
	nginxContainer.start()

	proxyVpp.waitForApp("-app", 5)

        // ... for server
	nginxServerContainer := s.getContainerByName(nginxServerContainerName)
	nginxServerContainer.run()
}
