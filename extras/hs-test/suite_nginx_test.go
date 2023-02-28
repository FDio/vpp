package main

const (
	// These correspond to names used in yaml config
	mirroringClientInterfaceName = "hst_client"
	mirroringServerInterfaceName = "hst_server"
	vppProxyContainerName        = "vpp-proxy"
	nginxProxyContainerName      = "nginx-proxy"
	nginxServerContainerName     = "nginx-server"
)

type NginxSuite struct {
	HstSuite
}

func (s *NginxSuite) SetupSuite() {
	s.loadNetworkTopology("2taps")

	s.loadContainerTopology("nginxProxyAndServer")
}

func (s *NginxSuite) SetupTest() {
	s.skipIfUnconfiguring()

	s.SetupVolumes()
	s.SetupContainers()

	// Setup test conditions
	var startupConfig Stanza
	startupConfig.
		NewStanza("session").
		Append("enable").
		Append("use-app-socket-api").Close()

	// ... for proxy
	vppProxyContainer := s.getContainerByName(vppProxyContainerName)
	proxyVpp, _ := vppProxyContainer.newVppInstance(startupConfig)
	proxyVpp.start()

	clientInterface := s.netInterfaces[mirroringClientInterfaceName]
	proxyVpp.createTap(clientInterface, 1)

	serverInterface := s.netInterfaces[mirroringServerInterfaceName]
	proxyVpp.createTap(serverInterface, 2)

	nginxContainer := s.getTransientContainerByName(nginxProxyContainerName)
	nginxContainer.create()
	nginxContainer.copy("./resources/nginx/nginx_proxy_mirroring.conf", "/nginx.conf")
	nginxContainer.start()

	proxyVpp.waitForApp("-app", 5)
}
