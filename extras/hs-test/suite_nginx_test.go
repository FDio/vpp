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

	s.setupVolumes()
	s.setupContainers()

	// Setup test conditions
	var startupConfig Stanza
	startupConfig.
		newStanza("session").
		append("enable").
		append("use-app-socket-api").close()

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

	values := struct {
		Proxy  string
		Server string
	}{
		Proxy:  clientInterface.getPeer().ip4AddressString(),
		Server: serverInterface.ip4AddressString(),
	}
	nginxContainer.createConfig(
		"/nginx.conf",
		"./resources/nginx/nginx_proxy_mirroring.conf",
		values,
	)
	nginxContainer.start()

	proxyVpp.waitForApp("nginx-", 5)
}
