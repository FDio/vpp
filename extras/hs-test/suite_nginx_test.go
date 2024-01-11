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
	s.HstSuite.SetupSuite()
	s.loadNetworkTopology("2taps")
	s.loadContainerTopology("nginxProxyAndServer")
}

func (s *NginxSuite) SetupTest() {
	s.HstSuite.SetupTest()

	// Setup test conditions
	var sessionConfig Stanza
	sessionConfig.
		newStanza("session").
		append("enable").
		append("use-app-socket-api").close()

	cpus := s.AllocateCpus()
	// ... for proxy
	vppProxyContainer := s.getContainerByName(vppProxyContainerName)
	proxyVpp, _ := vppProxyContainer.newVppInstance(cpus, sessionConfig)
	s.assertNil(proxyVpp.start())

	clientInterface := s.netInterfaces[mirroringClientInterfaceName]
	s.assertNil(proxyVpp.createTap(clientInterface, 1))

	serverInterface := s.netInterfaces[mirroringServerInterfaceName]
	s.assertNil(proxyVpp.createTap(serverInterface, 2))

	nginxContainer := s.getTransientContainerByName(nginxProxyContainerName)
	nginxContainer.create()

	values := struct {
		Proxy  string
		Server string
	}{
		Proxy:  clientInterface.peer.ip4AddressString(),
		Server: serverInterface.ip4AddressString(),
	}
	nginxContainer.createConfig(
		"/nginx.conf",
		"./resources/nginx/nginx_proxy_mirroring.conf",
		values,
	)
	s.assertNil(nginxContainer.start())

	proxyVpp.waitForApp("nginx-", 5)
}
