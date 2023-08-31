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
	s.LoadNetworkTopology("2taps")
	s.LoadContainerTopology("nginxProxyAndServer")
}

func (s *NginxSuite) SetupTest() {
	s.HstSuite.SetupTest()

	// Setup test conditions
	var sessionConfig Stanza
	sessionConfig.
		NewStanza("session").
		Append("enable").
		Append("use-app-socket-api").Close()

	cpus := s.AllocateCpus()
	// ... for proxy
	vppProxyContainer := s.GetContainerByName(vppProxyContainerName)
	proxyVpp, _ := vppProxyContainer.NewVppInstance(cpus, sessionConfig)
	proxyVpp.Start()

	clientInterface := s.netInterfaces[mirroringClientInterfaceName]
	proxyVpp.CreateTap(clientInterface, 1)

	serverInterface := s.netInterfaces[mirroringServerInterfaceName]
	proxyVpp.CreateTap(serverInterface, 2)

	nginxContainer := s.GetTransientContainerByName(nginxProxyContainerName)
	nginxContainer.Create()

	values := struct {
		Proxy  string
		Server string
	}{
		Proxy:  clientInterface.peer.Ip4AddressString(),
		Server: serverInterface.Ip4AddressString(),
	}
	nginxContainer.CreateConfig(
		"/nginx.conf",
		"./resources/nginx/nginx_proxy_mirroring.conf",
		values,
	)
	nginxContainer.Start()

	proxyVpp.WaitForApp("nginx-", 5)
}
