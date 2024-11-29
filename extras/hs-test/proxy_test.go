package main

import (
	"fmt"
	"time"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterVppProxyTests(VppProxyHttpGetTcpTest, VppProxyHttpGetTlsTest, VppProxyHttpPutTcpTest, VppProxyHttpPutTlsTest,
		VppConnectProxyGetTest, VppConnectProxyPutTest)
	RegisterVppProxySoloTests(VppProxyHttpGetTcpMTTest, VppProxyHttpPutTcpMTTest, VppProxyTcpIperfMTTest)
	RegisterVppUdpProxyTests(VppProxyUdpTest)
	RegisterEnvoyProxyTests(EnvoyProxyHttpGetTcpTest, EnvoyProxyHttpPutTcpTest)
	RegisterNginxProxyTests(NginxMirroringTest)
	RegisterNginxProxySoloTests(MirrorMultiThreadTest)
}

func configureVppProxy(s *VppProxySuite, proto string, proxyPort uint16) {
	vppProxy := s.GetContainerByName(VppProxyContainerName).VppInstance
	cmd := fmt.Sprintf("test proxy server fifo-size 512k server-uri %s://%s/%d", proto, s.VppProxyAddr(), proxyPort)
	if proto != "http" {
		cmd += fmt.Sprintf(" client-uri tcp://%s/%d", s.NginxAddr(), s.NginxPort())
	}
	output := vppProxy.Vppctl(cmd)
	s.Log("proxy configured: " + output)
}

func VppProxyHttpGetTcpMTTest(s *VppProxySuite) {
	VppProxyHttpGetTcpTest(s)
}

func VppProxyTcpIperfMTTest(s *VppProxySuite) {
	iperf1 := s.GetContainerByName("iperfA")
	iperf2 := s.GetContainerByName("iperfB")
	iperf1.Run()
	iperf2.Run()
	serverInterface := s.GetInterfaceByName(ServerTapInterfaceName)
	clientInterface := s.GetInterfaceByName(ClientTapInterfaceName)
	vppProxy := s.GetContainerByName("vpp-proxy").VppInstance

	// tap interfaces are created on test setup with 1 rx-queue,
	// need to recreate them with 2
	s.AssertNil(vppProxy.DeleteTap(serverInterface))
	vppProxy.Vppctl(fmt.Sprintf("create tap id %v num-rx-queues 2 consistent-qp "+
		"host-if-name %s host-ip4-addr %v",
		serverInterface.Peer.Index, serverInterface.Name(), serverInterface.Ip4Address))

	s.AssertNil(vppProxy.DeleteTap(clientInterface))
	vppProxy.Vppctl(fmt.Sprintf("create tap id %v num-rx-queues 2 consistent-qp "+
		"host-if-name %s host-ip4-addr %v",
		clientInterface.Peer.Index, clientInterface.Name(), clientInterface.Ip4Address))

	vppProxy.Vppctl("set int ip addr tap1 " + clientInterface.Peer.Ip4AddressString() + "/24")
	vppProxy.Vppctl("set int ip addr tap2 " + serverInterface.Peer.Ip4AddressString() + "/24")
	vppProxy.Vppctl("set int state tap1 up")
	vppProxy.Vppctl("set int state tap2 up")

	cmd := fmt.Sprintf("test proxy server fifo-size 512k server-uri tcp://%s/%s", clientInterface.Peer.Ip4AddressString(), "8080")
	cmd += fmt.Sprintf(" client-uri tcp://%s/%s", serverInterface.Ip4AddressString(), "80")
	output := vppProxy.Vppctl(cmd)
	s.AssertNotContains(output, "failed")
	s.Log("proxy configured: " + output)

	stopServerCh := make(chan struct{}, 1)
	srvCh := make(chan error, 1)
	clnCh := make(chan error)
	clnRes := make(chan string, 1)

	defer func() {
		stopServerCh <- struct{}{}
	}()

	go func() {
		defer GinkgoRecover()
		cmd := fmt.Sprintf("iperf3 -4 -s -B %s -p %s", serverInterface.Ip4AddressString(), "80")
		s.StartServerApp(iperf1, "iperf3", cmd, srvCh, stopServerCh)
	}()

	err := <-srvCh
	s.AssertNil(err, fmt.Sprint(err))

	go func() {
		defer GinkgoRecover()
		cmd := fmt.Sprintf("iperf3 -c %s -P 4 -p %s -B %s", clientInterface.Peer.Ip4AddressString(), "8080", clientInterface.Ip4AddressString())
		s.StartClientApp(iperf2, cmd, clnCh, clnRes)
	}()

	s.AssertChannelClosed(time.Minute*4, clnCh)
	s.Log(<-clnRes)
}

func VppProxyHttpGetTcpTest(s *VppProxySuite) {
	var proxyPort uint16 = 8080
	s.SetupNginxServer()
	configureVppProxy(s, "tcp", proxyPort)
	uri := fmt.Sprintf("http://%s:%d/httpTestFile", s.VppProxyAddr(), proxyPort)
	s.CurlDownloadResource(uri)
}

func VppProxyHttpGetTlsTest(s *VppProxySuite) {
	var proxyPort uint16 = 8080
	s.SetupNginxServer()
	configureVppProxy(s, "tls", proxyPort)
	uri := fmt.Sprintf("https://%s:%d/httpTestFile", s.VppProxyAddr(), proxyPort)
	s.CurlDownloadResource(uri)
}

func VppProxyHttpPutTcpMTTest(s *VppProxySuite) {
	VppProxyHttpPutTcpTest(s)
}

func VppProxyHttpPutTcpTest(s *VppProxySuite) {
	var proxyPort uint16 = 8080
	s.SetupNginxServer()
	configureVppProxy(s, "tcp", proxyPort)
	uri := fmt.Sprintf("http://%s:%d/upload/testFile", s.VppProxyAddr(), proxyPort)
	s.CurlUploadResource(uri, CurlContainerTestFile)
}

func VppProxyHttpPutTlsTest(s *VppProxySuite) {
	var proxyPort uint16 = 8080
	s.SetupNginxServer()
	configureVppProxy(s, "tls", proxyPort)
	uri := fmt.Sprintf("https://%s:%d/upload/testFile", s.VppProxyAddr(), proxyPort)
	s.CurlUploadResource(uri, CurlContainerTestFile)
}

func EnvoyProxyHttpGetTcpTest(s *EnvoyProxySuite) {
	uri := fmt.Sprintf("http://%s:%d/httpTestFile", s.ProxyAddr(), s.ProxyPort())
	s.CurlDownloadResource(uri)
}

func EnvoyProxyHttpPutTcpTest(s *EnvoyProxySuite) {
	uri := fmt.Sprintf("http://%s:%d/upload/testFile", s.ProxyAddr(), s.ProxyPort())
	s.CurlUploadResource(uri, CurlContainerTestFile)
}

func MirrorMultiThreadTest(s *NginxProxySuite) {
	nginxMirroring(s, true)
}

func NginxMirroringTest(s *NginxProxySuite) {
	nginxMirroring(s, false)
}

func nginxMirroring(s *NginxProxySuite, multiThreadWorkers bool) {
	nginxProxyContainer := s.GetContainerByName(NginxProxyContainerName)
	vpp := s.GetContainerByName(VppContainerName).VppInstance

	s.AddVclConfig(nginxProxyContainer, multiThreadWorkers)
	s.CreateNginxProxyConfig(nginxProxyContainer, multiThreadWorkers)
	nginxProxyContainer.Start()
	vpp.WaitForApp("nginx-", 5)
	uri := fmt.Sprintf("http://%s:%d/httpTestFile", s.ProxyAddr(), s.ProxyPort())
	s.CurlDownloadResource(uri)
}

func VppConnectProxyGetTest(s *VppProxySuite) {
	var proxyPort uint16 = 8080
	s.SetupNginxServer()
	configureVppProxy(s, "http", proxyPort)

	targetUri := fmt.Sprintf("http://%s:%d/httpTestFile", s.NginxAddr(), s.NginxPort())
	proxyUri := fmt.Sprintf("http://%s:%d", s.VppProxyAddr(), proxyPort)
	s.CurlDownloadResourceViaTunnel(targetUri, proxyUri)
}

func VppConnectProxyPutTest(s *VppProxySuite) {
	var proxyPort uint16 = 8080
	s.SetupNginxServer()
	configureVppProxy(s, "http", proxyPort)

	proxyUri := fmt.Sprintf("http://%s:%d", s.VppProxyAddr(), proxyPort)
	targetUri := fmt.Sprintf("http://%s:%d/upload/testFile", s.NginxAddr(), s.NginxPort())
	s.CurlUploadResourceViaTunnel(targetUri, proxyUri, CurlContainerTestFile)
}

func VppProxyUdpTest(s *VppUdpProxySuite) {
	remoteServerConn := s.StartEchoServer()
	defer remoteServerConn.Close()

	vppProxy := s.GetContainerByName(VppUdpProxyContainerName).VppInstance
	cmd := fmt.Sprintf("test proxy server fifo-size 512k server-uri udp://%s/%d", s.VppProxyAddr(), s.ProxyPort())
	cmd += fmt.Sprintf(" client-uri udp://%s/%d", s.ServerAddr(), s.ServerPort())
	s.Log(vppProxy.Vppctl(cmd))

	b := make([]byte, 1500)
	n, err := s.ClientSendReceive([]byte("hello"), b)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertEqual([]byte("hello"), b[:n])
}
