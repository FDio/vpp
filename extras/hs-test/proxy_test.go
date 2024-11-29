package main

import (
	"fmt"
	"strconv"
	"time"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterVppProxyTests(VppProxyHttpGetTcpTest, VppProxyHttpGetTlsTest, VppProxyHttpPutTcpTest, VppProxyHttpPutTlsTest,
		VppConnectProxyGetTest, VppConnectProxyPutTest)
	RegisterVppProxySoloTests(VppProxyHttpGetTcpMTTest, VppProxyHttpPutTcpMTTest, VppProxyTcpIperfMTTest, VppProxyUdpIperfMTTest)
	RegisterVppUdpProxyTests(VppProxyUdpTest)
	RegisterEnvoyProxyTests(EnvoyProxyHttpGetTcpTest, EnvoyProxyHttpPutTcpTest)
	RegisterNginxProxyTests(NginxMirroringTest)
	RegisterNginxProxySoloTests(MirrorMultiThreadTest)
}

func configureVppProxy(s *VppProxySuite, proto string, proxyPort uint16) {
	vppProxy := s.GetContainerByName(VppProxyContainerName).VppInstance
	cmd := fmt.Sprintf("test proxy server fifo-size 512k server-uri %s://%s/%d", proto, s.VppProxyAddr(), proxyPort)
	if proto != "http" && proto != "udp" {
		proto = "tcp"
	}
	if proto != "http" {
		cmd += fmt.Sprintf(" client-uri %s://%s/%d", proto, s.ServerAddr(), s.ServerPort())
	}

	output := vppProxy.Vppctl(cmd)
	s.Log("proxy configured: " + output)
}

func VppProxyHttpGetTcpMTTest(s *VppProxySuite) {
	VppProxyHttpGetTcpTest(s)
}

func VppProxyTcpIperfMTTest(s *VppProxySuite) {
	vppProxyIperfMTTest(s, "tcp")
}

func VppProxyUdpIperfMTTest(s *VppProxySuite) {
	vppProxyIperfMTTest(s, "udp")
}

func vppProxyIperfMTTest(s *VppProxySuite, proto string) {
	if proto == "tcp" {
		proto = ""
	} else {
		proto = "-u"
	}

	iperfServer := s.GetContainerByName(IperfServerContainerName)
	iperfClient := s.GetContainerByName(IperfClientContainerName)
	iperfServer.Run()
	iperfClient.Run()
	serverInterface := s.GetInterfaceByName(ServerTapInterfaceName)
	clientInterface := s.GetInterfaceByName(ClientTapInterfaceName)
	vppProxy := s.GetContainerByName(VppProxyContainerName).VppInstance
	proxyPort, err := strconv.Atoi(s.GetPortFromPpid())
	s.AssertNil(err)

	// tap interfaces are created on test setup with 1 rx-queue,
	// need to recreate them with 2 + consistent-qp
	s.AssertNil(vppProxy.DeleteTap(serverInterface))
	s.AssertNil(vppProxy.CreateTap(serverInterface, 2, uint32(serverInterface.Peer.Index), Consistent_qp))

	s.AssertNil(vppProxy.DeleteTap(clientInterface))
	s.AssertNil(vppProxy.CreateTap(clientInterface, 2, uint32(clientInterface.Peer.Index), Consistent_qp))

	configureVppProxy(s, "tcp", uint16(proxyPort))
	if proto == "-u" {
		configureVppProxy(s, "udp", uint16(proxyPort))
	}

	stopServerCh := make(chan struct{}, 1)
	srvCh := make(chan error, 1)
	clnCh := make(chan error)
	clnRes := make(chan string, 1)

	defer func() {
		stopServerCh <- struct{}{}
	}()

	go func() {
		defer GinkgoRecover()
		cmd := fmt.Sprintf("iperf3 -4 -s -B %s -p %s", s.ServerAddr(), fmt.Sprint(s.ServerPort()))
		s.StartServerApp(iperfServer, "iperf3", cmd, srvCh, stopServerCh)
	}()

	err = <-srvCh
	s.AssertNil(err, fmt.Sprint(err))

	go func() {
		defer GinkgoRecover()
		cmd := fmt.Sprintf("iperf3 -c %s -P 4 -p %d -B %s %s", s.VppProxyAddr(), proxyPort, s.ClientAddr(), proto)
		s.StartClientApp(iperfClient, cmd, clnCh, clnRes)
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

	targetUri := fmt.Sprintf("http://%s:%d/httpTestFile", s.ServerAddr(), s.ServerPort())
	proxyUri := fmt.Sprintf("http://%s:%d", s.VppProxyAddr(), proxyPort)
	s.CurlDownloadResourceViaTunnel(targetUri, proxyUri)
}

func VppConnectProxyPutTest(s *VppProxySuite) {
	var proxyPort uint16 = 8080
	s.SetupNginxServer()
	configureVppProxy(s, "http", proxyPort)

	proxyUri := fmt.Sprintf("http://%s:%d", s.VppProxyAddr(), proxyPort)
	targetUri := fmt.Sprintf("http://%s:%d/upload/testFile", s.ServerAddr(), s.ServerPort())
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
