package main

import (
	"fmt"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterVppProxyTests(VppProxyHttpGetTcpTest, VppProxyHttpGetTlsTest, VppProxyHttpPutTcpTest, VppProxyHttpPutTlsTest,
		VppConnectProxyGetTest, VppConnectProxyPutTest)
	RegisterVppProxySoloTests(VppProxyHttpGetTcpMTTest)
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

func VppProxyHttpGetTcpTest(s *VppProxySuite) {
	var proxyPort uint16 = 8080
	configureVppProxy(s, "tcp", proxyPort)
	uri := fmt.Sprintf("http://%s:%d/httpTestFile", s.VppProxyAddr(), proxyPort)
	s.CurlDownloadResource(uri)
}

func VppProxyHttpGetTlsTest(s *VppProxySuite) {
	var proxyPort uint16 = 8080
	configureVppProxy(s, "tls", proxyPort)
	uri := fmt.Sprintf("https://%s:%d/httpTestFile", s.VppProxyAddr(), proxyPort)
	s.CurlDownloadResource(uri)
}

func VppProxyHttpPutTcpTest(s *VppProxySuite) {
	var proxyPort uint16 = 8080
	configureVppProxy(s, "tcp", proxyPort)
	uri := fmt.Sprintf("http://%s:%d/upload/testFile", s.VppProxyAddr(), proxyPort)
	s.CurlUploadResource(uri, CurlContainerTestFile)
}

func VppProxyHttpPutTlsTest(s *VppProxySuite) {
	var proxyPort uint16 = 8080
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

	configureVppProxy(s, "http", proxyPort)

	targetUri := fmt.Sprintf("http://%s:%d/httpTestFile", s.NginxAddr(), s.NginxPort())
	proxyUri := fmt.Sprintf("http://%s:%d", s.VppProxyAddr(), proxyPort)
	s.CurlDownloadResourceViaTunnel(targetUri, proxyUri)
}

func VppConnectProxyPutTest(s *VppProxySuite) {
	var proxyPort uint16 = 8080

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
