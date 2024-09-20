package main

import (
	. "fd.io/hs-test/infra"
	"fmt"
)

func init() {
	RegisterVppProxyTests(VppProxyHttpGetTcpTest, VppProxyHttpGetTlsTest, VppProxyHttpPutTcpTest, VppProxyHttpPutTlsTest,
		VppConnectProxyGetTest, VppConnectProxyPutTest)
	RegisterEnvoyProxyTests(EnvoyProxyHttpGetTcpTest, EnvoyProxyHttpPutTcpTest)
	RegisterNginxProxyTests(NginxMirroringTest)
}

func configureVppProxy(s *VppProxySuite, proto string, proxyPort uint16) {
	vppProxy := s.GetContainerByName(VppProxyContainerName).VppInstance
	output := vppProxy.Vppctl(
		"test proxy server server-uri %s://%s/%d client-uri tcp://%s/%d",
		proto,
		s.VppProxyAddr(),
		proxyPort,
		s.NginxAddr(),
		s.NginxPort(),
	)
	s.Log("proxy configured: " + output)
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

// broken when CPUS > 1
func NginxMirroringTest(s *NginxProxySuite) {
	s.SkipIfMultiWorker()
	uri := fmt.Sprintf("http://%s:%d/httpTestFile", s.ProxyAddr(), s.ProxyPort())
	s.CurlDownloadResource(uri)
}

func VppConnectProxyGetTest(s *VppProxySuite) {
	var proxyPort uint16 = 8080
	vpp := s.GetContainerByName(VppProxyContainerName).VppInstance

	rv := vpp.Vppctl("http connect proxy uri tcp://%s/%d", s.VppProxyAddr(), proxyPort)
	s.AssertEmpty(rv)

	targetUri := fmt.Sprintf("http://%s:%d/httpTestFile", s.NginxAddr(), s.NginxPort())
	proxyUri := fmt.Sprintf("http://%s:%d", s.VppProxyAddr(), proxyPort)
	s.CurlDownloadResourceViaTunnel(targetUri, proxyUri)
}

func VppConnectProxyPutTest(s *VppProxySuite) {
	var proxyPort uint16 = 8080
	vpp := s.GetContainerByName(VppProxyContainerName).VppInstance

	rv := vpp.Vppctl("http connect proxy uri tcp://%s/%d", s.VppProxyAddr(), proxyPort)
	s.AssertEmpty(rv)

	proxyUri := fmt.Sprintf("http://%s:%d", s.VppProxyAddr(), proxyPort)
	targetUri := fmt.Sprintf("http://%s:%d/upload/testFile", s.NginxAddr(), s.NginxPort())
	s.CurlUploadResourceViaTunnel(targetUri, proxyUri, CurlContainerTestFile)
}
