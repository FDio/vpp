package main

import (
	. "fd.io/hs-test/infra"
	"fmt"
)

func init() {
	RegisterVppProxyTests(VppProxyHttpTcpTest, VppProxyHttpTlsTest)
	RegisterEnvoyProxyTests(EnvoyProxyHttpTcpTest)
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

func VppProxyHttpTcpTest(s *VppProxySuite) {
	var proxyPort uint16 = 8080
	configureVppProxy(s, "tcp", proxyPort)
	uri := fmt.Sprintf("http://%s:%d/httpTestFile", s.VppProxyAddr(), proxyPort)
	s.CurlDownloadResource(uri)
}

func VppProxyHttpTlsTest(s *VppProxySuite) {
	var proxyPort uint16 = 8080
	configureVppProxy(s, "tls", proxyPort)
	uri := fmt.Sprintf("https://%s:%d/httpTestFile", s.VppProxyAddr(), proxyPort)
	s.CurlDownloadResource(uri)
}

func EnvoyProxyHttpTcpTest(s *EnvoyProxySuite) {
	uri := fmt.Sprintf("http://%s:%d/httpTestFile", s.ProxyAddr(), s.ProxyPort())
	s.CurlDownloadResource(uri)
}
