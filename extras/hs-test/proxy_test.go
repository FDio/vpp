package main

import (
	"fmt"
	"io"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/onsi/gomega/gmeasure"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterVppProxyTests(VppProxyHttpGetTcpTest, VppProxyHttpGetTlsTest, VppProxyHttpPutTcpTest, VppProxyHttpPutTlsTest,
		VppConnectProxyGetTest, VppConnectProxyPutTest)
	RegisterVppProxySoloTests(VppProxyHttpGetTcpMTTest, VppProxyHttpPutTcpMTTest, VppProxyTcpIperfMTTest, VppProxyUdpIperfMTTest)
	RegisterVppUdpProxyTests(VppProxyUdpTest, VppConnectUdpProxyTest, VppConnectUdpInvalidCapsuleTest,
		VppConnectUdpUnknownCapsuleTest, VppConnectUdpClientCloseTest, VppConnectUdpTortureTest)
	RegisterEnvoyProxyTests(EnvoyProxyHttpGetTcpTest, EnvoyProxyHttpPutTcpTest)
	RegisterNginxProxyTests(NginxMirroringTest)
	RegisterNginxProxySoloTests(MirrorMultiThreadTest)
}

func configureVppProxy(s *VppProxySuite, proto string, proxyPort uint16) {
	vppProxy := s.Containers.VppProxy.VppInstance
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
	s.Containers.IperfC.Run()
	s.Containers.IperfS.Run()
	vppProxy := s.Containers.VppProxy.VppInstance
	proxyPort, err := strconv.Atoi(s.GetPortFromPpid())
	s.AssertNil(err)

	// tap interfaces are created on test setup with 1 rx-queue,
	// need to recreate them with 2 + consistent-qp
	s.AssertNil(vppProxy.DeleteTap(s.Interfaces.Server))
	s.AssertNil(vppProxy.CreateTap(s.Interfaces.Server, 2, uint32(s.Interfaces.Server.Peer.Index), Consistent_qp))

	s.AssertNil(vppProxy.DeleteTap(s.Interfaces.Client))
	s.AssertNil(vppProxy.CreateTap(s.Interfaces.Client, 2, uint32(s.Interfaces.Client.Peer.Index), Consistent_qp))

	configureVppProxy(s, "tcp", uint16(proxyPort))
	if proto == "udp" {
		configureVppProxy(s, "udp", uint16(proxyPort))
		proto = "-u"
	} else {
		proto = ""
	}

	stopServerCh := make(chan struct{}, 1)
	srvCh := make(chan error, 1)
	clnCh := make(chan error)
	clnRes := make(chan []byte, 1)

	defer func() {
		stopServerCh <- struct{}{}
	}()

	go func() {
		defer GinkgoRecover()
		cmd := fmt.Sprintf("iperf3 -4 -s -B %s -p %s", s.ServerAddr(), fmt.Sprint(s.ServerPort()))
		s.StartServerApp(s.Containers.IperfS, "iperf3", cmd, srvCh, stopServerCh)
	}()

	err = <-srvCh
	s.AssertNil(err, fmt.Sprint(err))

	go func() {
		defer GinkgoRecover()
		cmd := fmt.Sprintf("iperf3 -c %s -P 4 -l 1460 -b 10g -J -p %d -B %s %s", s.VppProxyAddr(), proxyPort, s.ClientAddr(), proto)
		s.StartClientApp(s.Containers.IperfC, cmd, clnCh, clnRes)
	}()

	s.AssertChannelClosed(time.Minute*4, clnCh)
	result := s.ParseJsonIperfOutput(<-clnRes)
	s.LogJsonIperfOutput(result)
	s.AssertIperfMinTransfer(result, 400)
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
	vpp := s.Containers.Vpp.VppInstance

	s.AddVclConfig(s.Containers.NginxProxy, multiThreadWorkers)
	s.CreateNginxProxyConfig(s.Containers.NginxProxy, multiThreadWorkers)
	s.Containers.NginxProxy.Start()
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

	vppProxy := s.Containers.VppProxy.VppInstance
	cmd := fmt.Sprintf("test proxy server fifo-size 512k server-uri udp://%s/%d", s.VppProxyAddr(), s.ProxyPort())
	cmd += fmt.Sprintf(" client-uri udp://%s/%d", s.ServerAddr(), s.ServerPort())
	s.Log(vppProxy.Vppctl(cmd))

	b := make([]byte, 1500)
	n, err := s.ClientSendReceive([]byte("hello"), b)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertEqual([]byte("hello"), b[:n])
}

func VppConnectUdpProxyTest(s *VppUdpProxySuite) {
	remoteServerConn := s.StartEchoServer()
	defer remoteServerConn.Close()

	vppProxy := s.Containers.VppProxy.VppInstance
	vppProxy.Disconnect()
	cmd := fmt.Sprintf("test proxy server fifo-size 512k server-uri http://%s/%d", s.VppProxyAddr(), s.ProxyPort())
	s.Log(vppProxy.Vppctl(cmd))

	proxyAddress := fmt.Sprintf("%s:%d", s.VppProxyAddr(), s.ProxyPort())
	targetUri := fmt.Sprintf("http://%s:%d/.well-known/masque/udp/%s/%d/", s.VppProxyAddr(), s.ProxyPort(), s.ServerAddr(), s.ServerPort())
	c := s.NewConnectUdpClient(true)
	err := c.Dial(proxyAddress, targetUri, s.MaxTimeout)
	s.AssertNil(err, fmt.Sprint(err))
	defer c.Close()

	data := []byte("hello")

	err = c.WriteDgramCapsule(data)
	s.AssertNil(err, fmt.Sprint(err))
	payload, err := c.ReadDgramCapsule()
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertEqual(data, payload)
}

func VppConnectUdpInvalidCapsuleTest(s *VppUdpProxySuite) {
	remoteServerConn := s.StartEchoServer()
	defer remoteServerConn.Close()

	vppProxy := s.Containers.VppProxy.VppInstance
	vppProxy.Disconnect()
	cmd := fmt.Sprintf("test proxy server fifo-size 512k server-uri http://%s/%d", s.VppProxyAddr(), s.ProxyPort())
	s.Log(vppProxy.Vppctl(cmd))

	proxyAddress := fmt.Sprintf("%s:%d", s.VppProxyAddr(), s.ProxyPort())
	targetUri := fmt.Sprintf("http://%s:%d/.well-known/masque/udp/%s/%d/", s.VppProxyAddr(), s.ProxyPort(), s.ServerAddr(), s.ServerPort())
	c := s.NewConnectUdpClient(true)
	err := c.Dial(proxyAddress, targetUri, s.MaxTimeout)
	s.AssertNil(err, fmt.Sprint(err))
	defer c.Close()

	capsule := []byte{0x00, 0x9D, 0x7F, 0x3E, 0x7D, 0x00, 0x4B, 0x6E, 0x69, 0x67, 0x68, 0x74, 0x73, 0x20, 0x6F, 0x66, 0x20, 0x4E, 0x69}
	n, err := c.Conn.Write(capsule)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertEqual(n, len(capsule))
	b := make([]byte, 1)
	_, err = c.Conn.Read(b)
	s.AssertMatchError(err, io.EOF, "connection not closed by proxy")
}

func VppConnectUdpUnknownCapsuleTest(s *VppUdpProxySuite) {
	remoteServerConn := s.StartEchoServer()
	defer remoteServerConn.Close()

	vppProxy := s.Containers.VppProxy.VppInstance
	vppProxy.Disconnect()
	cmd := fmt.Sprintf("test proxy server fifo-size 512k server-uri http://%s/%d", s.VppProxyAddr(), s.ProxyPort())
	s.Log(vppProxy.Vppctl(cmd))

	proxyAddress := fmt.Sprintf("%s:%d", s.VppProxyAddr(), s.ProxyPort())
	targetUri := fmt.Sprintf("http://%s:%d/.well-known/masque/udp/%s/%d/", s.VppProxyAddr(), s.ProxyPort(), s.ServerAddr(), s.ServerPort())
	c := s.NewConnectUdpClient(true)
	err := c.Dial(proxyAddress, targetUri, s.MaxTimeout)
	s.AssertNil(err, fmt.Sprint(err))
	defer c.Close()

	err = c.WriteCapsule(0x4040, []byte("None shall pass"))
	s.AssertNil(err, fmt.Sprint(err))

	data := []byte("hello")
	err = c.WriteDgramCapsule(data)
	s.AssertNil(err, fmt.Sprint(err))
	payload, err := c.ReadDgramCapsule()
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertEqual(data, payload)
}

func VppConnectUdpClientCloseTest(s *VppUdpProxySuite) {
	remoteServerConn := s.StartEchoServer()
	defer remoteServerConn.Close()

	vppProxy := s.Containers.VppProxy.VppInstance
	vppProxy.Disconnect()
	cmd := fmt.Sprintf("test proxy server fifo-size 512k server-uri http://%s/%d", s.VppProxyAddr(), s.ProxyPort())
	s.Log(vppProxy.Vppctl(cmd))

	proxyAddress := fmt.Sprintf("%s:%d", s.VppProxyAddr(), s.ProxyPort())
	targetUri := fmt.Sprintf("http://%s:%d/.well-known/masque/udp/%s/%d/", s.VppProxyAddr(), s.ProxyPort(), s.ServerAddr(), s.ServerPort())
	c := s.NewConnectUdpClient(true)
	err := c.Dial(proxyAddress, targetUri, s.MaxTimeout)
	s.AssertNil(err, fmt.Sprint(err))

	err = c.Close()
	s.AssertNil(err, fmt.Sprint(err))
	proxyClientConn := fmt.Sprintf("[T] %s:%d->%s", s.VppProxyAddr(), s.ProxyPort(), s.ClientAddr())
	proxyTargetConn := fmt.Sprintf("[U] %s:", s.Interfaces.Server.Peer.Ip4AddressString())
	for nTries := 0; nTries < 10; nTries++ {
		o := vppProxy.Vppctl("show session verbose 2")
		if !strings.Contains(o, proxyClientConn) {
			break
		}
		time.Sleep(1 * time.Second)
	}
	sessions := vppProxy.Vppctl("show session verbose 2")
	s.Log(sessions)
	s.AssertNotContains(sessions, proxyClientConn, "client-proxy session not closed")
	s.AssertNotContains(sessions, proxyTargetConn, "proxy-server session not closed")
}

type connectionParameters struct {
	proxyAddress string
	targetUri    string
	timeout      time.Duration
}

func connectUdpDataTransfer(s *VppUdpProxySuite, experiment *gmeasure.Experiment, data interface{}) {
	defer GinkgoRecover()
	params, isValid := data.(connectionParameters)
	s.AssertEqual(true, isValid)
	c := s.NewConnectUdpClient(false)
	err := c.Dial(params.proxyAddress, params.targetUri, params.timeout)
	s.AssertNil(err, fmt.Sprint(err))
	defer c.Close()

	req := make([]byte, 64)
	rand.Read(req)

	experiment.MeasureDuration("10k req 64B", func() {
		for i := 0; i < 10000; i++ {
			err = c.WriteDgramCapsule(req)
			s.AssertNil(err, fmt.Sprint(err))
			payload, err := c.ReadDgramCapsule()
			s.AssertNil(err, fmt.Sprint(err))
			s.AssertEqual(req, payload)
		}
	})
}

func VppConnectUdpTortureTest(s *VppUdpProxySuite) {
	remoteServerConn := s.StartEchoServer()
	defer remoteServerConn.Close()

	vppProxy := s.Containers.VppProxy.VppInstance
	vppProxy.Disconnect()
	cmd := fmt.Sprintf("test proxy server fifo-size 512k server-uri http://%s/%d", s.VppProxyAddr(), s.ProxyPort())
	s.Log(vppProxy.Vppctl(cmd))

	var params connectionParameters
	params.proxyAddress = fmt.Sprintf("%s:%d", s.VppProxyAddr(), s.ProxyPort())
	params.targetUri = fmt.Sprintf("http://%s:%d/.well-known/masque/udp/%s/%d/", s.VppProxyAddr(), s.ProxyPort(), s.ServerAddr(), s.ServerPort())
	params.timeout = s.MaxTimeout

	experiment := gmeasure.NewExperiment("HTTP CONNECT-UDP")

	experiment.Sample(func(idx int) {
		connectUdpDataTransfer(s, experiment, params)
	}, gmeasure.SamplingConfig{Duration: 30 * time.Second, NumParallel: 5})
	AddReportEntry(experiment.Name, experiment)
}
