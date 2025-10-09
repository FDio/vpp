package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterVppProxyTests(VppProxyHttpGetTcpTest, VppProxyHttpGetTlsTest, VppProxyHttpPutTcpTest, VppProxyHttpPutTlsTest,
		VppConnectProxyGetTest, VppConnectProxyPutTest, VppHttpsConnectProxyGetTest, VppH2ConnectProxyGetTest,
		VppH2ConnectProxyPutTest)
	RegisterVppProxyMWTests(VppProxyHttpGetTcpMWTest, VppProxyHttpPutTcpMWTest, VppProxyTcpIperfMWTest,
		VppProxyUdpIperfMWTest, VppConnectProxyStressMWTest, VppConnectProxyConnectionFailedMWTest)
	RegisterVppProxySoloTests(VppConnectProxyStressTest)
	RegisterVppUdpProxyTests(VppProxyUdpTest, VppConnectUdpProxyTest, VppConnectUdpInvalidCapsuleTest,
		VppConnectUdpUnknownCapsuleTest, VppConnectUdpClientCloseTest, VppConnectUdpInvalidTargetTest, VppConnectUdpServerCloseTest)
	RegisterVppUdpProxySoloTests(VppConnectUdpStressTest)
	RegisterVppUdpProxyMWTests(VppProxyUdpMigrationMWTest, VppConnectUdpStressMWTest)
	RegisterEnvoyProxyTests(EnvoyHttpGetTcpTest, EnvoyHttpPutTcpTest)
	RegisterNginxProxySoloTests(NginxMirroringTest, MirrorMultiThreadTest)
	RegisterMasqueTests(VppConnectProxyClientDownloadUdpTest,
		VppConnectProxyClientUploadUdpTest, VppConnectProxyMemLeakTest)
	RegisterMasqueSoloTests(VppConnectProxyIperfTcpTest, VppConnectProxyIperfUdpTest)
	RegisterMasqueMWTests(VppConnectProxyIperfTcpMWTest, VppConnectProxyIperfUdpMWTest, VppConnectProxyClientUploadTcpMWTest,
		VppConnectProxyClientTargetUnreachableMWTest, VppConnectProxyClientDownloadTcpMWTest,
		VppConnectProxyClientStressMWTest, VppConnectProxyClientUdpIdleMWTest, VppConnectProxyClientServerClosedTcpMWTest)
}

func VppProxyHttpGetTcpMWTest(s *VppProxySuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	VppProxyHttpGetTcpTest(s)
}

func VppProxyTcpIperfMWTest(s *VppProxySuite) {
	vppProxyIperfMWTest(s, "tcp")
}

func VppProxyUdpIperfMWTest(s *VppProxySuite) {
	vppProxyIperfMWTest(s, "udp")
}

func vppProxyIperfMWTest(s *VppProxySuite, proto string) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	s.Containers.IperfC.Run()
	s.Containers.IperfS.Run()

	s.ConfigureVppProxy("tcp", s.Ports.Proxy)
	if proto == "udp" {
		s.ConfigureVppProxy("udp", s.Ports.Proxy)
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
		cmd := fmt.Sprintf("iperf3 -4 -s -B %s -p %s --logfile %s", s.ServerAddr(), fmt.Sprint(s.Ports.Server), s.IperfLogFileName(s.Containers.IperfS))
		s.StartServerApp(s.Containers.IperfS, "iperf3", cmd, srvCh, stopServerCh)
	}()

	err := <-srvCh
	s.AssertNil(err, fmt.Sprint(err))

	go func() {
		defer GinkgoRecover()
		cmd := fmt.Sprintf("iperf3 -c %s -P 4 -l 1460 -b 10g -J -p %d -B %s %s", s.VppProxyAddr(), s.Ports.Proxy, s.ClientAddr(), proto)
		s.StartClientApp(s.Containers.IperfC, cmd, clnCh, clnRes)
	}()

	s.AssertChannelClosed(time.Minute*4, clnCh)
	result := s.ParseJsonIperfOutput(<-clnRes)
	s.LogJsonIperfOutput(result)
	s.AssertIperfMinTransfer(result, 200)
}

func VppProxyHttpGetTcpTest(s *VppProxySuite) {
	s.SetupNginxServer()
	s.ConfigureVppProxy("tcp", s.Ports.Proxy)
	uri := fmt.Sprintf("http://%s:%d/httpTestFile", s.VppProxyAddr(), s.Ports.Proxy)
	s.CurlDownloadResource(uri)
}

func VppProxyHttpGetTlsTest(s *VppProxySuite) {
	s.SetupNginxServer()
	s.ConfigureVppProxy("tls", s.Ports.Proxy)
	uri := fmt.Sprintf("https://%s:%d/httpTestFile", s.VppProxyAddr(), s.Ports.Proxy)
	s.CurlDownloadResource(uri)
}

func VppProxyHttpPutTcpMWTest(s *VppProxySuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	VppProxyHttpPutTcpTest(s)
}

func VppProxyHttpPutTcpTest(s *VppProxySuite) {
	s.SetupNginxServer()
	s.ConfigureVppProxy("tcp", s.Ports.Proxy)
	uri := fmt.Sprintf("http://%s:%d/upload/testFile", s.VppProxyAddr(), s.Ports.Proxy)
	s.CurlUploadResource(uri, CurlContainerTestFile)
}

func VppProxyHttpPutTlsTest(s *VppProxySuite) {
	s.SetupNginxServer()
	s.ConfigureVppProxy("tls", s.Ports.Proxy)
	uri := fmt.Sprintf("https://%s:%d/upload/testFile", s.VppProxyAddr(), s.Ports.Proxy)
	s.CurlUploadResource(uri, CurlContainerTestFile)
}

func EnvoyHttpGetTcpTest(s *EnvoyProxySuite) {
	uri := fmt.Sprintf("http://%s:%d/httpTestFile", s.ProxyAddr(), s.Ports.Proxy)
	s.CurlDownloadResource(uri)
}

func EnvoyHttpPutTcpTest(s *EnvoyProxySuite) {
	uri := fmt.Sprintf("http://%s:%d/upload/testFile", s.ProxyAddr(), s.Ports.Proxy)
	s.CurlUploadResource(uri, CurlContainerTestFile)
}

func MirrorMultiThreadTest(s *NginxProxySuite) {
	nginxMirroring(s, true)
}

// unstable, registered as solo
func NginxMirroringTest(s *NginxProxySuite) {
	nginxMirroring(s, false)
}

func nginxMirroring(s *NginxProxySuite, multiThreadWorkers bool) {
	vpp := s.Containers.Vpp.VppInstance

	s.AddVclConfig(s.Containers.NginxProxy, multiThreadWorkers)
	s.CreateNginxProxyConfig(s.Containers.NginxProxy, multiThreadWorkers)
	s.Containers.NginxProxy.Start()
	vpp.WaitForApp("nginx-", 5)
	uri := fmt.Sprintf("http://%s:%d/httpTestFile", s.ProxyAddr(), s.Ports.Proxy)
	s.CurlDownloadResource(uri)
}

func VppConnectProxyGetTest(s *VppProxySuite) {
	s.SetupNginxServer()
	s.ConfigureVppProxy("http", s.Ports.Proxy)

	targetUri := fmt.Sprintf("http://%s:%d/httpTestFile", s.ServerAddr(), s.Ports.Server)
	proxyUri := fmt.Sprintf("http://%s:%d", s.VppProxyAddr(), s.Ports.Proxy)
	s.CurlDownloadResourceViaTunnel(targetUri, proxyUri)
}

func VppHttpsConnectProxyGetTest(s *VppProxySuite) {
	s.SetupNginxServer()
	s.ConfigureVppProxy("https", s.Ports.Proxy)

	targetUri := fmt.Sprintf("http://%s:%d/httpTestFile", s.ServerAddr(), s.Ports.Server)
	proxyUri := fmt.Sprintf("https://%s:%d", s.VppProxyAddr(), s.Ports.Proxy)
	s.CurlDownloadResourceViaTunnel(targetUri, proxyUri)
}

func VppH2ConnectProxyGetTest(s *VppProxySuite) {
	s.SetupNginxServer()
	s.ConfigureVppProxy("https", s.Ports.Proxy)

	targetUri := fmt.Sprintf("http://%s:%d/httpTestFile", s.ServerAddr(), s.Ports.Server)
	proxyUri := fmt.Sprintf("https://%s:%d", s.VppProxyAddr(), s.Ports.Proxy)
	_, log := s.CurlDownloadResourceViaTunnel(targetUri, proxyUri, "--proxy-http2")
	// ALPN result check
	s.AssertContains(log, "CONNECT tunnel: HTTP/2 negotiated")
}

func VppConnectProxyConnectionFailedMWTest(s *VppProxySuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	s.SetupNginxServer()
	s.ConfigureVppProxy("http", s.Ports.Proxy)

	targetUri := fmt.Sprintf("http://%s:%d/httpTestFile", s.ServerAddr(), s.Ports.Server+1)
	proxyUri := fmt.Sprintf("http://%s:%d", s.VppProxyAddr(), s.Ports.Proxy)
	_, log := s.CurlRequestViaTunnel(targetUri, proxyUri)
	s.AssertContains(log, "HTTP/1.1 502 Bad Gateway")
}

func VppConnectProxyPutTest(s *VppProxySuite) {
	s.SetupNginxServer()
	s.ConfigureVppProxy("http", s.Ports.Proxy)

	proxyUri := fmt.Sprintf("http://%s:%d", s.VppProxyAddr(), s.Ports.Proxy)
	targetUri := fmt.Sprintf("http://%s:%d/upload/testFile", s.ServerAddr(), s.Ports.Server)
	s.CurlUploadResourceViaTunnel(targetUri, proxyUri, CurlContainerTestFile)
}

func VppH2ConnectProxyPutTest(s *VppProxySuite) {
	s.SetupNginxServer()
	s.ConfigureVppProxy("https", s.Ports.Proxy)

	proxyUri := fmt.Sprintf("https://%s:%d", s.VppProxyAddr(), s.Ports.Proxy)
	targetUri := fmt.Sprintf("http://%s:%d/upload/testFile", s.ServerAddr(), s.Ports.Server)
	_, log := s.CurlUploadResourceViaTunnel(targetUri, proxyUri, CurlContainerTestFile, "--proxy-http2")
	// ALPN result check
	s.AssertContains(log, "CONNECT tunnel: HTTP/2 negotiated")
}

func vppConnectProxyStressLoad(s *VppProxySuite, proxyPort string) {
	var (
		connectError, timeout, readError, writeError, invalidData, total atomic.Uint32
		wg                                                               sync.WaitGroup
	)
	stop := make(chan struct{})
	targetUri := fmt.Sprintf("%s:%d", s.ServerAddr(), s.Ports.Server)
	s.Log("Running 30s test @ " + targetUri)

	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			var tot, timed, re, we uint32
			defer wg.Done()
			defer func() {
				total.Add(tot)
				timeout.Add(timed)
				readError.Add(re)
				writeError.Add(we)
			}()
		connRestart:
			conn, err := net.DialTimeout("tcp", s.VppProxyAddr()+":"+proxyPort, time.Second*10)
			if err != nil {
				connectError.Add(1)
				return
			}
			defer conn.Close()

			conn.SetDeadline(time.Now().Add(time.Second * 5))

			var b bytes.Buffer
			fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\n", targetUri)
			fmt.Fprintf(&b, "Host: %s\r\n", s.ServerAddr())
			fmt.Fprintf(&b, "User-Agent: hs-test\r\n")
			io.WriteString(&b, "\r\n")
			_, err = conn.Write(b.Bytes())
			if err != nil {
				connectError.Add(1)
				return
			}
			r := bufio.NewReader(conn)
			resp, err := http.ReadResponse(r, nil)
			if err != nil {
				connectError.Add(1)
				return
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				connectError.Add(1)
				return
			}

			req := make([]byte, 64)
			rand.Read(req)

			for {
				select {
				default:
					conn.SetDeadline(time.Now().Add(time.Second * 5))
					tot += 1
					_, e := conn.Write(req)
					if e != nil {
						if errors.Is(e, os.ErrDeadlineExceeded) {
							timed += 1
						} else {
							we += 1
						}
						continue
					}
					reply := make([]byte, 1024)
					n, e := conn.Read(reply)
					if e != nil {
						if errors.Is(e, os.ErrDeadlineExceeded) {
							timed += 1
						} else {
							re += 1
						}
						conn.Close()
						goto connRestart
					}
					if bytes.Compare(req, reply[:n]) != 0 {
						invalidData.Add(1)
						conn.Close()
						goto connRestart
					}
				case <-stop:
					return
				}
			}

		}()
	}
	for i := 0; i < 30; i++ {
		GinkgoWriter.Print(".")
		time.Sleep(time.Second)
	}
	GinkgoWriter.Print("\n")
	close(stop) // tell clients to stop
	wg.Wait()   // wait until clients finish
	successRatio := (float64(total.Load()-(timeout.Load()+readError.Load()+writeError.Load()+invalidData.Load())) / float64(total.Load())) * 100.0
	summary := fmt.Sprintf("1000 connections %d requests in 30s", total.Load())
	report := fmt.Sprintf("Requests/sec: %d\n", total.Load()/30)
	report += fmt.Sprintf("Errors: timeout %d, read %d, write %d, invalid data received %d, connection %d\n", timeout.Load(), readError.Load(), writeError.Load(), invalidData.Load(), connectError.Load())
	report += fmt.Sprintf("Successes ratio: %.2f%%\n", successRatio)
	AddReportEntry(summary, report)
	s.AssertGreaterEqual(successRatio, 90.0)
}

func VppConnectProxyStressTest(s *VppProxySuite) {
	remoteServerConn := s.StartTcpEchoServer(s.ServerAddr(), int(s.Ports.Server))
	defer remoteServerConn.Close()

	s.ConfigureVppProxy("http", s.Ports.Proxy)

	// no goVPP less noise
	s.Containers.VppProxy.VppInstance.Disconnect()

	vppConnectProxyStressLoad(s, strconv.Itoa(int(s.Ports.Proxy)))
}

func VppConnectProxyStressMWTest(s *VppProxySuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	remoteServerConn := s.StartTcpEchoServer(s.ServerAddr(), int(s.Ports.Server))
	defer remoteServerConn.Close()

	vppProxy := s.Containers.VppProxy.VppInstance

	s.ConfigureVppProxy("http", s.Ports.Proxy)

	// no goVPP less noise
	vppProxy.Disconnect()

	vppConnectProxyStressLoad(s, strconv.Itoa(int(s.Ports.Proxy)))
}

func VppProxyUdpTest(s *VppUdpProxySuite) {
	remoteServerConn := s.StartUdpEchoServer(s.ServerAddr(), s.Ports.Server)
	defer remoteServerConn.Close()

	vppProxy := s.Containers.VppProxy.VppInstance
	cmd := fmt.Sprintf("test proxy server fifo-size 512k server-uri udp://%s/%d", s.VppProxyAddr(), s.Ports.Proxy)
	cmd += fmt.Sprintf(" client-uri udp://%s/%d", s.ServerAddr(), s.Ports.Server)
	s.Log(vppProxy.Vppctl(cmd))

	b := make([]byte, 1500)
	n, err := s.ClientSendReceive([]byte("hello"), b)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertEqual([]byte("hello"), b[:n])
}

func VppProxyUdpMigrationMWTest(s *VppUdpProxySuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	remoteServerConn := s.StartUdpEchoServer(s.ServerAddr(), s.Ports.Server)
	defer remoteServerConn.Close()

	vppProxy := s.Containers.VppProxy.VppInstance
	cmd := fmt.Sprintf("test proxy server fifo-size 512k server-uri udp://%s/%d", s.VppProxyAddr(), s.Ports.Proxy)
	cmd += fmt.Sprintf(" client-uri udp://%s/%d", s.ServerAddr(), s.Ports.Server)
	s.Log(vppProxy.Vppctl(cmd))

	b := make([]byte, 1500)

	n, err := s.ClientSendReceive([]byte("hello"), b)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertEqual([]byte("hello"), b[:n])

	n, err = s.ClientSendReceive([]byte("world"), b)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertEqual([]byte("world"), b[:n])

	s.Log(s.Containers.VppProxy.VppInstance.Vppctl("show session verbose 2"))
}

func VppConnectUdpProxyTest(s *VppUdpProxySuite) {
	remoteServerConn := s.StartUdpEchoServer(s.ServerAddr(), s.Ports.Server)
	defer remoteServerConn.Close()

	vppProxy := s.Containers.VppProxy.VppInstance
	cmd := fmt.Sprintf("test proxy server fifo-size 512k server-uri http://%s/%d", s.VppProxyAddr(), s.Ports.Proxy)
	s.Log(vppProxy.Vppctl(cmd))

	proxyAddress := fmt.Sprintf("%s:%d", s.VppProxyAddr(), s.Ports.Proxy)
	targetUri := fmt.Sprintf("http://%s:%d/.well-known/masque/udp/%s/%d/", s.VppProxyAddr(), s.Ports.Proxy, s.ServerAddr(), s.Ports.Server)
	c := s.NewConnectUdpClient(s.MaxTimeout, true)
	err := c.Dial(proxyAddress, targetUri)
	s.AssertNil(err, fmt.Sprint(err))
	defer c.Close()

	data := []byte("hello")

	err = c.WriteDgramCapsule(data)
	s.AssertNil(err, fmt.Sprint(err))
	payload, err := c.ReadDgramCapsule()
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertEqual(data, payload)
}

func VppConnectUdpServerCloseTest(s *VppUdpProxySuite) {
	remoteServerConn := s.StartUdpEchoServer(s.ServerAddr(), s.Ports.Server)
	defer remoteServerConn.Close()

	vppProxy := s.Containers.VppProxy.VppInstance
	vppProxy.Disconnect()
	cmd := fmt.Sprintf("test proxy server fifo-size 512k server-uri http://%s/%d", s.VppProxyAddr(), s.Ports.Proxy)
	s.Log(vppProxy.Vppctl(cmd))

	proxyAddress := fmt.Sprintf("%s:%d", s.VppProxyAddr(), s.Ports.Proxy)
	targetUri := fmt.Sprintf("http://%s:%d/.well-known/masque/udp/%s/%d/", s.VppProxyAddr(), s.Ports.Proxy, s.ServerAddr(), s.Ports.Server)
	c := s.NewConnectUdpClient(s.MaxTimeout, true)
	err := c.Dial(proxyAddress, targetUri)
	s.AssertNil(err, fmt.Sprint(err))
	defer c.Close()

	err = remoteServerConn.Close()
	s.AssertNil(err, fmt.Sprint(err))

	data := []byte("hello")
	err = c.WriteDgramCapsule(data)
	s.AssertNil(err, fmt.Sprint(err))

	proxyClientConn := fmt.Sprintf("[T] %s:%d->%s", s.VppProxyAddr(), s.Ports.Proxy, s.ClientAddr())
	proxyTargetConn := fmt.Sprintf("[U] %s:", s.Interfaces.Server.Ip4Address)
	for nTries := 0; nTries < 10; nTries++ {
		o := vppProxy.Vppctl("show session verbose 2")
		s.Log(o)
		if !strings.Contains(o, proxyClientConn) {
			break
		}
		time.Sleep(3 * time.Second)
	}
	sessions := vppProxy.Vppctl("show session verbose 2")
	s.Log(sessions)
	s.AssertNotContains(sessions, proxyClientConn, "client-proxy session not closed")
	s.AssertNotContains(sessions, proxyTargetConn, "proxy-server session not closed")
}

func VppConnectUdpInvalidTargetTest(s *VppUdpProxySuite) {
	vppProxy := s.Containers.VppProxy.VppInstance
	cmd := fmt.Sprintf("test proxy server fifo-size 512k server-uri http://%s/%d", s.VppProxyAddr(), s.Ports.Proxy)
	s.Log(vppProxy.Vppctl(cmd))

	proxyAddress := fmt.Sprintf("%s:%d", s.VppProxyAddr(), s.Ports.Proxy)

	targetUri := fmt.Sprintf("http://%s:%d/.well-known/masque/udp/example.com/80/", s.VppProxyAddr(), s.Ports.Proxy)
	c := s.NewConnectUdpClient(s.MaxTimeout, true)
	err := c.Dial(proxyAddress, targetUri)
	s.AssertNotNil(err, "name resolution not supported")

	targetUri = fmt.Sprintf("http://%s:%d/.well-known/masque/udp/1.2.3.4/800000000/", s.VppProxyAddr(), s.Ports.Proxy)
	c = s.NewConnectUdpClient(s.MaxTimeout, true)
	err = c.Dial(proxyAddress, targetUri)
	s.AssertNotNil(err, "invalid port number")

	targetUri = fmt.Sprintf("http://%s:%d/masque/udp/1.2.3.4/80/", s.VppProxyAddr(), s.Ports.Proxy)
	c = s.NewConnectUdpClient(s.MaxTimeout, true)
	err = c.Dial(proxyAddress, targetUri)
	s.AssertNotNil(err, "invalid prefix")
}

func VppConnectUdpInvalidCapsuleTest(s *VppUdpProxySuite) {
	remoteServerConn := s.StartUdpEchoServer(s.ServerAddr(), s.Ports.Server)
	defer remoteServerConn.Close()

	vppProxy := s.Containers.VppProxy.VppInstance
	cmd := fmt.Sprintf("test proxy server fifo-size 512k server-uri http://%s/%d", s.VppProxyAddr(), s.Ports.Proxy)
	s.Log(vppProxy.Vppctl(cmd))

	proxyAddress := fmt.Sprintf("%s:%d", s.VppProxyAddr(), s.Ports.Proxy)
	targetUri := fmt.Sprintf("http://%s:%d/.well-known/masque/udp/%s/%d/", s.VppProxyAddr(), s.Ports.Proxy, s.ServerAddr(), s.Ports.Server)
	c := s.NewConnectUdpClient(s.MaxTimeout, true)
	err := c.Dial(proxyAddress, targetUri)
	s.AssertNil(err, fmt.Sprint(err))
	defer c.Close()

	// Capsule length is set to 494878333 which exceed maximum allowed UDP payload length 65527 and connection must be aborted
	capsule := []byte{
		0x00,                   // type
		0x9D, 0x7F, 0x3E, 0x7D, // length
		0x00,                                                                         // context ID
		0x4B, 0x6E, 0x69, 0x67, 0x68, 0x74, 0x73, 0x20, 0x6F, 0x66, 0x20, 0x4E, 0x69, // some extra junk
	}
	n, err := c.Conn.Write(capsule)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertEqual(n, len(capsule))
	b := make([]byte, 1)
	_, err = c.Conn.Read(b)
	s.AssertMatchError(err, io.EOF, "connection not closed by proxy")
}

func VppConnectUdpUnknownCapsuleTest(s *VppUdpProxySuite) {
	remoteServerConn := s.StartUdpEchoServer(s.ServerAddr(), s.Ports.Server)
	defer remoteServerConn.Close()

	vppProxy := s.Containers.VppProxy.VppInstance
	cmd := fmt.Sprintf("test proxy server fifo-size 512k server-uri http://%s/%d", s.VppProxyAddr(), s.Ports.Proxy)
	s.Log(vppProxy.Vppctl(cmd))

	proxyAddress := fmt.Sprintf("%s:%d", s.VppProxyAddr(), s.Ports.Proxy)
	targetUri := fmt.Sprintf("http://%s:%d/.well-known/masque/udp/%s/%d/", s.VppProxyAddr(), s.Ports.Proxy, s.ServerAddr(), s.Ports.Server)
	c := s.NewConnectUdpClient(s.MaxTimeout, true)
	err := c.Dial(proxyAddress, targetUri)
	s.AssertNil(err, fmt.Sprint(err))
	defer c.Close()

	// Send capsule with unknown type 0x40 which is outside range for standards (0x00 - 0x3f)
	// Endpoint that receives capsule with unknown type must silently drop that capsule and skip over to parse the next capsule
	err = c.WriteCapsule(0x4040, []byte("None shall pass"))
	s.AssertNil(err, fmt.Sprint(err))

	// Send valid capsule to verify that previous was dropped
	data := []byte("hello")
	err = c.WriteDgramCapsule(data)
	s.AssertNil(err, fmt.Sprint(err))
	payload, err := c.ReadDgramCapsule()
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertEqual(data, payload)
}

func VppConnectUdpClientCloseTest(s *VppUdpProxySuite) {
	remoteServerConn := s.StartUdpEchoServer(s.ServerAddr(), s.Ports.Server)
	defer remoteServerConn.Close()

	vppProxy := s.Containers.VppProxy.VppInstance
	cmd := fmt.Sprintf("test proxy server fifo-size 512k server-uri http://%s/%d", s.VppProxyAddr(), s.Ports.Proxy)
	s.Log(vppProxy.Vppctl(cmd))

	proxyAddress := fmt.Sprintf("%s:%d", s.VppProxyAddr(), s.Ports.Proxy)
	targetUri := fmt.Sprintf("http://%s:%d/.well-known/masque/udp/%s/%d/", s.VppProxyAddr(), s.Ports.Proxy, s.ServerAddr(), s.Ports.Server)
	c := s.NewConnectUdpClient(s.MaxTimeout, true)
	err := c.Dial(proxyAddress, targetUri)
	s.AssertNil(err, fmt.Sprint(err))

	err = c.Close()
	s.AssertNil(err, fmt.Sprint(err))
	//proxyClientConn := fmt.Sprintf("[T] %s:%d->%s", s.VppProxyAddr(), s.Ports.Proxy, s.ClientAddr())
	proxyTargetConn := fmt.Sprintf("[U] %s:", s.Interfaces.Server.Peer.Ip4AddressString())
	/*for nTries := 0; nTries < 10; nTries++ {
		o := vppProxy.Vppctl("show session verbose 2")
		if !strings.Contains(o, proxyClientConn) {
			break
		}
		time.Sleep(1 * time.Second)
	}
	s.Log(sessions)
	s.AssertNotContains(sessions, proxyClientConn, "client-proxy session not closed")*/
	sessions := vppProxy.Vppctl("show session verbose 2")
	s.AssertNotContains(sessions, proxyTargetConn, "proxy-server session not closed")
}

func vppConnectUdpStressLoad(s *VppUdpProxySuite) {
	var (
		connectError, timeout, readError, writeError, invalidData, total atomic.Uint32
		wg                                                               sync.WaitGroup
	)

	proxyAddress := fmt.Sprintf("%s:%d", s.VppProxyAddr(), s.Ports.Proxy)
	targetUri := fmt.Sprintf("http://%s/.well-known/masque/udp/%s/%d/", proxyAddress, s.ServerAddr(), s.Ports.Server)

	// warm-up
	warmUp := s.NewConnectUdpClient(s.MaxTimeout, false)
	err := warmUp.Dial(proxyAddress, targetUri)
	s.AssertNil(err, fmt.Sprint(err))
	defer warmUp.Close()
	data := []byte("hello")
	err = warmUp.WriteDgramCapsule(data)
	s.AssertNil(err, fmt.Sprint(err))
	payload, err := warmUp.ReadDgramCapsule()
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertEqual(data, payload)
	warmUp.Close()

	stop := make(chan struct{})

	s.Log("Running 30s test @ " + targetUri)
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			var tot, timed, re, we uint32
			defer wg.Done()
			defer func() {
				total.Add(tot)
				timeout.Add(timed)
				readError.Add(re)
				writeError.Add(we)
			}()
		restart:
			c := s.NewConnectUdpClient(s.MaxTimeout, false)
			e := c.Dial(proxyAddress, targetUri)
			if e != nil {
				connectError.Add(1)
				return
			}
			defer c.Close()

			req := make([]byte, 64)
			rand.Read(req)

			for {
				select {
				default:
					tot += 1
					e = c.WriteDgramCapsule(req)
					if e != nil {
						if errors.Is(e, os.ErrDeadlineExceeded) {
							timed += 1
						} else {
							we += 1
						}
						continue
					}
					resp, e := c.ReadDgramCapsule()
					if e != nil {
						if errors.Is(e, os.ErrDeadlineExceeded) {
							timed += 1
						} else if errors.Is(e, &CapsuleParseError{}) {
							invalidData.Add(1)
						} else {
							re += 1
						}
						c.Close()
						goto restart
					}
					if bytes.Compare(req, resp) != 0 {
						invalidData.Add(1)
						c.Close()
						goto restart
					}
				case <-stop:
					return
				}
			}
		}()
	}
	for i := 0; i < 30; i++ {
		GinkgoWriter.Print(".")
		time.Sleep(time.Second)
	}
	GinkgoWriter.Print("\n")
	close(stop) // tell clients to stop
	wg.Wait()   // wait until clients finish
	successRatio := (float64(total.Load()-(timeout.Load()+readError.Load()+writeError.Load()+invalidData.Load())) / float64(total.Load())) * 100.0
	summary := fmt.Sprintf("1000 connections %d requests in 30s", total.Load())
	report := fmt.Sprintf("Requests/sec: %d\n", total.Load()/30)
	report += fmt.Sprintf("Errors: timeout %d, read %d, write %d, invalid data received %d, connection %d\n", timeout.Load(), readError.Load(), writeError.Load(), invalidData.Load(), connectError.Load())
	report += fmt.Sprintf("Successes ratio: %.2f%%\n", successRatio)
	AddReportEntry(summary, report)
	s.AssertGreaterEqual(successRatio, 90.0)
}

func VppConnectUdpStressTest(s *VppUdpProxySuite) {
	remoteServerConn := s.StartUdpEchoServer(s.ServerAddr(), s.Ports.Server)
	defer remoteServerConn.Close()

	vppProxy := s.Containers.VppProxy.VppInstance
	cmd := fmt.Sprintf("test proxy server fifo-size 512k server-uri http://%s/%d", s.VppProxyAddr(), s.Ports.Proxy)
	s.Log(vppProxy.Vppctl(cmd))

	// no goVPP less noise
	vppProxy.Disconnect()

	vppConnectUdpStressLoad(s)
}

func VppConnectUdpStressMWTest(s *VppUdpProxySuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	remoteServerConn := s.StartUdpEchoServer(s.ServerAddr(), s.Ports.Server)
	defer remoteServerConn.Close()

	vppProxy := s.Containers.VppProxy.VppInstance
	cmd := fmt.Sprintf("test proxy server fifo-size 512k server-uri http://%s/%d", s.VppProxyAddr(), s.Ports.Proxy)
	s.Log(vppProxy.Vppctl(cmd))

	// no goVPP less noise
	vppProxy.Disconnect()

	vppConnectUdpStressLoad(s)
}

func vppConnectProxyClientCheckCleanup(s *MasqueSuite) {
	clientVpp := s.Containers.VppClient.VppInstance
	closed := false
	for nTries := 0; nTries < 35; nTries++ {
		o := clientVpp.Vppctl("show http connect proxy client sessions")
		if !strings.Contains(o, "session [") {
			closed = true
			break
		}
		time.Sleep(1 * time.Second)
	}
	s.AssertEqual(closed, true)
	h2Stats := clientVpp.Vppctl("show http stats")
	streamsOpened := 0
	streamsClosed := 0
	lines := strings.Split(h2Stats, "\n")
	for _, line := range lines {
		if strings.Contains(line, "application streams opened") {
			tmp := strings.Split(line, " ")
			streamsOpened, _ = strconv.Atoi(tmp[1])
		}
		if strings.Contains(line, "application streams closed") {
			tmp := strings.Split(line, " ")
			streamsClosed, _ = strconv.Atoi(tmp[1])
		}
	}
	// one stream for http/2 connection (parent stays open)
	s.AssertEqual(streamsOpened-streamsClosed, 1)
}

func vppConnectProxyServerCheckCleanup(s *MasqueSuite) {
	o := s.Containers.VppServer.VppInstance.Vppctl("show session verbose")
	s.AssertNotContains(o, "[H2]")
	h2Stats := s.Containers.VppServer.VppInstance.Vppctl("show http stats")
	streamsOpened := 0
	streamsClosed := 0
	lines := strings.Split(h2Stats, "\n")
	for _, line := range lines {
		if strings.Contains(line, "application streams opened") {
			tmp := strings.Split(line, " ")
			streamsOpened, _ = strconv.Atoi(tmp[1])
		}
		if strings.Contains(line, "application streams closed") {
			tmp := strings.Split(line, " ")
			streamsClosed, _ = strconv.Atoi(tmp[1])
		}
	}
	s.AssertEqual(streamsOpened-streamsClosed, 0)
}

func VppConnectProxyClientDownloadTcpMWTest(s *MasqueSuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	s.StartNginxServer()
	clientVpp := s.Containers.VppClient.VppInstance
	s.ProxyClientConnect("tcp", s.Ports.NginxSsl)
	cmd := fmt.Sprintf("http connect proxy client listener add listener tcp://0.0.0.0:%s", s.Ports.Nginx)
	s.Log(clientVpp.Vppctl(cmd))
	o := clientVpp.Vppctl("show http connect proxy client listeners")
	s.Log(o)
	s.AssertContains(o, "tcp://0.0.0.0:"+s.Ports.Nginx)
	s.AssertContains(o, "tcp://0.0.0.0:"+s.Ports.NginxSsl)

	uri := fmt.Sprintf("https://%s:%s/httpTestFile", s.NginxAddr(), s.Ports.NginxSsl)
	finished := make(chan error, 1)
	go func() {
		defer GinkgoRecover()
		s.StartCurl(finished, uri, s.NetNamespaces.Client, "200", 30, []string{"--http1.1"})
	}()
	s.Log(clientVpp.Vppctl("show http connect proxy client sessions"))
	s.AssertNil(<-finished)
	// test client initiated stream close
	vppConnectProxyClientCheckCleanup(s)
	vppConnectProxyServerCheckCleanup(s)
}

func VppConnectProxyClientDownloadUdpTest(s *MasqueSuite) {
	s.StartNginxServer()
	clientVpp := s.Containers.VppClient.VppInstance
	s.ProxyClientConnect("udp", s.Ports.NginxSsl)
	s.Log(clientVpp.Vppctl("show http connect proxy client listeners"))

	uri := fmt.Sprintf("https://%s:%s/httpTestFile", s.NginxAddr(), s.Ports.NginxSsl)
	finished := make(chan error, 1)
	go func() {
		defer GinkgoRecover()
		s.StartCurl(finished, uri, s.NetNamespaces.Client, "200", 30, []string{"--http3-only"})
	}()
	s.AssertNil(<-finished)
}

func VppConnectProxyClientUploadTcpMWTest(s *MasqueSuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	s.StartNginxServer()
	s.ProxyClientConnect("tcp", s.Ports.NginxSsl)

	fileName := "/tmp/test_file"
	defer os.Remove(fileName)
	fallocate := exec.Command("fallocate", "-l", "10MB", fileName)
	_, err := fallocate.CombinedOutput()
	s.AssertNil(err)

	uri := fmt.Sprintf("https://%s:%s/upload/testFile", s.NginxAddr(), s.Ports.NginxSsl)
	finished := make(chan error, 1)
	go func() {
		defer GinkgoRecover()
		s.StartCurl(finished, uri, s.NetNamespaces.Client, "201", 30, []string{"--http1.1", "-T", fileName})
	}()
	s.AssertNil(<-finished)
}

func VppConnectProxyClientUploadUdpTest(s *MasqueSuite) {
	s.StartNginxServer()
	s.ProxyClientConnect("udp", s.Ports.NginxSsl)

	fileName := "/tmp/test_file"
	defer os.Remove(fileName)
	fallocate := exec.Command("fallocate", "-l", "10MB", fileName)
	_, err := fallocate.CombinedOutput()
	s.AssertNil(err)

	uri := fmt.Sprintf("https://%s:%s/upload/testFile", s.NginxAddr(), s.Ports.NginxSsl)
	finished := make(chan error, 1)
	go func() {
		defer GinkgoRecover()
		s.StartCurl(finished, uri, s.NetNamespaces.Client, "201", 30, []string{"--http3-only", "-T", fileName})
	}()
	s.AssertNil(<-finished)
}

func VppConnectProxyIperfTcpTest(s *MasqueSuite) {
	s.Containers.IperfServer.Run()
	s.ProxyClientConnect("tcp", s.Ports.Nginx)
	clientVpp := s.Containers.VppClient.VppInstance

	stopServerCh := make(chan struct{})
	srvCh := make(chan error, 1)

	defer func() {
		stopServerCh <- struct{}{}
	}()

	go func() {
		defer GinkgoRecover()
		c := "iperf3 -s -B " + s.NginxAddr() + " -p " + s.Ports.Nginx
		s.StartServerApp(s.Containers.IperfServer, "iperf3", c, srvCh, stopServerCh)
	}()
	err := <-srvCh
	s.AssertNil(err, fmt.Sprint(err))
	s.Log("server running")

	finished := make(chan error, 1)
	go func() {
		defer GinkgoRecover()
		s.StartIperfClient(finished, s.Interfaces.Client.Peer.Ip4AddressString(), s.NginxAddr(), s.Ports.Nginx,
			s.NetNamespaces.Client, []string{"-P", "4"})
	}()
	s.Log(clientVpp.Vppctl("show http connect proxy client sessions"))
	s.AssertNil(<-finished)
}

func VppConnectProxyIperfUdpTest(s *MasqueSuite) {
	s.Containers.IperfServer.Run()
	// test listen all, we are running solo anyway
	s.ProxyClientConnect("udp", "0")
	clientVpp := s.Containers.VppClient.VppInstance
	cmd := fmt.Sprintf("http connect proxy client listener add listener tcp://0.0.0.0:0")
	s.Log(clientVpp.Vppctl(cmd))

	stopServerCh := make(chan struct{})
	srvCh := make(chan error, 1)

	defer func() {
		stopServerCh <- struct{}{}
	}()

	go func() {
		defer GinkgoRecover()
		c := "iperf3 -s -B " + s.NginxAddr() + " -p " + s.Ports.Nginx
		s.StartServerApp(s.Containers.IperfServer, "iperf3", c, srvCh, stopServerCh)
	}()
	err := <-srvCh
	s.AssertNil(err, fmt.Sprint(err))
	s.Log("server running")

	finished := make(chan error, 1)
	go func() {
		defer GinkgoRecover()
		s.StartIperfClient(finished, s.Interfaces.Client.Peer.Ip4AddressString(), s.NginxAddr(), s.Ports.Nginx,
			s.NetNamespaces.Client, []string{"-u", "-P", "4"})
	}()
	s.Log(clientVpp.Vppctl("show http connect proxy client sessions"))
	s.AssertNil(<-finished)
}

func VppConnectProxyIperfTcpMWTest(s *MasqueSuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	VppConnectProxyIperfTcpTest(s)
	// test server send rst_stream (iperf data flows)
	vppConnectProxyClientCheckCleanup(s)
	vppConnectProxyServerCheckCleanup(s)
}

func VppConnectProxyIperfUdpMWTest(s *MasqueSuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	VppConnectProxyIperfUdpTest(s)
	clientVpp := s.Containers.VppClient.VppInstance
	closed := false
	for nTries := 0; nTries < 60; nTries++ {
		o := clientVpp.Vppctl("show http connect proxy client sessions")
		if !strings.Contains(o, "] tcp ") {
			closed = true
			break
		}
		time.Sleep(1 * time.Second)
	}
	s.AssertEqual(closed, true)
}

func VppConnectProxyClientTargetUnreachableMWTest(s *MasqueSuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	s.StartNginxServer()
	s.ProxyClientConnect("tcp", s.Ports.Unused)

	uri := fmt.Sprintf("https://%s:%s/httpTestFile", s.NginxAddr(), s.Ports.Unused)
	finished := make(chan error, 1)
	go func() {
		defer GinkgoRecover()
		s.StartCurl(finished, uri, s.NetNamespaces.Client, "200", 30, []string{"--http1.1"})
	}()
	s.AssertNotNil(<-finished)

	vppConnectProxyClientCheckCleanup(s)
}

func VppConnectProxyClientServerClosedTcpMWTest(s *MasqueSuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	s.StartNginxServer()
	clientVpp := s.Containers.VppClient.VppInstance
	s.ProxyClientConnect("tcp", s.Ports.Nginx)

	uri := fmt.Sprintf("http://%s:%s/64B", s.NginxAddr(), s.Ports.Nginx)
	finished := make(chan error, 1)
	go func() {
		defer GinkgoRecover()
		// run http/1.0 so server start closing
		s.StartCurl(finished, uri, s.NetNamespaces.Client, "200", 30, []string{"--http1.0"})
	}()
	s.Log(clientVpp.Vppctl("show http connect proxy client sessions"))
	s.AssertNil(<-finished)
	// test server initiated stream close
	vppConnectProxyClientCheckCleanup(s)
	vppConnectProxyServerCheckCleanup(s)
}

func VppConnectProxyClientUdpIdleMWTest(s *MasqueSuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	s.StartNginxServer()
	s.ProxyClientConnect("udp", s.Ports.NginxSsl, "udp-idle-timeout 5")

	uri := fmt.Sprintf("https://%s:%s/64B", s.NginxAddr(), s.Ports.NginxSsl)
	finished := make(chan error, 1)
	go func() {
		defer GinkgoRecover()
		s.StartCurl(finished, uri, s.NetNamespaces.Client, "200", 30, []string{"--http3-only"})
	}()
	s.AssertNil(<-finished)

	vppConnectProxyClientCheckCleanup(s)
	vppConnectProxyServerCheckCleanup(s)
}

func VppConnectProxyMemLeakTest(s *MasqueSuite) {
	s.SkipUnlessLeakCheck()

	s.StartNginxServer()
	s.ProxyClientConnect("tcp", s.Ports.Nginx)

	clientVpp := s.Containers.VppClient.VppInstance
	serverVpp := s.Containers.VppServer.VppInstance
	/* no goVPP less noise */
	clientVpp.Disconnect()
	serverVpp.Disconnect()

	uri := fmt.Sprintf("http://%s:%s/64B", s.NginxAddr(), s.Ports.Nginx)

	/* warmup requests (FIB, pool allocations) */
	finished := make(chan error, 1)
	go func() {
		defer GinkgoRecover()
		// run http/1.0 so server start closing
		s.StartCurl(finished, uri, s.NetNamespaces.Client, "200", 30, []string{"--http1.1"})
	}()
	s.AssertNil(<-finished)

	/* let's give it some time to clean up sessions, so pool elements can be reused and we have less noise */
	vppConnectProxyClientCheckCleanup(s)
	vppConnectProxyServerCheckCleanup(s)

	clientVpp.EnableMemoryTrace()
	clientTraces1, err := clientVpp.GetMemoryTrace()
	s.AssertNil(err, fmt.Sprint(err))

	finished = make(chan error, 1)
	go func() {
		defer GinkgoRecover()
		// run http/1.0 so server start closing
		s.StartCurl(finished, uri, s.NetNamespaces.Client, "200", 30, []string{"--http1.1"})
	}()
	s.AssertNil(<-finished)

	/* let's give it some time to clean up sessions */
	vppConnectProxyClientCheckCleanup(s)
	vppConnectProxyServerCheckCleanup(s)

	clientTraces2, err := clientVpp.GetMemoryTrace()
	s.AssertNil(err, fmt.Sprint(err))
	clientVpp.MemLeakCheck(clientTraces1, clientTraces2)
}

func VppConnectProxyClientStressMWTest(s *MasqueSuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	s.StartNginxServer()
	s.ProxyClientConnect("tcp", s.Ports.Nginx)

	// try to open more tunnels than SETTINGS_MAX_CONCURRENT_STREAMS, (100 - 1 for parent), to test failed http connects
	uri := fmt.Sprintf("http://%s:%s/64B", s.NginxAddr(), s.Ports.Nginx)
	cmd := CommandInNetns([]string{"ab", "-q", "-l", "-n", "10000", "-c", "102", "-s", "5", "-r", uri}, s.NetNamespaces.Client)
	s.Log(cmd)
	res, _ := cmd.CombinedOutput()
	s.Log(string(res))

	vppConnectProxyClientCheckCleanup(s)
	vppConnectProxyServerCheckCleanup(s)
}
