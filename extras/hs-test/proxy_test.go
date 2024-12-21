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
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterVppProxyTests(VppProxyHttpGetTcpTest, VppProxyHttpGetTlsTest, VppProxyHttpPutTcpTest, VppProxyHttpPutTlsTest,
		VppConnectProxyGetTest, VppConnectProxyPutTest)
	RegisterVppProxySoloTests(VppProxyHttpGetTcpMTTest, VppProxyHttpPutTcpMTTest, VppProxyTcpIperfMTTest,
		VppProxyUdpIperfMTTest, VppConnectProxyTortureTest, VppConnectProxyTortureMTTest)
	RegisterVppUdpProxyTests(VppProxyUdpTest)
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

func vppConnectProxyTorture(s *VppProxySuite, proxyPort string) {
	var (
		connectError, timeout, readError, writeError, invalidData, total atomic.Uint32
		wg                                                               sync.WaitGroup
	)
	stop := make(chan struct{})
	targetUri := fmt.Sprintf("%s:%d", s.ServerAddr(), s.ServerPort())
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
	s.AssertGreaterThan(successRatio, 90.0)
}

func VppConnectProxyTortureTest(s *VppProxySuite) {
	var proxyPort uint16 = 8080
	remoteServerConn := s.StartEchoServer()
	defer remoteServerConn.Close()

	configureVppProxy(s, "http", proxyPort)

	// no goVPP less noise
	s.Containers.VppProxy.VppInstance.Disconnect()

	vppConnectProxyTorture(s, strconv.Itoa(int(proxyPort)))
}

func VppConnectProxyTortureMTTest(s *VppProxySuite) {
	var proxyPort uint16 = 8080
	remoteServerConn := s.StartEchoServer()
	defer remoteServerConn.Close()

	vppProxy := s.Containers.VppProxy.VppInstance
	// tap interfaces are created on test setup with 1 rx-queue,
	// need to recreate them with 2 + consistent-qp
	s.AssertNil(vppProxy.DeleteTap(s.Interfaces.Server))
	s.AssertNil(vppProxy.CreateTap(s.Interfaces.Server, 2, uint32(s.Interfaces.Server.Peer.Index), Consistent_qp))
	s.AssertNil(vppProxy.DeleteTap(s.Interfaces.Client))
	s.AssertNil(vppProxy.CreateTap(s.Interfaces.Client, 2, uint32(s.Interfaces.Client.Peer.Index), Consistent_qp))

	configureVppProxy(s, "http", proxyPort)

	// no goVPP less noise
	vppProxy.Disconnect()

	vppConnectProxyTorture(s, strconv.Itoa(int(proxyPort)))
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
