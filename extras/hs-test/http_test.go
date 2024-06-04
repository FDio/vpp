package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
)

func init() {
	registerNsTests(HttpTpsTest)
	registerVethTests(HttpCliTest, HttpCliConnectErrorTest)
	registerNoTopoTests(NginxHttp3Test, NginxAsServerTest,
		NginxPerfCpsTest, NginxPerfRpsTest, NginxPerfWrkTest, HeaderServerTest,
		HttpStaticMovedTest, HttpStaticNotFoundTest, HttpCliMethodNotAllowedTest,
		HttpCliBadRequestTest, HttpStaticBuildInUrlGetIfStatsTest, HttpStaticBuildInUrlPostIfStatsTest,
		HttpInvalidRequestLineTest, HttpMethodNotImplementedTest, HttpInvalidHeadersTest,
		HttpContentLengthTest, HttpStaticBuildInUrlGetIfListTest, HttpStaticBuildInUrlGetVersionTest,
		HttpStaticMacTimeTest, HttpStaticBuildInUrlGetVersionVerboseTest, HttpVersionNotSupportedTest,
		HttpInvalidContentLengthTest, HttpInvalidTargetSyntaxTest, HttpStaticPathTraversalTest, HttpUriDecodeTest,
		HttpHeadersTest)
	registerNoTopoSoloTests(HttpStaticPromTest)
}

const wwwRootPath = "/tmp/www_root"

func HttpTpsTest(s *NsSuite) {
	iface := s.getInterfaceByName(clientInterface)
	client_ip := iface.ip4AddressString()
	port := "8080"
	finished := make(chan error, 1)
	clientNetns := s.getNetNamespaceByName("cln")

	container := s.getContainerByName("vpp")

	// configure vpp in the container
	container.vppInstance.vppctl("http tps uri tcp://0.0.0.0/8080 debug")

	go func() {
		defer GinkgoRecover()
		s.startWget(finished, client_ip, port, "test_file_10M", clientNetns)
	}()
	// wait for client
	err := <-finished
	s.assertNil(err, fmt.Sprint(err))
}

func HttpCliTest(s *VethsSuite) {
	serverContainer := s.getContainerByName("server-vpp")
	clientContainer := s.getContainerByName("client-vpp")

	serverVeth := s.getInterfaceByName(serverInterfaceName)

	serverContainer.vppInstance.vppctl("http cli server")

	uri := "http://" + serverVeth.ip4AddressString() + "/80"

	o := clientContainer.vppInstance.vppctl("http cli client" +
		" uri " + uri + " query /show/vlib/graph")

	s.log(o)
	s.assertContains(o, "<html>", "<html> not found in the result!")
}

func HttpCliConnectErrorTest(s *VethsSuite) {
	clientContainer := s.getContainerByName("client-vpp")

	serverVeth := s.getInterfaceByName(serverInterfaceName)

	uri := "http://" + serverVeth.ip4AddressString() + "/80"

	o := clientContainer.vppInstance.vppctl("http cli client" +
		" uri " + uri + " query /show/vlib/graph")

	s.log(o)
	s.assertContains(o, "failed to connect")
}

func NginxHttp3Test(s *NoTopoSuite) {
	s.SkipUnlessExtendedTestsBuilt()

	query := "index.html"
	nginxCont := s.getContainerByName("nginx-http3")
	s.assertNil(nginxCont.run())

	vpp := s.getContainerByName("vpp").vppInstance
	vpp.waitForApp("nginx-", 5)
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()

	defer func() { os.Remove(query) }()
	curlCont := s.getContainerByName("curl")
	args := fmt.Sprintf("curl --noproxy '*' --local-port 55444 --http3-only -k https://%s:8443/%s", serverAddress, query)
	curlCont.extraRunningArgs = args
	o, err := curlCont.combinedOutput()
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(o, "<http>", "<http> not found in the result!")
}

func HttpStaticPromTest(s *NoTopoSuite) {
	finished := make(chan error, 1)
	query := "stats.prom"
	vpp := s.getContainerByName("vpp").vppInstance
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()
	s.log(vpp.vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers"))
	s.log(vpp.vppctl("prom enable"))
	time.Sleep(time.Second * 5)
	go func() {
		defer GinkgoRecover()
		s.startWget(finished, serverAddress, "80", query, "")
	}()
	err := <-finished
	s.assertNil(err)
}

func HttpStaticPathTraversalTest(s *NoTopoSuite) {
	vpp := s.getContainerByName("vpp").vppInstance
	vpp.container.exec("mkdir -p " + wwwRootPath)
	vpp.container.exec("mkdir -p " + "/tmp/secret_folder")
	vpp.container.createFile("/tmp/secret_folder/secret_file.txt", "secret")
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()
	s.log(vpp.vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress + "/80 debug"))

	client := newHttpClient()
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/../secret_folder/secret_file.txt", nil)
	s.assertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.assertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.assertEqual(404, resp.StatusCode)
}

func HttpStaticMovedTest(s *NoTopoSuite) {
	vpp := s.getContainerByName("vpp").vppInstance
	vpp.container.exec("mkdir -p " + wwwRootPath + "/tmp.aaa")
	vpp.container.createFile(wwwRootPath+"/tmp.aaa/index.html", "<http><body><p>Hello</p></body></http>")
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()
	s.log(vpp.vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress + "/80 debug"))

	client := newHttpClient()
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/tmp.aaa", nil)
	s.assertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.assertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.assertEqual(301, resp.StatusCode)
	s.assertNotEqual("", resp.Header.Get("Location"))
}

func HttpStaticNotFoundTest(s *NoTopoSuite) {
	vpp := s.getContainerByName("vpp").vppInstance
	vpp.container.exec("mkdir -p " + wwwRootPath)
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()
	s.log(vpp.vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress + "/80 debug"))

	client := newHttpClient()
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/notfound.html", nil)
	s.assertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.assertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.assertEqual(404, resp.StatusCode)
}

func HttpCliMethodNotAllowedTest(s *NoTopoSuite) {
	vpp := s.getContainerByName("vpp").vppInstance
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()
	vpp.vppctl("http cli server")

	client := newHttpClient()
	req, err := http.NewRequest("POST", "http://"+serverAddress+":80/test", nil)
	s.assertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.assertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.assertEqual(405, resp.StatusCode)
	// TODO: need to be fixed in http code
	//s.assertNotEqual("", resp.Header.Get("Allow"))
}

func HttpCliBadRequestTest(s *NoTopoSuite) {
	vpp := s.getContainerByName("vpp").vppInstance
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()
	vpp.vppctl("http cli server")

	client := newHttpClient()
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80", nil)
	s.assertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.assertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.assertEqual(400, resp.StatusCode)
}

func HttpStaticBuildInUrlGetVersionTest(s *NoTopoSuite) {
	vpp := s.getContainerByName("vpp").vppInstance
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()
	s.log(vpp.vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers debug"))

	client := newHttpClient()
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/version.json", nil)
	s.assertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.assertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.assertEqual(200, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(string(data), "vpp_details")
	s.assertContains(string(data), "version")
	s.assertContains(string(data), "build_date")
	s.assertNotContains(string(data), "build_by")
	s.assertNotContains(string(data), "build_host")
	s.assertNotContains(string(data), "build_dir")
}

func HttpStaticBuildInUrlGetVersionVerboseTest(s *NoTopoSuite) {
	vpp := s.getContainerByName("vpp").vppInstance
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()
	s.log(vpp.vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers debug"))

	client := newHttpClient()
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/version.json?verbose=true", nil)
	s.assertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.assertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.assertEqual(200, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(string(data), "vpp_details")
	s.assertContains(string(data), "version")
	s.assertContains(string(data), "build_date")
	s.assertContains(string(data), "build_by")
	s.assertContains(string(data), "build_host")
	s.assertContains(string(data), "build_dir")
}

func HttpStaticBuildInUrlGetIfListTest(s *NoTopoSuite) {
	vpp := s.getContainerByName("vpp").vppInstance
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()
	s.log(vpp.vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers debug"))

	client := newHttpClient()
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/interface_list.json", nil)
	s.assertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.assertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.assertEqual(200, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(string(data), "interface_list")
	s.assertContains(string(data), s.getInterfaceByName(tapInterfaceName).peer.Name())
}

func HttpStaticBuildInUrlGetIfStatsTest(s *NoTopoSuite) {
	vpp := s.getContainerByName("vpp").vppInstance
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()
	s.log(vpp.vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers debug"))

	client := newHttpClient()
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/interface_stats.json", nil)
	s.assertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.assertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.assertEqual(200, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(string(data), "interface_stats")
	s.assertContains(string(data), "local0")
	s.assertContains(string(data), s.getInterfaceByName(tapInterfaceName).peer.Name())
}

func validatePostInterfaceStats(s *NoTopoSuite, data string) {
	s.assertContains(data, "interface_stats")
	s.assertContains(data, s.getInterfaceByName(tapInterfaceName).peer.Name())
	s.assertNotContains(data, "error")
	s.assertNotContains(data, "local0")
}

func HttpStaticBuildInUrlPostIfStatsTest(s *NoTopoSuite) {
	vpp := s.getContainerByName("vpp").vppInstance
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()
	s.log(vpp.vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers debug"))
	body := []byte(s.getInterfaceByName(tapInterfaceName).peer.Name())

	client := newHttpClient()
	req, err := http.NewRequest("POST",
		"http://"+serverAddress+":80/interface_stats.json", bytes.NewBuffer(body))
	s.assertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.assertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.assertEqual(200, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	s.assertNil(err, fmt.Sprint(err))
	validatePostInterfaceStats(s, string(data))
}

func HttpStaticMacTimeTest(s *NoTopoSuite) {
	vpp := s.getContainerByName("vpp").vppInstance
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()
	s.log(vpp.vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers debug"))
	s.log(vpp.vppctl("mactime enable-disable " + s.getInterfaceByName(tapInterfaceName).peer.Name()))

	client := newHttpClient()
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/mactime.json", nil)
	s.assertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.assertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.assertEqual(200, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(string(data), "mactime")
	s.assertContains(string(data), s.getInterfaceByName(tapInterfaceName).ip4AddressString())
	s.assertContains(string(data), s.getInterfaceByName(tapInterfaceName).hwAddress.String())
}

func HttpInvalidRequestLineTest(s *NoTopoSuite) {
	vpp := s.getContainerByName("vpp").vppInstance
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()
	vpp.vppctl("http cli server")

	resp, err := tcpSendReceive(serverAddress+":80", "GET / HTTP/1.1")
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(resp, "HTTP/1.1 400 Bad Request", "invalid framing not allowed")

	resp, err = tcpSendReceive(serverAddress+":80", "GET / HTTP/1.1\r\n")
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(resp, "HTTP/1.1 400 Bad Request", "invalid framing not allowed")

	resp, err = tcpSendReceive(serverAddress+":80", "GET /\r\n\r\n")
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(resp, "HTTP/1.1 400 Bad Request", "HTTP-version must be present")

	resp, err = tcpSendReceive(serverAddress+":80", "GET HTTP/1.1\r\n\r\n")
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(resp, "HTTP/1.1 400 Bad Request", "request-target must be present")

	resp, err = tcpSendReceive(serverAddress+":80", "GET  HTTP/1.1\r\n\r\n")
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(resp, "HTTP/1.1 400 Bad Request", "request-target must be present")

	resp, err = tcpSendReceive(serverAddress+":80", "GET / HTTP/x\r\n\r\n")
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(resp, "HTTP/1.1 400 Bad Request", "'HTTP/x' invalid http version not allowed")

	resp, err = tcpSendReceive(serverAddress+":80", "GET / HTTP1.1\r\n\r\n")
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(resp, "HTTP/1.1 400 Bad Request", "'HTTP1.1' invalid http version not allowed")
}

func HttpInvalidTargetSyntaxTest(s *NoTopoSuite) {
	vpp := s.getContainerByName("vpp").vppInstance
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()
	s.log(vpp.vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers debug"))

	resp, err := tcpSendReceive(serverAddress+":80", "GET /interface|stats.json HTTP/1.1\r\n\r\n")
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(resp, "HTTP/1.1 400 Bad Request", "'|' not allowed in target path")

	resp, err = tcpSendReceive(serverAddress+":80", "GET /interface#stats.json HTTP/1.1\r\n\r\n")
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(resp, "HTTP/1.1 400 Bad Request", "'#' not allowed in target path")

	resp, err = tcpSendReceive(serverAddress+":80", "GET /interface%stats.json HTTP/1.1\r\n\r\n")
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(resp, "HTTP/1.1 400 Bad Request",
		"after '%' there must be two hex-digit characters in target path")

	resp, err = tcpSendReceive(serverAddress+":80", "GET /interface%1stats.json HTTP/1.1\r\n\r\n")
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(resp, "HTTP/1.1 400 Bad Request",
		"after '%' there must be two hex-digit characters in target path")

	resp, err = tcpSendReceive(serverAddress+":80", "GET /interface%Bstats.json HTTP/1.1\r\n\r\n")
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(resp, "HTTP/1.1 400 Bad Request",
		"after '%' there must be two hex-digit characters in target path")

	resp, err = tcpSendReceive(serverAddress+":80", "GET /interface%stats.json%B HTTP/1.1\r\n\r\n")
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(resp, "HTTP/1.1 400 Bad Request",
		"after '%' there must be two hex-digit characters in target path")

	resp, err = tcpSendReceive(serverAddress+":80", "GET /version.json?verbose>true HTTP/1.1\r\n\r\n")
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(resp, "HTTP/1.1 400 Bad Request", "'>' not allowed in target query")

	resp, err = tcpSendReceive(serverAddress+":80", "GET /version.json?verbose%true HTTP/1.1\r\n\r\n")
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(resp, "HTTP/1.1 400 Bad Request",
		"after '%' there must be two hex-digit characters in target query")

	resp, err = tcpSendReceive(serverAddress+":80", "GET /version.json?verbose=%1 HTTP/1.1\r\n\r\n")
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(resp, "HTTP/1.1 400 Bad Request",
		"after '%' there must be two hex-digit characters in target query")
}

func HttpInvalidContentLengthTest(s *NoTopoSuite) {
	vpp := s.getContainerByName("vpp").vppInstance
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()
	vpp.vppctl("http cli server")

	resp, err := tcpSendReceive(serverAddress+":80", "GET /show/version HTTP/1.1\r\nContent-Length:\r\n\r\n")
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(resp, "HTTP/1.1 400 Bad Request", "Content-Length value must be present")

	resp, err = tcpSendReceive(serverAddress+":80", "GET /show/version HTTP/1.1\r\nContent-Length: \r\n\r\n")
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(resp, "HTTP/1.1 400 Bad Request", "Content-Length value must be present")

	resp, err = tcpSendReceive(serverAddress+":80", "GET /show/version HTTP/1.1\r\nContent-Length: a\r\n\r\n")
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(resp, "HTTP/1.1 400 Bad Request",
		"Content-Length value other than digit not allowed")
}

func HttpContentLengthTest(s *NoTopoSuite) {
	vpp := s.getContainerByName("vpp").vppInstance
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()
	s.log(vpp.vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers debug"))
	ifName := s.getInterfaceByName(tapInterfaceName).peer.Name()

	resp, err := tcpSendReceive(serverAddress+":80",
		"POST /interface_stats.json HTTP/1.1\r\nContent-Length:4\r\n\r\n"+ifName)
	s.assertNil(err, fmt.Sprint(err))
	validatePostInterfaceStats(s, resp)

	resp, err = tcpSendReceive(serverAddress+":80",
		"POST /interface_stats.json HTTP/1.1\r\n Content-Length:  4 \r\n\r\n"+ifName)
	s.assertNil(err, fmt.Sprint(err))
	validatePostInterfaceStats(s, resp)

	resp, err = tcpSendReceive(serverAddress+":80",
		"POST /interface_stats.json HTTP/1.1\r\n\tContent-Length:\t\t4\r\n\r\n"+ifName)
	s.assertNil(err, fmt.Sprint(err))
	validatePostInterfaceStats(s, resp)
}

func HttpMethodNotImplementedTest(s *NoTopoSuite) {
	vpp := s.getContainerByName("vpp").vppInstance
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()
	vpp.vppctl("http cli server")

	client := newHttpClient()
	req, err := http.NewRequest("OPTIONS", "http://"+serverAddress+":80/show/version", nil)
	s.assertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.assertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.assertEqual(501, resp.StatusCode)
}

func HttpVersionNotSupportedTest(s *NoTopoSuite) {
	vpp := s.getContainerByName("vpp").vppInstance
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()
	vpp.vppctl("http cli server")

	resp, err := tcpSendReceive(serverAddress+":80", "GET / HTTP/2\r\n\r\n")
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(resp, "HTTP/1.1 505 HTTP Version Not Supported")
}

func HttpUriDecodeTest(s *NoTopoSuite) {
	vpp := s.getContainerByName("vpp").vppInstance
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()
	vpp.vppctl("http cli server")

	client := newHttpClient()
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/sh%6fw%20versio%6E%20verbose", nil)
	s.assertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.assertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.assertEqual(200, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	s.assertNil(err, fmt.Sprint(err))
	s.log(string(data))
	s.assertNotContains(string(data), "unknown input")
	s.assertContains(string(data), "Compiler")
}

func HttpHeadersTest(s *NoTopoSuite) {
	vpp := s.getContainerByName("vpp").vppInstance
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()
	vpp.vppctl("http cli server")

	resp, err := tcpSendReceive(
		serverAddress+":80",
		"GET /show/version HTTP/1.1\r\nHost:"+serverAddress+":80\r\nUser-Agent:test\r\nAccept:text/xml\r\nAccept:\ttext/plain\t \r\nAccept:text/html\r\n\r\n")
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(resp, "HTTP/1.1 200 OK")
	s.assertContains(resp, "Content-Type: text / plain")
	s.assertNotContains(resp, "<html>", "html content received instead of plain text")
}

func HttpInvalidHeadersTest(s *NoTopoSuite) {
	vpp := s.getContainerByName("vpp").vppInstance
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()
	vpp.vppctl("http cli server")

	resp, err := tcpSendReceive(serverAddress+":80", "GET /show/version HTTP/1.1\r\nUser-Agent: test\r\n")
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(resp, "HTTP/1.1 400 Bad Request", "Header section must end with CRLF CRLF")

	resp, err = tcpSendReceive(serverAddress+":80", "GET /show/version HTTP/1.1\r\nHost:"+serverAddress+":80\r\nUser@Agent:test\r\n\r\n")
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(resp, "HTTP/1.1 400 Bad Request", "'@' not allowed in field name")

	resp, err = tcpSendReceive(serverAddress+":80", "GET /show/version HTTP/1.1\r\nHost:"+serverAddress+":80\r\nUser-Agent\r\n\r\n")
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(resp, "HTTP/1.1 400 Bad Request", "incomplete field line not allowed")

	resp, err = tcpSendReceive(serverAddress+":80", "GET /show/version HTTP/1.1\r\nHost:"+serverAddress+":80\r\n: test\r\n\r\n")
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(resp, "HTTP/1.1 400 Bad Request", "empty field name not allowed")

	resp, err = tcpSendReceive(serverAddress+":80", "GET /show/version HTTP/1.1\r\nHost:"+serverAddress+":80\rUser-Agent:test\r\n\r\n")
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(resp, "HTTP/1.1 400 Bad Request", "invalid field line end not allowed")

	resp, err = tcpSendReceive(serverAddress+":80", "GET /show/version HTTP/1.1\r\nHost:"+serverAddress+":80\nUser-Agent:test\r\n\r\n")
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(resp, "HTTP/1.1 400 Bad Request", "invalid field line end not allowed")

	resp, err = tcpSendReceive(serverAddress+":80", "GET /show/version HTTP/1.1\r\nHost:"+serverAddress+":80\r\nUser-Agent:\r\n\r\n")
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(resp, "HTTP/1.1 400 Bad Request", "empty field value not allowed")

	resp, err = tcpSendReceive(serverAddress+":80", "GET /show/version HTTP/1.1\r\nHost:"+serverAddress+":80\r\nUser-Agent:    \r\n\r\n")
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(resp, "HTTP/1.1 400 Bad Request", "empty field value not allowed")
}

func HeaderServerTest(s *NoTopoSuite) {
	vpp := s.getContainerByName("vpp").vppInstance
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()
	vpp.vppctl("http cli server")

	client := newHttpClient()
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/show/version", nil)
	s.assertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.assertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.assertEqual("http_cli_server", resp.Header.Get("Server"))
}

func NginxAsServerTest(s *NoTopoSuite) {
	query := "return_ok"
	finished := make(chan error, 1)

	nginxCont := s.getContainerByName("nginx")
	s.assertNil(nginxCont.run())

	vpp := s.getContainerByName("vpp").vppInstance
	vpp.waitForApp("nginx-", 5)

	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()

	defer func() { os.Remove(query) }()
	go func() {
		defer GinkgoRecover()
		s.startWget(finished, serverAddress, "80", query, "")
	}()
	s.assertNil(<-finished)
}

func parseString(s, pattern string) string {
	temp := strings.Split(s, "\n")
	for _, item := range temp {
		if strings.Contains(item, pattern) {
			return item
		}
	}
	return ""
}

func runNginxPerf(s *NoTopoSuite, mode, ab_or_wrk string) error {
	nRequests := 1000000
	nClients := 1000

	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()

	vpp := s.getContainerByName("vpp").vppInstance

	nginxCont := s.getContainerByName(singleTopoContainerNginx)
	s.assertNil(nginxCont.run())
	vpp.waitForApp("nginx-", 5)

	if ab_or_wrk == "ab" {
		abCont := s.getContainerByName("ab")
		args := fmt.Sprintf("-n %d -c %d", nRequests, nClients)
		if mode == "rps" {
			args += " -k"
		} else if mode != "cps" {
			return fmt.Errorf("invalid mode %s; expected cps/rps", mode)
		}
		// don't exit on socket receive errors
		args += " -r"
		args += " http://" + serverAddress + ":80/64B.json"
		abCont.extraRunningArgs = args
		o, err := abCont.combinedOutput()
		rps := parseString(o, "Requests per second:")
		s.log(rps)
		s.log(err)
		s.assertNil(err, "err: '%s', output: '%s'", err, o)
	} else {
		wrkCont := s.getContainerByName("wrk")
		args := fmt.Sprintf("-c %d -t 2 -d 30 http://%s:80/64B.json", nClients,
			serverAddress)
		wrkCont.extraRunningArgs = args
		o, err := wrkCont.combinedOutput()
		rps := parseString(o, "requests")
		s.log(rps)
		s.log(err)
		s.assertNil(err, "err: '%s', output: '%s'", err, o)
	}
	return nil
}

// unstable with multiple workers
func NginxPerfCpsTest(s *NoTopoSuite) {
	s.SkipIfMultiWorker()
	s.assertNil(runNginxPerf(s, "cps", "ab"))
}

func NginxPerfRpsTest(s *NoTopoSuite) {
	s.assertNil(runNginxPerf(s, "rps", "ab"))
}

func NginxPerfWrkTest(s *NoTopoSuite) {
	s.assertNil(runNginxPerf(s, "", "wrk"))
}
