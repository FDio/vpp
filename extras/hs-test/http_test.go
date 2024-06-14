package main

import (
	"bytes"
	"fmt"
	"github.com/onsi/gomega/gmeasure"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterVethTests(HttpCliTest, HttpCliConnectErrorTest)
	RegisterNoTopoTests(NginxHttp3Test, NginxAsServerTest,
		NginxPerfCpsTest, NginxPerfRpsTest, NginxPerfWrkTest, HeaderServerTest,
		HttpStaticMovedTest, HttpStaticNotFoundTest, HttpCliMethodNotAllowedTest,
		HttpCliBadRequestTest, HttpStaticBuildInUrlGetIfStatsTest, HttpStaticBuildInUrlPostIfStatsTest,
		HttpInvalidRequestLineTest, HttpMethodNotImplementedTest, HttpInvalidHeadersTest,
		HttpContentLengthTest, HttpStaticBuildInUrlGetIfListTest, HttpStaticBuildInUrlGetVersionTest,
		HttpStaticMacTimeTest, HttpStaticBuildInUrlGetVersionVerboseTest, HttpVersionNotSupportedTest,
		HttpInvalidContentLengthTest, HttpInvalidTargetSyntaxTest, HttpStaticPathTraversalTest, HttpUriDecodeTest,
		HttpHeadersTest)
	RegisterNoTopoSoloTests(HttpStaticPromTest, HttpTpsTest)
}

const wwwRootPath = "/tmp/www_root"

func httpDownloadBenchmark(s *HstSuite, experiment *gmeasure.Experiment, data interface{}) {
	url, isValid := data.(string)
	s.AssertEqual(true, isValid)
	client := NewHttpClient()
	req, err := http.NewRequest("GET", url, nil)
	s.AssertNil(err, fmt.Sprint(err))
	t := time.Now()
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.AssertEqual(200, resp.StatusCode)
	_, err = io.ReadAll(resp.Body)
	duration := time.Since(t)
	experiment.RecordValue("Download Speed", (float64(resp.ContentLength)/1024/1024)/duration.Seconds(), gmeasure.Units("MB/s"), gmeasure.Precision(2))
}

func HttpTpsTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
	url := "http://" + serverAddress + ":8080/test_file_10M"

	vpp.Vppctl("http tps uri tcp://0.0.0.0/8080")

	s.RunBenchmark("HTTP tps 10M", 10, 0, httpDownloadBenchmark, url)
}

func HttpCliTest(s *VethsSuite) {
	serverContainer := s.GetContainerByName("server-vpp")
	clientContainer := s.GetContainerByName("client-vpp")

	serverVeth := s.GetInterfaceByName(ServerInterfaceName)

	serverContainer.VppInstance.Vppctl("http cli server")

	uri := "http://" + serverVeth.Ip4AddressString() + "/80"

	o := clientContainer.VppInstance.Vppctl("http cli client" +
		" uri " + uri + " query /show/vlib/graph")

	s.Log(o)
	s.AssertContains(o, "<html>", "<html> not found in the result!")
}

func HttpCliConnectErrorTest(s *VethsSuite) {
	clientContainer := s.GetContainerByName("client-vpp")

	serverVeth := s.GetInterfaceByName(ServerInterfaceName)

	uri := "http://" + serverVeth.Ip4AddressString() + "/80"

	o := clientContainer.VppInstance.Vppctl("http cli client" +
		" uri " + uri + " query /show/vlib/graph")

	s.Log(o)
	s.AssertContains(o, "failed to connect")
}

func NginxHttp3Test(s *NoTopoSuite) {
	s.SkipUnlessExtendedTestsBuilt()

	query := "index.html"
	nginxCont := s.GetContainerByName("nginx-http3")
	s.AssertNil(nginxCont.Run())

	vpp := s.GetContainerByName("vpp").VppInstance
	vpp.WaitForApp("nginx-", 5)
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()

	defer func() { os.Remove(query) }()
	curlCont := s.GetContainerByName("curl")
	args := fmt.Sprintf("curl --noproxy '*' --local-port 55444 --http3-only -k https://%s:8443/%s", serverAddress, query)
	curlCont.ExtraRunningArgs = args
	o, err := curlCont.CombinedOutput()
	s.Log(o)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(o, "<http>", "<http> not found in the result!")
}

func HttpStaticPromTest(s *NoTopoSuite) {
	finished := make(chan error, 1)
	query := "stats.prom"
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers"))
	s.Log(vpp.Vppctl("prom enable"))
	time.Sleep(time.Second * 5)
	go func() {
		defer GinkgoRecover()
		s.StartWget(finished, serverAddress, "80", query, "")
	}()
	err := <-finished
	s.AssertNil(err)
}

func HttpStaticPathTraversalTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	vpp.Container.Exec("mkdir -p " + wwwRootPath)
	vpp.Container.Exec("mkdir -p " + "/tmp/secret_folder")
	vpp.Container.CreateFile("/tmp/secret_folder/secret_file.txt", "secret")
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
	s.Log(vpp.Vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress + "/80 debug"))

	client := NewHttpClient()
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/../secret_folder/secret_file.txt", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.AssertEqual(404, resp.StatusCode)
}

func HttpStaticMovedTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	vpp.Container.Exec("mkdir -p " + wwwRootPath + "/tmp.aaa")
	vpp.Container.CreateFile(wwwRootPath+"/tmp.aaa/index.html", "<http><body><p>Hello</p></body></http>")
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
	s.Log(vpp.Vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress + "/80 debug"))

	client := NewHttpClient()
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/tmp.aaa", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.AssertEqual(301, resp.StatusCode)
	s.AssertNotEqual("", resp.Header.Get("Location"))
}

func HttpStaticNotFoundTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	vpp.Container.Exec("mkdir -p " + wwwRootPath)
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
	s.Log(vpp.Vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress + "/80 debug"))

	client := NewHttpClient()
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/notfound.html", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.AssertEqual(404, resp.StatusCode)
}

func HttpCliMethodNotAllowedTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
	vpp.Vppctl("http cli server")

	client := NewHttpClient()
	req, err := http.NewRequest("POST", "http://"+serverAddress+":80/test", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.AssertEqual(405, resp.StatusCode)
	// TODO: need to be fixed in http code
	//s.AssertNotEqual("", resp.Header.Get("Allow"))
}

func HttpCliBadRequestTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
	vpp.Vppctl("http cli server")

	client := NewHttpClient()
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.AssertEqual(400, resp.StatusCode)
}

func HttpStaticBuildInUrlGetVersionTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers debug"))

	client := NewHttpClient()
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/version.json", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.AssertEqual(200, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(string(data), "vpp_details")
	s.AssertContains(string(data), "version")
	s.AssertContains(string(data), "build_date")
	s.AssertNotContains(string(data), "build_by")
	s.AssertNotContains(string(data), "build_host")
	s.AssertNotContains(string(data), "build_dir")
}

func HttpStaticBuildInUrlGetVersionVerboseTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers debug"))

	client := NewHttpClient()
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/version.json?verbose=true", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.AssertEqual(200, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(string(data), "vpp_details")
	s.AssertContains(string(data), "version")
	s.AssertContains(string(data), "build_date")
	s.AssertContains(string(data), "build_by")
	s.AssertContains(string(data), "build_host")
	s.AssertContains(string(data), "build_dir")
}

func HttpStaticBuildInUrlGetIfListTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers debug"))

	client := NewHttpClient()
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/interface_list.json", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.AssertEqual(200, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(string(data), "interface_list")
	s.AssertContains(string(data), s.GetInterfaceByName(TapInterfaceName).Peer.Name())
}

func HttpStaticBuildInUrlGetIfStatsTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers debug"))

	client := NewHttpClient()
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/interface_stats.json", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.AssertEqual(200, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(string(data), "interface_stats")
	s.AssertContains(string(data), "local0")
	s.AssertContains(string(data), s.GetInterfaceByName(TapInterfaceName).Peer.Name())
}

func validatePostInterfaceStats(s *NoTopoSuite, data string) {
	s.AssertContains(data, "interface_stats")
	s.AssertContains(data, s.GetInterfaceByName(TapInterfaceName).Peer.Name())
	s.AssertNotContains(data, "error")
	s.AssertNotContains(data, "local0")
}

func HttpStaticBuildInUrlPostIfStatsTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers debug"))
	body := []byte(s.GetInterfaceByName(TapInterfaceName).Peer.Name())

	client := NewHttpClient()
	req, err := http.NewRequest("POST",
		"http://"+serverAddress+":80/interface_stats.json", bytes.NewBuffer(body))
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.AssertEqual(200, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
	validatePostInterfaceStats(s, string(data))
}

func HttpStaticMacTimeTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers debug"))
	s.Log(vpp.Vppctl("mactime enable-disable " + s.GetInterfaceByName(TapInterfaceName).Peer.Name()))

	client := NewHttpClient()
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/mactime.json", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.AssertEqual(200, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(string(data), "mactime")
	s.AssertContains(string(data), s.GetInterfaceByName(TapInterfaceName).Ip4AddressString())
	s.AssertContains(string(data), s.GetInterfaceByName(TapInterfaceName).HwAddress.String())
}

func HttpInvalidRequestLineTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
	vpp.Vppctl("http cli server")

	resp, err := TcpSendReceive(serverAddress+":80", "GET / HTTP/1.1")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "invalid framing not allowed")

	resp, err = TcpSendReceive(serverAddress+":80", "GET / HTTP/1.1\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "invalid framing not allowed")

	resp, err = TcpSendReceive(serverAddress+":80", "GET /\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "HTTP-version must be present")

	resp, err = TcpSendReceive(serverAddress+":80", "GET HTTP/1.1\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "request-target must be present")

	resp, err = TcpSendReceive(serverAddress+":80", "GET  HTTP/1.1\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "request-target must be present")

	resp, err = TcpSendReceive(serverAddress+":80", "GET / HTTP/x\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "'HTTP/x' invalid http version not allowed")

	resp, err = TcpSendReceive(serverAddress+":80", "GET / HTTP1.1\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "'HTTP1.1' invalid http version not allowed")
}

func HttpInvalidTargetSyntaxTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers debug"))

	resp, err := TcpSendReceive(serverAddress+":80", "GET /interface|stats.json HTTP/1.1\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "'|' not allowed in target path")

	resp, err = TcpSendReceive(serverAddress+":80", "GET /interface#stats.json HTTP/1.1\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "'#' not allowed in target path")

	resp, err = TcpSendReceive(serverAddress+":80", "GET /interface%stats.json HTTP/1.1\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request",
		"after '%' there must be two hex-digit characters in target path")

	resp, err = TcpSendReceive(serverAddress+":80", "GET /interface%1stats.json HTTP/1.1\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request",
		"after '%' there must be two hex-digit characters in target path")

	resp, err = TcpSendReceive(serverAddress+":80", "GET /interface%Bstats.json HTTP/1.1\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request",
		"after '%' there must be two hex-digit characters in target path")

	resp, err = TcpSendReceive(serverAddress+":80", "GET /interface%stats.json%B HTTP/1.1\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request",
		"after '%' there must be two hex-digit characters in target path")

	resp, err = TcpSendReceive(serverAddress+":80", "GET /version.json?verbose>true HTTP/1.1\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "'>' not allowed in target query")

	resp, err = TcpSendReceive(serverAddress+":80", "GET /version.json?verbose%true HTTP/1.1\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request",
		"after '%' there must be two hex-digit characters in target query")

	resp, err = TcpSendReceive(serverAddress+":80", "GET /version.json?verbose=%1 HTTP/1.1\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request",
		"after '%' there must be two hex-digit characters in target query")
}

func HttpInvalidContentLengthTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
	vpp.Vppctl("http cli server")

	resp, err := TcpSendReceive(serverAddress+":80", "GET /show/version HTTP/1.1\r\nContent-Length:\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "Content-Length value must be present")

	resp, err = TcpSendReceive(serverAddress+":80", "GET /show/version HTTP/1.1\r\nContent-Length: \r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "Content-Length value must be present")

	resp, err = TcpSendReceive(serverAddress+":80", "GET /show/version HTTP/1.1\r\nContent-Length: a\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request",
		"Content-Length value other than digit not allowed")
}

func HttpContentLengthTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers debug"))
	ifName := s.GetInterfaceByName(TapInterfaceName).Peer.Name()

	resp, err := TcpSendReceive(serverAddress+":80",
		"POST /interface_stats.json HTTP/1.1\r\nContent-Length:4\r\n\r\n"+ifName)
	s.AssertNil(err, fmt.Sprint(err))
	validatePostInterfaceStats(s, resp)

	resp, err = TcpSendReceive(serverAddress+":80",
		"POST /interface_stats.json HTTP/1.1\r\n Content-Length:  4 \r\n\r\n"+ifName)
	s.AssertNil(err, fmt.Sprint(err))
	validatePostInterfaceStats(s, resp)

	resp, err = TcpSendReceive(serverAddress+":80",
		"POST /interface_stats.json HTTP/1.1\r\n\tContent-Length:\t\t4\r\n\r\n"+ifName)
	s.AssertNil(err, fmt.Sprint(err))
	validatePostInterfaceStats(s, resp)
}

func HttpMethodNotImplementedTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
	vpp.Vppctl("http cli server")

	client := NewHttpClient()
	req, err := http.NewRequest("OPTIONS", "http://"+serverAddress+":80/show/version", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.AssertEqual(501, resp.StatusCode)
}

func HttpVersionNotSupportedTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
	vpp.Vppctl("http cli server")

	resp, err := TcpSendReceive(serverAddress+":80", "GET / HTTP/2\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 505 HTTP Version Not Supported")
}

func HttpUriDecodeTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
	vpp.Vppctl("http cli server")

	client := NewHttpClient()
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/sh%6fw%20versio%6E%20verbose", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.AssertEqual(200, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
	s.Log(string(data))
	s.AssertNotContains(string(data), "unknown input")
	s.AssertContains(string(data), "Compiler")
}

func HttpHeadersTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
	vpp.Vppctl("http cli server")

	resp, err := TcpSendReceive(
		serverAddress+":80",
		"GET /show/version HTTP/1.1\r\nHost:"+serverAddress+":80\r\nUser-Agent:test\r\nAccept:text/xml\r\nAccept:\ttext/plain\t \r\nAccept:text/html\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 200 OK")
	s.AssertContains(resp, "Content-Type: text / plain")
	s.AssertNotContains(resp, "<html>", "html content received instead of plain text")
}

func HttpInvalidHeadersTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
	vpp.Vppctl("http cli server")

	resp, err := TcpSendReceive(serverAddress+":80", "GET /show/version HTTP/1.1\r\nUser-Agent: test\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "Header section must end with CRLF CRLF")

	resp, err = TcpSendReceive(serverAddress+":80", "GET /show/version HTTP/1.1\r\nHost:"+serverAddress+":80\r\nUser@Agent:test\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "'@' not allowed in field name")

	resp, err = TcpSendReceive(serverAddress+":80", "GET /show/version HTTP/1.1\r\nHost:"+serverAddress+":80\r\nUser-Agent\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "incomplete field line not allowed")

	resp, err = TcpSendReceive(serverAddress+":80", "GET /show/version HTTP/1.1\r\nHost:"+serverAddress+":80\r\n: test\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "empty field name not allowed")

	resp, err = TcpSendReceive(serverAddress+":80", "GET /show/version HTTP/1.1\r\nHost:"+serverAddress+":80\rUser-Agent:test\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "invalid field line end not allowed")

	resp, err = TcpSendReceive(serverAddress+":80", "GET /show/version HTTP/1.1\r\nHost:"+serverAddress+":80\nUser-Agent:test\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "invalid field line end not allowed")

	resp, err = TcpSendReceive(serverAddress+":80", "GET /show/version HTTP/1.1\r\nHost:"+serverAddress+":80\r\nUser-Agent:\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "empty field value not allowed")

	resp, err = TcpSendReceive(serverAddress+":80", "GET /show/version HTTP/1.1\r\nHost:"+serverAddress+":80\r\nUser-Agent:    \r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "empty field value not allowed")
}

func HeaderServerTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
	vpp.Vppctl("http cli server")

	client := NewHttpClient()
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/show/version", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.AssertEqual("http_cli_server", resp.Header.Get("Server"))
}

func NginxAsServerTest(s *NoTopoSuite) {
	query := "return_ok"
	finished := make(chan error, 1)

	nginxCont := s.GetContainerByName("nginx")
	s.AssertNil(nginxCont.Run())

	vpp := s.GetContainerByName("vpp").VppInstance
	vpp.WaitForApp("nginx-", 5)

	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()

	defer func() { os.Remove(query) }()
	go func() {
		defer GinkgoRecover()
		s.StartWget(finished, serverAddress, "80", query, "")
	}()
	s.AssertNil(<-finished)
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

	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()

	vpp := s.GetContainerByName("vpp").VppInstance

	nginxCont := s.GetContainerByName(SingleTopoContainerNginx)
	s.AssertNil(nginxCont.Run())
	vpp.WaitForApp("nginx-", 5)

	if ab_or_wrk == "ab" {
		abCont := s.GetContainerByName("ab")
		args := fmt.Sprintf("-n %d -c %d", nRequests, nClients)
		if mode == "rps" {
			args += " -k"
		} else if mode != "cps" {
			return fmt.Errorf("invalid mode %s; expected cps/rps", mode)
		}
		// don't exit on socket receive errors
		args += " -r"
		args += " http://" + serverAddress + ":80/64B.json"
		abCont.ExtraRunningArgs = args
		o, err := abCont.CombinedOutput()
		rps := parseString(o, "Requests per second:")
		s.Log(rps)
		s.Log(err)
		s.AssertNil(err, "err: '%s', output: '%s'", err, o)
	} else {
		wrkCont := s.GetContainerByName("wrk")
		args := fmt.Sprintf("-c %d -t 2 -d 30 http://%s:80/64B.json", nClients,
			serverAddress)
		wrkCont.ExtraRunningArgs = args
		o, err := wrkCont.CombinedOutput()
		rps := parseString(o, "requests")
		s.Log(rps)
		s.Log(err)
		s.AssertNil(err, "err: '%s', output: '%s'", err, o)
	}
	return nil
}

// unstable with multiple workers
func NginxPerfCpsTest(s *NoTopoSuite) {
	s.SkipIfMultiWorker()
	s.AssertNil(runNginxPerf(s, "cps", "ab"))
}

func NginxPerfRpsTest(s *NoTopoSuite) {
	s.AssertNil(runNginxPerf(s, "rps", "ab"))
}

func NginxPerfWrkTest(s *NoTopoSuite) {
	s.AssertNil(runNginxPerf(s, "", "wrk"))
}
