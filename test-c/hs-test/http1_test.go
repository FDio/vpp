package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/onsi/gomega/ghttp"
	"github.com/onsi/gomega/gmeasure"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterVethTests(HttpCliTest, HttpCliConnectErrorTest, HttpCliTlsTest)
	RegisterSoloVethTests(HttpClientGetMemLeakTest)
	RegisterHttp1Tests(HeaderServerTest, HttpPersistentConnectionTest, HttpPipeliningTest,
		HttpStaticMovedTest, HttpStaticNotFoundTest, HttpCliMethodNotAllowedTest, HttpAbsoluteFormUriTest,
		HttpCliBadRequestTest, HttpStaticBuildInUrlGetIfStatsTest, HttpStaticBuildInUrlPostIfStatsTest,
		HttpInvalidRequestLineTest, HttpMethodNotImplementedTest, HttpInvalidHeadersTest, HttpStaticPostTest,
		HttpContentLengthTest, HttpStaticBuildInUrlGetIfListTest, HttpStaticBuildInUrlGetVersionTest,
		HttpStaticMacTimeTest, HttpStaticBuildInUrlGetVersionVerboseTest, HttpVersionNotSupportedTest,
		HttpInvalidContentLengthTest, HttpInvalidTargetSyntaxTest, HttpStaticPathSanitizationTest, HttpUriDecodeTest,
		HttpHeadersTest, HttpStaticFileHandlerTest, HttpStaticFileHandlerDefaultMaxAgeTest, HttpClientTest,
		HttpClientErrRespTest, HttpClientPostFormTest, HttpClientGet128kbResponseTest, HttpClientGetResponseBodyTest,
		HttpClientGetTlsNoRespBodyTest, HttpClientPostFileTest, HttpClientPostFilePtrTest,
		HttpRequestLineTest, HttpClientGetTimeout, HttpStaticFileHandlerWrkTest, HttpStaticUrlHandlerWrkTest, HttpConnTimeoutTest,
		HttpClientGetRepeatTest, HttpClientPostRepeatTest, HttpIgnoreH2UpgradeTest, HttpInvalidAuthorityFormUriTest, HttpHeaderErrorConnectionDropTest,
		HttpClientInvalidHeaderNameTest, HttpStaticHttp1OnlyTest, HttpTimerSessionDisable, HttpClientBodySizeTest,
		HttpStaticRedirectTest, HttpClientNoPrintTest, HttpClientChunkedDownloadTest, HttpClientPostRejectedTest,
		HttpClientRedirect302Test, HttpClientRedirect308Test, HttpSendGetAndCloseTest, HttpClientRedirectLimitTest, HttpClientRedirectMemLeakTest)
	RegisterHttp1SoloTests(HttpStaticPromTest, HttpGetTpsTest, HttpGetTpsInterruptModeTest, PromConcurrentConnectionsTest,
		PromMemLeakTest, HttpClientPostMemLeakTest, HttpInvalidClientRequestMemLeakTest, HttpPostTpsTest, HttpPostTpsInterruptModeTest,
		PromConsecutiveConnectionsTest, HttpGetTpsTlsTest, HttpPostTpsTlsTest)
	RegisterHttp1MWTests(HttpClientGetRepeatMWTest, HttpClientPtrGetRepeatMWTest)
	RegisterNoTopo6SoloTests(HttpClientGetResponseBody6Test, HttpClientGetTlsResponseBody6Test)
}

const wwwRootPath = "/tmp/www_root"
const defaultHttpTimeout = time.Second * 10

func httpDownloadBenchmark(s *HstSuite, experiment *gmeasure.Experiment, data interface{}) {
	url, isValid := data.(string)
	s.AssertEqual(true, isValid)
	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", url, nil)
	s.AssertNil(err, fmt.Sprint(err))
	t := time.Now()
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.AssertHttpStatus(resp, 200)
	_, err = io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
	duration := time.Since(t)
	experiment.RecordValue("Download Speed", (float64(resp.ContentLength)/1024/1024)/duration.Seconds(), gmeasure.Units("MB/s"), gmeasure.Precision(2))
}

func HttpGetTpsInterruptModeTest(s *Http1Suite) {
	HttpGetTpsTest(s)
}

func HttpGetTpsTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	url := "http://" + serverAddress + "/test_file_10M"

	vpp.Vppctl("http tps uri tcp://%s", serverAddress)

	s.RunBenchmark("HTTP tps download 10M", 10, 0, httpDownloadBenchmark, url)
}

func HttpGetTpsTlsTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	url := "https://" + serverAddress + "/test_file_10M"

	vpp.Vppctl("http tps uri tls://%s", serverAddress)

	s.RunBenchmark("HTTP tps download 10M", 10, 0, httpDownloadBenchmark, url)
}

func httpUploadBenchmark(s *HstSuite, experiment *gmeasure.Experiment, data interface{}) {
	url, isValid := data.(string)
	s.AssertEqual(true, isValid)
	body := make([]byte, 10485760)
	_, err := rand.Read(body)
	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	s.AssertNil(err, fmt.Sprint(err))
	t := time.Now()
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.AssertHttpStatus(resp, 200)
	_, err = io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
	duration := time.Since(t)
	experiment.RecordValue("Upload Speed", (float64(req.ContentLength)/1024/1024)/duration.Seconds(), gmeasure.Units("MB/s"), gmeasure.Precision(2))
}

func HttpPostTpsInterruptModeTest(s *Http1Suite) {
	HttpPostTpsTest(s)
}

func HttpPostTpsTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	url := "http://" + serverAddress + "/test_file_10M"

	vpp.Vppctl("http tps uri tcp://%s", serverAddress)

	s.RunBenchmark("HTTP tps upload 10M", 10, 0, httpUploadBenchmark, url)
}

func HttpPostTpsTlsTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	url := "https://" + serverAddress + "/test_file_10M"

	vpp.Vppctl("http tps uri tls://%s", serverAddress)

	s.RunBenchmark("HTTP tps upload 10M", 10, 0, httpUploadBenchmark, url)
}

func HttpPersistentConnectionTest(s *Http1Suite) {
	// testing url handler app do not support multi-thread
	s.SkipIfMultiWorker()
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers"))
	s.Log(vpp.Vppctl("test-url-handler enable"))

	transport := http.DefaultTransport
	transport.(*http.Transport).Proxy = nil
	transport.(*http.Transport).DisableKeepAlives = false
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Second * 30,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}

	body := []byte("{\"sandwich\": {\"spam\": 2, \"eggs\": 1}}")
	req, err := http.NewRequest("POST", "http://"+serverAddress+"/test3", bytes.NewBuffer(body))
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	s.Log(DumpHttpResp(resp, true))
	s.AssertHttpStatus(resp, 200)
	s.AssertEqual(false, resp.Close)
	s.AssertHttpContentLength(resp, int64(0))
	o1 := vpp.Vppctl("show session verbose proto http state ready")
	s.Log(o1)
	s.AssertContains(o1, "established")

	req, err = http.NewRequest("GET", "http://"+serverAddress+"/test1", nil)
	s.AssertNil(err, fmt.Sprint(err))
	clientTrace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			s.AssertEqual(true, info.Reused, "connection not reused")
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), clientTrace))
	resp, err = client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	s.Log(DumpHttpResp(resp, true))
	s.AssertHttpStatus(resp, 200)
	s.AssertEqual(false, resp.Close)
	s.AssertHttpBody(resp, "hello")
	o2 := vpp.Vppctl("show session verbose proto http state ready")
	s.Log(o2)
	s.AssertContains(o2, "established")
	s.AssertEqual(o1, o2)

	req, err = http.NewRequest("GET", "http://"+serverAddress+"/test2", nil)
	s.AssertNil(err, fmt.Sprint(err))
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), clientTrace))
	resp, err = client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	s.Log(DumpHttpResp(resp, true))
	s.AssertHttpStatus(resp, 200)
	s.AssertEqual(false, resp.Close)
	s.AssertHttpBody(resp, "some data")
	o2 = vpp.Vppctl("show session verbose proto http state ready")
	s.Log(o2)
	s.AssertContains(o2, "established")
	s.AssertEqual(o1, o2)
}

func HttpPipeliningTest(s *Http1Suite) {
	// testing url handler app do not support multi-thread
	s.SkipIfMultiWorker()
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers debug"))
	s.Log(vpp.Vppctl("test-url-handler enable"))

	req1 := "GET /test_delayed HTTP/1.1\r\nHost:" + serverAddress + "\r\nUser-Agent:test\r\n\r\n"
	req2 := "GET /test1 HTTP/1.1\r\nHost:" + serverAddress + "\r\nUser-Agent:test\r\n\r\n"

	conn, err := net.DialTimeout("tcp", serverAddress, time.Second*30)
	s.AssertNil(err, fmt.Sprint(err))
	defer conn.Close()
	err = conn.SetDeadline(time.Now().Add(time.Second * 15))
	s.AssertNil(err, fmt.Sprint(err))
	n, err := conn.Write([]byte(req1))
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertEqual(n, len([]rune(req1)))
	// send second request a bit later so first is already in progress
	time.Sleep(500 * time.Millisecond)
	n, err = conn.Write([]byte(req2))
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertEqual(n, len([]rune(req2)))
	reply := make([]byte, 1024)
	_, err = conn.Read(reply)
	s.AssertNil(err, fmt.Sprint(err))
	s.Log(string(reply))
	s.AssertContains(string(reply), "delayed data", "first request response not received")
	s.AssertNotContains(string(reply), "hello", "second request response received")
	// make sure response for second request is not received later
	_, err = conn.Read(reply)
	s.AssertMatchError(err, os.ErrDeadlineExceeded, "second request response received")
}

func HttpStaticPostTest(s *Http1Suite) {
	// testing url handler app do not support multi-thread
	s.SkipIfMultiWorker()
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers debug max-body-size 1m"))
	s.Log(vpp.Vppctl("test-url-handler enable"))

	body := make([]byte, 131072)
	_, err := rand.Read(body)
	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("POST", "http://"+serverAddress+"/test3", bytes.NewBuffer(body))
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.AssertHttpStatus(resp, 200)
	_, err = io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
}

func HttpCliTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1

	cliServerCmd := "http cli server uri http://" + serverAddress
	s.Containers.ServerVpp.VppInstance.Vppctl(cliServerCmd)

	o := s.Containers.ClientVpp.VppInstance.Vppctl("http cli client" +
		" uri http://" + serverAddress + "/show/vlib/graph")

	s.Log(o)
	s.AssertContains(o, "<html>", "<html> not found in the result!")
	s.AssertContains(o, "</html>", "</html> not found in the result!")

	/* test client session cleanup */
	clientCleanupDone := false
	for nTries := 0; nTries < 30; nTries++ {
		o := s.Containers.ClientVpp.VppInstance.Vppctl("show session verbose 2")
		if !strings.Contains(o, "->"+serverAddress) {
			clientCleanupDone = true
			break
		}
		time.Sleep(1 * time.Second)
	}
	s.AssertEqual(true, clientCleanupDone)

	/* test server app stop listen */
	s.Containers.ServerVpp.VppInstance.Vppctl(cliServerCmd + " listener del")
	o = s.Containers.ServerVpp.VppInstance.Vppctl("show session verbose proto http")
	s.AssertNotContains(o, "LISTEN")

	o = s.Containers.ClientVpp.VppInstance.Vppctl("show http stats")
	s.Log(o)
	s.AssertContains(o, "1 connections established")
	s.AssertContains(o, "1 requests sent")
	s.AssertContains(o, "1 responses received")
	o = s.Containers.ServerVpp.VppInstance.Vppctl("show http stats")
	s.Log(o)
	s.AssertContains(o, "1 connections accepted")
	s.AssertContains(o, "1 requests received")
	s.AssertContains(o, "1 responses sent")
}

func HttpCliTlsTest(s *VethsSuite) {
	uri := "https://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1

	s.Containers.ServerVpp.VppInstance.Vppctl("http cli server http1-only uri " + uri)

	o := s.Containers.ClientVpp.VppInstance.Vppctl("http cli client" +
		" uri " + uri + "/show/version")
	s.Log(o)
	s.AssertContains(o, "<html>", "<html> not found in the result!")
	s.AssertContains(o, "</html>", "</html> not found in the result!")

	/* second request to test postponed ho-cleanup */
	o = s.Containers.ClientVpp.VppInstance.Vppctl("http cli client" +
		" uri " + uri + "/show/version")
	s.Log(o)
	s.AssertContains(o, "<html>", "<html> not found in the result!")
	s.AssertContains(o, "</html>", "</html> not found in the result!")
}

func HttpCliConnectErrorTest(s *VethsSuite) {
	uri := "http://" + s.Interfaces.Server.Ip4AddressString() + "/80"

	o := s.Containers.ClientVpp.VppInstance.Vppctl("http cli client" +
		" uri " + uri + "/show/vlib/graph")

	s.Log(o)
	s.AssertContains(o, "failed to connect")
}

func HttpClientTest(s *Http1Suite) {
	serverAddress := s.HostAddr() + ":" + s.Ports.Http
	server := ghttp.NewUnstartedServer()
	l, err := net.Listen("tcp", serverAddress)
	s.AssertNil(err, fmt.Sprint(err))
	server.HTTPTestServer.Listener = l
	server.AppendHandlers(
		ghttp.CombineHandlers(
			s.LogHttpReq(true),
			ghttp.VerifyRequest("GET", "/test"),
			ghttp.VerifyHeader(http.Header{"User-Agent": []string{"http_cli_client"}}),
			ghttp.VerifyHeader(http.Header{"Accept": []string{"text/html"}}),
			ghttp.RespondWith(http.StatusOK, "<html><body><p>Hello</p></body></html>"),
		))
	server.Start()
	defer server.Close()
	uri := "http://" + serverAddress
	vpp := s.Containers.Vpp.VppInstance
	o := vpp.Vppctl("http cli client uri " + uri + "/test")

	s.Log(o)
	s.AssertContains(o, "<html>", "<html> not found in the result!")
	s.AssertContains(o, "</html>", "</html> not found in the result!")
}

func HttpClientChunkedDownloadTest(s *Http1Suite) {
	serverAddress := s.HostAddr() + ":" + s.Ports.Http
	server := ghttp.NewUnstartedServer()
	l, err := net.Listen("tcp", serverAddress)
	s.AssertNil(err, fmt.Sprint(err))
	server.HTTPTestServer.Listener = l
	response := strings.Repeat("a", 128*1024)
	server.AppendHandlers(
		ghttp.CombineHandlers(
			s.LogHttpReq(true),
			ghttp.VerifyRequest("GET", "/"),
			ghttp.RespondWith(http.StatusOK, response, http.Header{"Content-Length": {strconv.Itoa(len(response))}}),
		))
	server.Start()
	defer server.Close()
	uri := "http://" + serverAddress
	vpp := s.Containers.Vpp.VppInstance
	o := vpp.Vppctl("http client save-to response.txt fifo-size 64k max-body-size 64k uri " + uri)

	s.Log(o)
	file_contents, err := vpp.Container.Exec(false, "cat /tmp/response.txt")
	s.AssertNil(err)
	s.AssertContains(file_contents, response)
}

func HttpClientBodySizeTest(s *Http1Suite) {
	serverAddress := s.HostAddr() + ":" + s.Ports.Http
	server := ghttp.NewUnstartedServer()
	l, err := net.Listen("tcp", serverAddress)
	s.AssertNil(err, fmt.Sprint(err))
	server.HTTPTestServer.Listener = l
	server.AppendHandlers(
		ghttp.CombineHandlers(
			s.LogHttpReq(true),
			ghttp.VerifyRequest("GET", "/test"),
			ghttp.RespondWith(http.StatusOK, "<html><body><p>Hello</p></body></html>"),
		))
	server.Start()
	defer server.Close()
	uri := "http://" + serverAddress + "/test"
	vpp := s.Containers.Vpp.VppInstance
	o := vpp.Vppctl("http client max-body-size 5 verbose uri " + uri)

	s.Log(o)
	s.AssertContains(o, "* response body over limit", "response body size info not found in result!")
	s.AssertContains(o, ", read total 38 bytes", "client retrieved invalid amount of bytes!")
}

func HttpClientInvalidHeaderNameTest(s *Http1Suite) {
	serverAddress := s.HostAddr()
	l, err := net.Listen("tcp", serverAddress+":80")
	s.AssertNil(err, fmt.Sprint(err))
	defer l.Close()
	go func() {
		b := make([]byte, 512)
		conn, err := l.Accept()
		if err != nil {
			return
		}
		_, err = conn.Read(b)
		if err != nil {
			return
		}
		_, err = conn.Write([]byte("HTTP/1.1 200 OK\r\n\xE0\x81\x9C\r\n\r\n"))
		if err != nil {
			return
		}
	}()
	uri := "http://" + serverAddress + "/index.html"
	vpp := s.Containers.Vpp.VppInstance
	o := vpp.Vppctl("http client uri " + uri + " timeout 5")
	s.Log(o)
	s.AssertContains(o, "transport closed")

	/* wait until cleanup to be sure we don't crash */
	httpCleanupDone := false
	tcpSessionCleanupDone := false
	for nTries := 0; nTries < 60; nTries++ {
		o := vpp.Vppctl("show session verbose 2")
		if !strings.Contains(o, "[T]") {
			tcpSessionCleanupDone = true
		}
		if !strings.Contains(o, "[H1]") {
			httpCleanupDone = true
		}
		if httpCleanupDone && tcpSessionCleanupDone {
			s.Log(o)
			break
		}
		time.Sleep(1 * time.Second)
	}
	s.AssertEqual(true, tcpSessionCleanupDone, "TCP session not cleanup")
	s.AssertEqual(true, httpCleanupDone, "HTTP not cleanup")
	o = vpp.Vppctl("show http stats")
	s.Log(o)
	s.AssertContains(o, "1 connections protocol error")
}

func HttpClientErrRespTest(s *Http1Suite) {
	serverAddress := s.HostAddr() + ":" + s.Ports.Http
	server := ghttp.NewUnstartedServer()
	l, err := net.Listen("tcp", serverAddress)
	s.AssertNil(err, fmt.Sprint(err))
	server.HTTPTestServer.Listener = l
	server.AppendHandlers(
		ghttp.CombineHandlers(
			s.LogHttpReq(true),
			ghttp.VerifyRequest("GET", "/test"),
			ghttp.RespondWith(http.StatusNotFound, "404: Not Found"),
		))
	server.Start()
	defer server.Close()
	uri := "http://" + serverAddress
	vpp := s.Containers.Vpp.VppInstance
	o := vpp.Vppctl("http cli client uri " + uri + "/test")

	s.Log(o)
	s.AssertContains(o, "404: Not Found", "error not found in the result!")
}

func HttpClientPostFormTest(s *Http1Suite) {
	serverAddress := s.HostAddr() + ":" + s.Ports.Http
	body := "field1=value1&field2=value2"

	server := ghttp.NewUnstartedServer()
	l, err := net.Listen("tcp", serverAddress)
	s.AssertNil(err, fmt.Sprint(err))
	server.HTTPTestServer.Listener = l
	server.AppendHandlers(
		ghttp.CombineHandlers(
			s.LogHttpReq(true),
			ghttp.VerifyRequest("POST", "/test"),
			ghttp.VerifyContentType("application/x-www-form-urlencoded"),
			ghttp.VerifyHeaderKV("Hello", "World"),
			ghttp.VerifyBody([]byte(body)),
			ghttp.RespondWith(http.StatusOK, nil),
		))
	server.Start()
	defer server.Close()

	uri := "http://" + serverAddress + "/test"
	vpp := s.Containers.Vpp.VppInstance
	o := vpp.Vppctl("http client post verbose header Hello:World uri " + uri + " data " + body)

	s.Log(o)
	s.AssertContains(o, "200 OK")
}

func HttpClientNoPrintTest(s *Http1Suite) {
	serverAddress := s.HostAddr() + ":" + s.Ports.Http
	server := ghttp.NewUnstartedServer()
	l, err := net.Listen("tcp", serverAddress)
	s.AssertNil(err, fmt.Sprint(err))
	server.HTTPTestServer.Listener = l
	server.AppendHandlers(
		ghttp.CombineHandlers(
			s.LogHttpReq(true),
			ghttp.VerifyRequest("GET", "/"),
			// Bogus header just for testing
			ghttp.RespondWith(http.StatusOK, "<html><body><p>Hello</p></body></html>", http.Header{"Content-Type": {"image/jpeg"}}),
		))
	server.Start()
	defer server.Close()
	uri := "http://" + serverAddress
	vpp := s.Containers.Vpp.VppInstance
	o := vpp.Vppctl("http client verbose uri " + uri)

	s.Log(o)
	s.AssertContains(o, "* binary file, not printing!", "no warning message found!")
	s.AssertNotContains(o, "</html>", "</html> found in the result!")
}

func HttpClientGetResponseBodyTest(s *Http1Suite) {
	response := "<body>hello world</body>"
	size := len(response)
	httpClientGet(s, response, size, "http")
}

func HttpClientGet128kbResponseTest(s *Http1Suite) {
	response := strings.Repeat("a", 128*1024)
	size := len(response)
	httpClientGet(s, response, size, "http")
}

func HttpClientGetTlsNoRespBodyTest(s *Http1Suite) {
	response := ""
	httpClientGet(s, response, 0, "https")
}

func golangServer(s *Http1Suite, serverAddress string, proto string) *ghttp.Server {
	var l net.Listener
	var err error

	destinationServer := ghttp.NewUnstartedServer()

	if proto == "https" {
		certFile := "resources/cert/localhost.crt"
		keyFile := "resources/cert/localhost.key"
		cer, err := tls.LoadX509KeyPair(certFile, keyFile)
		s.AssertNil(err)
		tlsConfig := &tls.Config{Certificates: []tls.Certificate{cer}}
		destinationServer.HTTPTestServer.TLS = tlsConfig
		l, err = tls.Listen("tcp", serverAddress, tlsConfig)
	} else {
		l, err = net.Listen("tcp", serverAddress)
	}
	s.AssertNil(err, fmt.Sprint(err))

	destinationServer.HTTPTestServer.Listener = l

	return destinationServer
}

func httpClientGet(s *Http1Suite, response string, size int, proto string) {
	var err error
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.HostAddr() + ":" + s.Ports.Http
	server := golangServer(s, serverAddress, proto)
	server.AppendHandlers(
		ghttp.CombineHandlers(
			s.LogHttpReq(true),
			ghttp.VerifyRequest("GET", "/"),
			ghttp.RespondWith(
				http.StatusOK,
				response,
				http.Header{"Content-Length": {strconv.Itoa(size)}},
			),
		),
	)
	server.Start()
	defer server.Close()

	uri := proto + "://" + serverAddress
	cmd := "http client use-ptr verbose header Hello:World header Test-H2:Test-K2 save-to response.txt uri " + uri

	o := vpp.Vppctl(cmd)
	outputLen := len(o)
	if outputLen > 500 {
		s.Log(o[:500])
		s.Log("* HST Framework: output limited to 500 chars to avoid flooding the console. Output length: " + fmt.Sprint(outputLen))
	} else {
		s.Log(o)
	}
	s.AssertContains(o, "200 OK")
	s.AssertContains(o, "Content-Length: "+strconv.Itoa(size))

	file_contents, err := vpp.Container.Exec(false, "cat /tmp/response.txt")
	s.AssertNil(err)
	s.AssertContains(file_contents, response)
}

func httpClientGetRedirect(s *Http1Suite, requestMethod string, response string, size int, proto string, httpResponseCode int, 
	server1Method string, server2Method string, clientUri string) {
		vpp := s.Containers.Vpp.VppInstance
		destinationAddress := s.HostAddr() + ":" + s.Ports.NginxServer
		redirectServerAddress := s.HostAddr() + ":" + s.Ports.Http

		redirectServer := golangServer(s, redirectServerAddress, proto)
		redirectServer.AppendHandlers(
		ghttp.CombineHandlers(
			s.LogHttpReq(true),
			ghttp.VerifyRequest(server1Method, "/"),
			ghttp.VerifyHeaderKV("Hello", "World"),
			ghttp.VerifyHeaderKV("Test-H2", "Test-K2"),
			ghttp.RespondWith(
				httpResponseCode,
				"",
				http.Header{
					"Location": {"/test"},
				},
			),
		),
		ghttp.CombineHandlers(
			s.LogHttpReq(true),
			ghttp.VerifyRequest(server2Method, "/test"),
			ghttp.VerifyHeaderKV("Hello", "World"),
			ghttp.VerifyHeaderKV("Test-H2", "Test-K2"),
			ghttp.RespondWith(
				httpResponseCode,
				"",
				http.Header{
					"Location": {"http://" + destinationAddress},
				},
			),
		),
	)

		redirectServer.Start()
		defer redirectServer.Close()

		destinationServer := golangServer(s, destinationAddress, proto)
		destinationServer.AppendHandlers(
		ghttp.CombineHandlers(
			s.LogHttpReq(true),
			ghttp.VerifyRequest(server2Method, "/"),
			ghttp.RespondWith(
				http.StatusOK,
				response,
				http.Header{"Content-Length": {strconv.Itoa(size)}},
			),
		),
	)
		destinationServer.Start()
		defer destinationServer.Close()

		if requestMethod == "post" {
			requestMethod += " data field1=value1&field2=value2"
		}
		cmd := "http client " + requestMethod + " redirect max-redirects 5 verbose use-ptr header Hello:World header Test-H2:Test-K2 save-to response.txt uri " + clientUri
		
		o := vpp.Vppctl(cmd)
		outputLen := len(o)
		if outputLen > 500 {
			s.Log(o[:500])
			s.Log("* HST Framework: output limited to 500 chars to avoid flooding the console. Output length: " + fmt.Sprint(outputLen))
			} else {
		s.Log(o)
	}

	s.AssertContains(o, "200 OK")
	s.AssertContains(o, "Content-Length: "+strconv.Itoa(size))
	file_contents, err := vpp.Container.Exec(false, "cat /tmp/response.txt")
	s.AssertNil(err)
	s.AssertContains(file_contents, response)
}

func HttpClientRedirect302Test(s *Http1Suite) {
	response := "<body>hello world</body>"
	size := len(response)
	uri := "http://" + s.HostAddr() + ":" + s.Ports.Http
	httpClientGetRedirect(s, "post", response, size, "http", http.StatusFound, "POST", "GET", uri)
}

func HttpClientRedirect308Test(s *Http1Suite) {
	response := "<body>hello world</body>"
	size := len(response)
	uri := "http://" + s.HostAddr() + ":" + s.Ports.Http
	httpClientGetRedirect(s, "post", response, size, "http", http.StatusPermanentRedirect, "POST", "POST", uri)
}

func HttpClientRedirectLimitTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddr := s.HostAddr() + ":" + s.Ports.Http
	server := golangServer(s, serverAddr, "http")
	handlers := ghttp.CombineHandlers(
			s.LogHttpReq(false),
			ghttp.VerifyRequest("GET", "/"),
			ghttp.VerifyHeaderKV("Hello", "World"),
			ghttp.VerifyHeaderKV("Test-H2", "Test-K2"),
			ghttp.RespondWith(
				http.StatusPermanentRedirect,
				"",
				http.Header{
					"Location": {"http://" + serverAddr},
				},
			),
		)
		for range 6 {
			server.AppendHandlers(handlers)
		}
		server.Start()
		defer server.Close()
	
	uri := "http://" + serverAddr
	cmd := "http client redirect max-redirects 5 verbose timeout 999 header Hello:World header Test-H2:Test-K2 save-to response.txt uri " + uri
		
	o := vpp.Vppctl(cmd)
	s.Log(o)
	s.AssertContains(o, "redirect limit")
	s.AssertContains(o, http.StatusPermanentRedirect)
}

// registered as a solo test and not using generated ports
func HttpClientGetResponseBody6Test(s *NoTopo6Suite) {
	response := "<body>hello world</body>"
	size := len(response)
	httpClientGet6(s, response, size, "http")
}

// registered as a solo test and not using generated ports
func HttpClientGetTlsResponseBody6Test(s *NoTopo6Suite) {
	response := "<body>hello world</body>"
	size := len(response)
	httpClientGet6(s, response, size, "https")
}

func httpClientGet6(s *NoTopo6Suite, response string, size int, proto string) {
	var l net.Listener
	var err error
	var port string

	vpp := s.Containers.Vpp.VppInstance
	server := ghttp.NewUnstartedServer()
	serverAddress := "[" + s.HostAddr() + "]"

	if proto == "https" {
		certFile := "resources/cert/localhost.crt"
		keyFile := "resources/cert/localhost.key"
		cer, err := tls.LoadX509KeyPair(certFile, keyFile)
		s.AssertNil(err)
		tlsConfig := &tls.Config{Certificates: []tls.Certificate{cer}}
		server.HTTPTestServer.TLS = tlsConfig
		port = "443"
		l, err = tls.Listen("tcp", serverAddress+":443", tlsConfig)
	} else {
		port = "80"
		l, err = net.Listen("tcp", serverAddress+":80")
	}
	s.AssertNil(err, fmt.Sprint(err))

	server.HTTPTestServer.Listener = l
	server.AppendHandlers(
		ghttp.CombineHandlers(
			s.LogHttpReq(false),
			ghttp.VerifyRequest("GET", "/"),
			ghttp.VerifyHeaderKV("Hello", "World"),
			ghttp.VerifyHeaderKV("Test-H2", "Test-K2"),
			ghttp.RespondWith(http.StatusOK, string(response), http.Header{"Content-Length": {strconv.Itoa(size)}}),
		))
	server.Start()
	defer server.Close()

	uri := proto + "://" + serverAddress + ":" + port + "/"
	cmd := "http client use-ptr verbose header Hello:World header Test-H2:Test-K2 save-to response.txt uri " + uri

	o := vpp.Vppctl(cmd)
	s.Log(o)
	s.AssertContains(o, "200 OK")
	s.AssertContains(o, "Content-Length: "+strconv.Itoa(size))

	file_contents, err := vpp.Container.Exec(false, "cat /tmp/response.txt")
	s.AssertNil(err)
	s.AssertContains(file_contents, response)
}

func HttpClientGetRepeatMWTest(s *Http1Suite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	httpClientRepeat(s, "", "sessions 2")
}

func HttpClientPtrGetRepeatMWTest(s *Http1Suite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	httpClientRepeat(s, "", "use-ptr sessions 2")
}

func HttpClientGetRepeatTest(s *Http1Suite) {
	httpClientRepeat(s, "", "")
}

func HttpClientPostRepeatTest(s *Http1Suite) {
	httpClientRepeat(s, "post", "")
}

func httpClientRepeat(s *Http1Suite, requestMethod string, clientArgs string) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.Interfaces.Tap.Ip4AddressString() + ":" + s.Ports.NginxServer
	replyCountInt := 0
	repeatAmount := 10000
	durationInSec := 10
	var err error

	s.CreateNginxServer()
	s.AssertNil(s.Containers.NginxServer.Start())
	logPath := s.Containers.NginxServer.GetContainerWorkDir() + "/" + s.Containers.NginxServer.Name + "-access.log"

	if requestMethod == "post" {
		fileName := "/tmp/test_file.txt"
		s.Log(vpp.Container.Exec(false, "fallocate -l 64 "+fileName))
		s.Log(vpp.Container.Exec(false, "ls -la "+fileName))
		requestMethod += " file /tmp/test_file.txt"
	}

	uri := "http://" + serverAddress + "/index"
	cmd := fmt.Sprintf("http client %s %s duration %d header Hello:World uri %s",
		requestMethod, clientArgs, durationInSec, uri)

	s.Log("Duration %ds", durationInSec)
	o := vpp.Vppctl(cmd)
	s.Log(o)

	replyCount, err := s.Containers.NginxServer.Exec(false, "awk 'END { print NR }' "+logPath)
	s.AssertNil(err)
	if replyCount != "" {
		replyCountInt, err = strconv.Atoi(replyCount[:len(replyCount)-1])
		s.AssertNil(err)
	}
	// empty the log file
	s.Containers.NginxServer.Exec(false, "truncate -s 0 "+logPath)

	s.Log("Server response count: %d", replyCountInt)
	s.AssertNotNil(o)
	s.AssertNotContains(o, "error")
	s.AssertGreaterEqual(replyCountInt, 15000)

	replyCount = ""
	cmd = fmt.Sprintf("http client %s %s repeat %d header Hello:World uri %s",
		requestMethod, clientArgs, repeatAmount, uri)

	s.AssertNil(err, fmt.Sprint(err))
	s.Log("Repeat %d", repeatAmount)
	o = vpp.Vppctl(cmd)
	s.Log(o)

	replyCount, err = s.Containers.NginxServer.Exec(false, "awk 'END { print NR }' "+logPath)
	s.AssertNil(err)
	if replyCount != "" {
		replyCountInt, err = strconv.Atoi(replyCount[:len(replyCount)-1])
		s.AssertNil(err)
	}
	s.Log("Server response count: %d", replyCountInt)
	s.AssertNotNil(o)
	s.AssertNotContains(o, "error")
	s.AssertEqual(repeatAmount, replyCountInt)
}

func HttpClientGetTimeout(s *Http1Suite) {
	serverAddress := s.HostAddr() + ":" + s.Ports.Http
	vpp := s.Containers.Vpp.VppInstance

	server := ghttp.NewUnstartedServer()
	l, err := net.Listen("tcp", serverAddress)
	s.AssertNil(err, fmt.Sprint(err))
	server.HTTPTestServer.Listener = l
	server.AppendHandlers(
		ghttp.CombineHandlers(
			s.LogHttpReq(false),
			ghttp.VerifyRequest("GET", "/timeout"),
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(5 * time.Second)
			}),
			ghttp.RespondWith(http.StatusOK, nil),
		))
	server.Start()
	defer server.Close()
	uri := "http://" + serverAddress + "/timeout"
	cmd := "http client verbose timeout 1 uri " + uri

	o := vpp.Vppctl(cmd)
	s.Log(o)
	s.AssertContains(o, "error: timeout")
}

func httpClientPostFile(s *Http1Suite, usePtr bool, fileSize int) {
	serverAddress := s.HostAddr() + ":" + s.Ports.Http
	vpp := s.Containers.Vpp.VppInstance
	fileName := "/tmp/test_file.txt"
	s.Log(vpp.Container.Exec(false, "fallocate -l "+strconv.Itoa(fileSize)+" "+fileName))
	s.Log(vpp.Container.Exec(false, "ls -la "+fileName))

	server := ghttp.NewUnstartedServer()
	l, err := net.Listen("tcp", serverAddress)
	s.AssertNil(err, fmt.Sprint(err))
	server.HTTPTestServer.Listener = l
	server.AppendHandlers(
		ghttp.CombineHandlers(
			s.LogHttpReq(false),
			ghttp.VerifyRequest("POST", "/test"),
			ghttp.VerifyHeader(http.Header{"Content-Length": []string{strconv.Itoa(fileSize)}}),
			ghttp.VerifyContentType("application/octet-stream"),
			ghttp.RespondWith(http.StatusOK, nil),
		))
	server.Start()
	defer server.Close()

	uri := "http://" + serverAddress + "/test"
	cmd := "http client post verbose uri " + uri + " file " + fileName
	if usePtr {
		cmd += " use-ptr"
	}
	o := vpp.Vppctl(cmd)

	s.Log(o)
	s.AssertContains(o, "200 OK")
}

func HttpClientPostFileTest(s *Http1Suite) {
	httpClientPostFile(s, false, 32768)
}

func HttpClientPostFilePtrTest(s *Http1Suite) {
	httpClientPostFile(s, true, 131072)
}

func HttpClientPostRejectedTest(s *Http1Suite) {
	serverAddress := s.HostAddr() + ":" + s.Ports.Http
	vpp := s.Containers.Vpp.VppInstance
	fileName := "/tmp/test_file.txt"
	// send something big so we are sure that server respond when we are still sending body
	s.Log(vpp.Container.Exec(false, "fallocate -l "+strconv.Itoa(10<<20)+" "+fileName))
	s.Log(vpp.Container.Exec(false, "ls -la "+fileName))

	server := ghttp.NewUnstartedServer()
	l, err := net.Listen("tcp", serverAddress)
	s.AssertNil(err, fmt.Sprint(err))
	server.HTTPTestServer.Listener = l
	server.AppendHandlers(
		ghttp.CombineHandlers(
			s.LogHttpReq(false),
			ghttp.VerifyRequest("POST", "/test"),
			ghttp.RespondWith(http.StatusForbidden, nil),
		))
	server.Start()
	defer server.Close()

	uri := "http://" + serverAddress + "/test"
	cmd := "http client post verbose uri " + uri + " file " + fileName
	o := vpp.Vppctl(cmd)

	s.Log(o)
	s.AssertContains(o, "403")
	s.Log(vpp.Vppctl("show session verbose 2"))
}

func HttpStaticPromTest(s *Http1Suite) {
	query := "stats.prom"
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers"))
	s.Log(vpp.Vppctl("prom enable"))
	time.Sleep(time.Second * 5)
	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "http://"+serverAddress+"/"+query, nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, false))
	s.AssertHttpStatus(resp, 200)
	s.AssertHttpHeaderWithValue(resp, "Content-Type", "text/plain")
	s.AssertGreaterEqual(resp.ContentLength, 0)
	_, err = io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
}

func promReq(s *Http1Suite, url string, timeout time.Duration) {
	client := NewHttpClient(timeout, false)
	req, err := http.NewRequest("GET", url, nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.AssertHttpStatus(resp, 200)
	_, err = io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
}

func promReqWg(s *Http1Suite, url string, wg *sync.WaitGroup) {
	defer GinkgoRecover()
	defer wg.Done()
	promReq(s, url, defaultHttpTimeout)
}

func PromConcurrentConnectionsTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	url := "http://" + serverAddress + "/stats.prom"

	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers"))
	s.Log(vpp.Vppctl("prom enable"))
	time.Sleep(time.Second * 5)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go promReqWg(s, url, &wg)
	}
	wg.Wait()
	s.Log(vpp.Vppctl("show session verbose proto http"))
}

func PromConsecutiveConnectionsTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	url := "http://" + serverAddress + "/stats.prom"

	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers"))
	s.Log(vpp.Vppctl("prom enable"))
	time.Sleep(time.Second * 5)

	for i := 0; i < 1000; i++ {
		promReq(s, url, time.Millisecond*500)
	}
}

func PromMemLeakTest(s *Http1Suite) {
	s.SkipUnlessLeakCheck()

	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	url := "http://" + serverAddress + "/stats.prom"

	/* no goVPP less noise */
	vpp.Disconnect()

	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers"))
	s.Log(vpp.Vppctl("prom enable"))
	time.Sleep(time.Second * 3)

	/* warmup requests (FIB, pool allocations) */
	for i := 0; i < 5; i++ {
		time.Sleep(time.Second * 1)
		promReq(s, url, defaultHttpTimeout)
	}

	/* let's give it some time to clean up sessions, so pool elements can be reused and we have less noise */
	time.Sleep(time.Second * 12)

	vpp.EnableMemoryTrace()
	traces1, err := vpp.GetMemoryTrace()
	s.AssertNil(err, fmt.Sprint(err))

	/* collect stats couple of times */
	for i := 0; i < 5; i++ {
		time.Sleep(time.Second * 1)
		promReq(s, url, defaultHttpTimeout)
	}

	/* let's give it some time to clean up sessions */
	time.Sleep(time.Second * 12)

	traces2, err := vpp.GetMemoryTrace()
	s.AssertNil(err, fmt.Sprint(err))
	vpp.MemLeakCheck(traces1, traces2)
}

func HttpClientGetMemLeakTest(s *VethsSuite) {
	s.SkipUnlessLeakCheck()

	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	/* no goVPP less noise */
	clientVpp.Disconnect()

	uri := "http://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1

	serverVpp.Vppctl("http cli server uri " + uri)

	/* warmup request (FIB) */
	clientVpp.Vppctl("http cli client uri " + uri + "/show/version")

	/* let's give it some time to clean up sessions, so local port can be reused and we have less noise */
	time.Sleep(time.Second * 12)

	clientVpp.EnableMemoryTrace()
	traces1, err := clientVpp.GetMemoryTrace()
	s.AssertNil(err, fmt.Sprint(err))

	clientVpp.Vppctl("http cli client uri " + uri + "/show/vlib/graph")

	/* let's give it some time to clean up sessions */
	time.Sleep(time.Second * 12)

	traces2, err := clientVpp.GetMemoryTrace()
	s.AssertNil(err, fmt.Sprint(err))
	clientVpp.MemLeakCheck(traces1, traces2)
}

func HttpClientRedirectMemLeakTest(s *Http1Suite) {
	s.SkipUnlessLeakCheck()

	serverAddress := s.HostAddr() + ":" + s.Ports.Http

	uri := "http://" + serverAddress + "/test"
	vpp := s.Containers.Vpp.VppInstance

	/* no goVPP less noise */
	vpp.Disconnect()

	server := ghttp.NewUnstartedServer()
	l, err := net.Listen("tcp", serverAddress)
	s.AssertNil(err, fmt.Sprint(err))
	server.HTTPTestServer.Listener = l
	server.AppendHandlers(
		ghttp.CombineHandlers(
			ghttp.VerifyRequest("GET", "/test"),
			ghttp.RespondWith(
				http.StatusPermanentRedirect,
				"",
				http.Header{
					"Location": {"/"},
				},
			),
		),
		ghttp.CombineHandlers(
			ghttp.VerifyRequest("GET", "/"),
			ghttp.RespondWith(http.StatusOK, nil),
		),
	)

	server.AppendHandlers(
		ghttp.CombineHandlers(
			ghttp.VerifyRequest("GET", "/test"),
			ghttp.RespondWith(
				http.StatusPermanentRedirect,
				"",
				http.Header{
					"Location": {"/"},
				},
			),
		),
		ghttp.CombineHandlers(
			ghttp.VerifyRequest("GET", "/"),
			ghttp.RespondWith(http.StatusOK, nil),
		),
	)
	server.Start()
	defer server.Close()

	vpp.Vppctl("http client redirect max-redirects 5 verbose header Hello:World header Test-H2:Test-K2 save-to response.txt uri " + uri)
	time.Sleep(time.Second * 12)

	vpp.EnableMemoryTrace()
	traces1, err := vpp.GetMemoryTrace()
	s.AssertNil(err, fmt.Sprint(err))

	vpp.Vppctl("http client redirect max-redirects 5 verbose header Hello:World header Test-H2:Test-K2 save-to response.txt uri " + uri)
	time.Sleep(time.Second * 12)

	traces2, err := vpp.GetMemoryTrace()
	s.AssertNil(err, fmt.Sprint(err))
	vpp.MemLeakCheck(traces1, traces2)
}

func HttpClientPostMemLeakTest(s *Http1Suite) {
	s.SkipUnlessLeakCheck()

	serverAddress := s.HostAddr() + ":" + s.Ports.Http
	body := "field1=value1&field2=value2"

	uri := "http://" + serverAddress
	vpp := s.Containers.Vpp.VppInstance

	/* no goVPP less noise */
	vpp.Disconnect()

	server := ghttp.NewUnstartedServer()
	l, err := net.Listen("tcp", serverAddress)
	s.AssertNil(err, fmt.Sprint(err))
	server.HTTPTestServer.Listener = l
	server.AppendHandlers(
		ghttp.CombineHandlers(
			ghttp.VerifyRequest("POST", "/test"),
			ghttp.RespondWith(http.StatusOK, nil),
		),
		ghttp.CombineHandlers(
			ghttp.VerifyRequest("POST", "/test"),
			ghttp.RespondWith(http.StatusOK, nil),
		),
	)
	server.Start()
	defer server.Close()

	/* warmup request (FIB) */
	vpp.Vppctl("http post uri " + uri + " target /test data " + body)

	/* let's give it some time to clean up sessions, so local port can be reused and we have less noise */
	time.Sleep(time.Second * 12)

	vpp.EnableMemoryTrace()
	traces1, err := vpp.GetMemoryTrace()
	s.AssertNil(err, fmt.Sprint(err))

	vpp.Vppctl("http post uri " + uri + " target /test data " + body)

	/* let's give it some time to clean up sessions */
	time.Sleep(time.Second * 12)

	traces2, err := vpp.GetMemoryTrace()
	s.AssertNil(err, fmt.Sprint(err))
	vpp.MemLeakCheck(traces1, traces2)
}

func HttpInvalidClientRequestMemLeakTest(s *Http1Suite) {
	s.SkipUnlessLeakCheck()

	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http

	/* no goVPP less noise */
	vpp.Disconnect()

	vpp.Vppctl("http cli server uri http://" + serverAddress)

	/* warmup request (FIB) */
	_, err := TcpSendReceive(serverAddress, "GET / HTTP/1.1\r\n")
	s.AssertNil(err, fmt.Sprint(err))

	/* let's give it some time to clean up sessions, so local port can be reused and we have less noise */
	time.Sleep(time.Second * 12)

	vpp.EnableMemoryTrace()
	traces1, err := vpp.GetMemoryTrace()
	s.AssertNil(err, fmt.Sprint(err))

	_, err = TcpSendReceive(serverAddress, "GET / HTTP/1.1\r\n")
	s.AssertNil(err, fmt.Sprint(err))

	/* let's give it some time to clean up sessions */
	time.Sleep(time.Second * 12)

	traces2, err := vpp.GetMemoryTrace()
	s.AssertNil(err, fmt.Sprint(err))
	vpp.MemLeakCheck(traces1, traces2)

}

func runWrkPerf(s *Http1Suite) {
	nConnections := 1000
	serverAddress := s.VppAddr() + ":" + s.Ports.Http

	args := fmt.Sprintf("-c %d -t 2 -d 30s http://%s/64B", nConnections, serverAddress)
	s.Containers.Wrk.ExtraRunningArgs = args
	s.Containers.Wrk.Run()
	s.Log("Please wait for 30s, test is running.")
	o, err := s.Containers.Wrk.GetOutput()
	s.Log(o)
	s.AssertEmpty(err, "err: '%s'", err)
}

func HttpStaticFileHandlerWrkTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	vpp.Container.Exec(false, "mkdir -p "+wwwRootPath)
	content := "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	err := vpp.Container.CreateFile(wwwRootPath+"/64B", content)
	s.AssertNil(err, fmt.Sprint(err))
	s.Log(vpp.Vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress + " private-segment-size 256m"))
	runWrkPerf(s)
}

func HttpStaticUrlHandlerWrkTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers private-segment-size 256m"))
	s.Log(vpp.Vppctl("test-url-handler enable"))
	runWrkPerf(s)
}

func HttpStaticFileHandlerDefaultMaxAgeTest(s *Http1Suite) {
	HttpStaticFileHandlerTestFunction(s, "default")
}

func HttpStaticFileHandlerTest(s *Http1Suite) {
	HttpStaticFileHandlerTestFunction(s, "123")
}

func HttpStaticFileHandlerTestFunction(s *Http1Suite, max_age string) {
	var maxAgeFormatted string
	if max_age == "default" {
		maxAgeFormatted = ""
		max_age = "600"
	} else {
		maxAgeFormatted = "max-age " + max_age
	}

	content := "<html><body><p>Hello</p></body></html>"
	content2 := "<html><body><p>Page</p></body></html>"

	vpp := s.Containers.Vpp.VppInstance
	vpp.Container.Exec(false, "mkdir -p "+wwwRootPath)
	err := vpp.Container.CreateFile(wwwRootPath+"/index.html", content)
	s.AssertNil(err, fmt.Sprint(err))
	err = vpp.Container.CreateFile(wwwRootPath+"/page.html", content2)
	s.AssertNil(err, fmt.Sprint(err))
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	s.Log(vpp.Vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress + " debug cache-size 2m " + maxAgeFormatted))

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "http://"+serverAddress+"/index.html", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))

	s.Log(DumpHttpResp(resp, true))
	s.AssertHttpStatus(resp, 200)
	s.AssertHttpHeaderWithValue(resp, "Content-Type", "text/html")
	s.AssertHttpHeaderWithValue(resp, "Cache-Control", "max-age="+max_age)
	parsedTime, err := time.Parse(time.RFC1123, resp.Header.Get("Last-Modified"))
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertTimeEqualWithinThreshold(parsedTime, time.Now(), time.Minute*5)
	s.AssertEqual(len(resp.Header.Get("Last-Modified")), 29)
	s.AssertHttpContentLength(resp, int64(len([]rune(content))))
	s.AssertHttpBody(resp, content)
	o := vpp.Vppctl("show http static server cache verbose")
	s.Log(o)
	s.AssertContains(o, "index.html")
	s.AssertNotContains(o, "page.html")

	resp, err = client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	s.Log(DumpHttpResp(resp, true))
	s.AssertHttpStatus(resp, 200)
	s.AssertHttpHeaderWithValue(resp, "Content-Type", "text/html")
	s.AssertHttpHeaderWithValue(resp, "Cache-Control", "max-age="+max_age)
	s.AssertHttpContentLength(resp, int64(len([]rune(content))))
	s.AssertHttpBody(resp, content)

	req, err = http.NewRequest("GET", "http://"+serverAddress+"/page.html", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err = client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	s.Log(DumpHttpResp(resp, true))
	s.AssertHttpStatus(resp, 200)
	s.AssertHttpHeaderWithValue(resp, "Content-Type", "text/html")
	s.AssertHttpHeaderWithValue(resp, "Cache-Control", "max-age="+max_age)
	s.AssertHttpContentLength(resp, int64(len([]rune(content2))))
	s.AssertHttpBody(resp, content2)
	o = vpp.Vppctl("show http static server cache verbose")
	s.Log(o)
	s.AssertContains(o, "index.html")
	s.AssertContains(o, "page.html")
}

func HttpStaticPathSanitizationTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	vpp.Container.Exec(false, "mkdir -p "+wwwRootPath)
	vpp.Container.Exec(false, "mkdir -p "+"/tmp/secret_folder")
	err := vpp.Container.CreateFile("/tmp/secret_folder/secret_file.txt", "secret")
	s.AssertNil(err, fmt.Sprint(err))
	indexContent := "<html><body>index</body></html>"
	err = vpp.Container.CreateFile(wwwRootPath+"/index.html", indexContent)
	s.AssertNil(err, fmt.Sprint(err))
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	s.Log(vpp.Vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress + " debug"))

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "http://"+serverAddress+"/../secret_folder/secret_file.txt", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, true))
	s.AssertHttpStatus(resp, 404)
	s.AssertHttpHeaderNotPresent(resp, "Content-Type")
	s.AssertHttpHeaderNotPresent(resp, "Cache-Control")
	s.AssertHttpContentLength(resp, int64(0))

	req, err = http.NewRequest("GET", "http://"+serverAddress+"//////fake/directory///../././//../../secret_folder/secret_file.txt", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err = client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, true))
	s.AssertHttpStatus(resp, 404)
	s.AssertHttpHeaderNotPresent(resp, "Content-Type")
	s.AssertHttpHeaderNotPresent(resp, "Cache-Control")
	s.AssertHttpContentLength(resp, int64(0))

	req, err = http.NewRequest("GET", "http://"+serverAddress+"/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err = client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, true))
	s.AssertHttpStatus(resp, 301)
	s.AssertHttpHeaderWithValue(resp, "Location", "http://"+serverAddress+"/index.html")
}

func HttpStaticMovedTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	vpp.Container.Exec(false, "mkdir -p "+wwwRootPath+"/tmp.aaa")
	err := vpp.Container.CreateFile(wwwRootPath+"/tmp.aaa/index.html", "<html><body><p>Hello</p></body></html>")
	s.AssertNil(err, fmt.Sprint(err))
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	s.Log(vpp.Vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress + " debug"))

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "http://"+serverAddress+"/tmp.aaa", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, true))
	s.AssertHttpStatus(resp, 301)
	s.AssertHttpHeaderWithValue(resp, "Location", "http://"+serverAddress+"/tmp.aaa/index.html")
	s.AssertHttpHeaderNotPresent(resp, "Content-Type")
	s.AssertHttpHeaderNotPresent(resp, "Cache-Control")
	s.AssertHttpContentLength(resp, int64(0))
}

func HttpStaticRedirectTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	vpp.Container.Exec(false, "mkdir -p "+wwwRootPath)
	err := vpp.Container.CreateFile(wwwRootPath+"/index.html", "<html><body><p>Hello</p></body></html>")
	s.AssertNil(err, fmt.Sprint(err))
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	s.Log(vpp.Vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress + " debug"))

	req := "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"

	conn, err := net.DialTimeout("tcp", serverAddress, time.Second*30)
	s.AssertNil(err, fmt.Sprint(err))
	defer conn.Close()
	err = conn.SetDeadline(time.Now().Add(time.Second * 5))
	s.AssertNil(err, fmt.Sprint(err))
	n, err := conn.Write([]byte(req))
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertEqual(n, len([]rune(req)))
	reply := make([]byte, 1024)
	_, err = conn.Read(reply)
	s.AssertNil(err, fmt.Sprint(err))
	s.Log(string(reply))
	expectedLocation := fmt.Sprintf("Location: http://example.com/index.html")
	s.AssertContains(string(reply), expectedLocation)
}

func HttpStaticNotFoundTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	vpp.Container.Exec(false, "mkdir -p "+wwwRootPath)
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	s.Log(vpp.Vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress + " debug"))

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "http://"+serverAddress+"/notfound.html", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, true))
	s.AssertHttpStatus(resp, 404)
	s.AssertHttpHeaderNotPresent(resp, "Content-Type")
	s.AssertHttpHeaderNotPresent(resp, "Cache-Control")
	s.AssertHttpContentLength(resp, int64(0))
}

func HttpCliMethodNotAllowedTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	vpp.Vppctl("http cli server uri http://" + serverAddress)

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("POST", "http://"+serverAddress+"/test", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, true))
	s.AssertHttpStatus(resp, 405)
	s.AssertHttpHeaderWithValue(resp, "Allow", "GET", "server MUST generate an Allow header")
	s.AssertHttpHeaderNotPresent(resp, "Content-Type")
	s.AssertHttpContentLength(resp, int64(0))
}

func HttpCliBadRequestTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	vpp.Vppctl("http cli server uri http://" + serverAddress)

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "http://"+serverAddress, nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, true))
	s.AssertHttpStatus(resp, 400)
	s.AssertHttpHeaderNotPresent(resp, "Content-Type")
	s.AssertHttpContentLength(resp, int64(0))
}

func HttpStaticHttp1OnlyTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	s.Log(vpp.Vppctl("http static server uri tls://" + serverAddress + " url-handlers http1-only debug"))

	client := NewHttpClient(defaultHttpTimeout, true)
	req, err := http.NewRequest("GET", "https://"+serverAddress+"/version.json", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, true))
	s.AssertHttpStatus(resp, 200)
	s.AssertEqual(1, resp.ProtoMajor)
	data, err := io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(string(data), "version")
}

func HttpStaticBuildInUrlGetVersionTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	s.Log(vpp.Vppctl("http static server uri tls://" + serverAddress + " url-handlers debug"))

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "https://"+serverAddress+"/version.json", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, true))
	s.AssertHttpStatus(resp, 200)
	s.AssertEqual(1, resp.ProtoMajor)
	data, err := io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(string(data), "vpp_details")
	s.AssertContains(string(data), "version")
	s.AssertContains(string(data), "build_date")
	s.AssertNotContains(string(data), "build_by")
	s.AssertNotContains(string(data), "build_host")
	s.AssertNotContains(string(data), "build_dir")
	s.AssertHttpHeaderWithValue(resp, "Content-Type", "application/json")
}

func HttpStaticBuildInUrlGetVersionVerboseTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers debug"))

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "http://"+serverAddress+"/version.json?verbose=true", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, true))
	s.AssertHttpStatus(resp, 200)
	data, err := io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(string(data), "vpp_details")
	s.AssertContains(string(data), "version")
	s.AssertContains(string(data), "build_date")
	s.AssertContains(string(data), "build_by")
	s.AssertContains(string(data), "build_host")
	s.AssertContains(string(data), "build_dir")
	s.AssertHttpHeaderWithValue(resp, "Content-Type", "application/json")
}

func HttpStaticBuildInUrlGetIfListTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers debug"))

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "http://"+serverAddress+"/interface_list.json", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, true))
	s.AssertHttpStatus(resp, 200)
	data, err := io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(string(data), "interface_list")
	s.AssertContains(string(data), s.VppIfName())
	s.AssertHttpHeaderWithValue(resp, "Content-Type", "application/json")
}

func HttpStaticBuildInUrlGetIfStatsTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers debug"))

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "http://"+serverAddress+"/interface_stats.json", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, true))
	s.AssertHttpStatus(resp, 200)
	data, err := io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(string(data), "interface_stats")
	s.AssertContains(string(data), "local0")
	s.AssertContains(string(data), s.VppIfName())
	s.AssertHttpHeaderWithValue(resp, "Content-Type", "application/json")
}

func validatePostInterfaceStats(s *Http1Suite, data string) {
	s.AssertContains(data, "interface_stats")
	s.AssertContains(data, s.VppIfName())
	s.AssertNotContains(data, "error")
	s.AssertNotContains(data, "local0")
}

func HttpStaticBuildInUrlPostIfStatsTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers debug"))
	body := []byte(s.VppIfName())

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("POST",
		"http://"+serverAddress+"/interface_stats.json", bytes.NewBuffer(body))
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, true))
	s.AssertHttpStatus(resp, 200)
	data, err := io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
	validatePostInterfaceStats(s, string(data))
	s.AssertHttpHeaderWithValue(resp, "Content-Type", "application/json")
}

func HttpStaticMacTimeTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers debug"))
	s.Log(vpp.Vppctl("mactime enable-disable " + s.VppIfName()))

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "http://"+serverAddress+"/mactime.json", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, true))
	s.AssertHttpStatus(resp, 200)
	data, err := io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(string(data), "mactime")
	s.AssertContains(string(data), s.HostAddr())
	s.AssertContains(string(data), s.Interfaces.Tap.HwAddress.String())
	s.AssertHttpHeaderWithValue(resp, "Content-Type", "application/json")
	parsedTime, err := time.Parse(time.RFC1123, resp.Header.Get("Date"))
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertTimeEqualWithinThreshold(parsedTime, time.Now(), time.Minute*5)
	s.AssertEqual(len(resp.Header.Get("Date")), 29)
}

func HttpInvalidRequestLineTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	vpp.Vppctl("http cli server uri http://" + serverAddress)

	resp, err := TcpSendReceive(serverAddress, " GET / HTTP/1.1")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "invalid request line start not allowed")

	resp, err = TcpSendReceive(serverAddress, "\rGET / HTTP/1.1")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "invalid request line start not allowed")

	resp, err = TcpSendReceive(serverAddress, "\nGET / HTTP/1.1")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "invalid request line start not allowed")

	resp, err = TcpSendReceive(serverAddress, "GET / HTTP/1.1")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "invalid framing not allowed")

	resp, err = TcpSendReceive(serverAddress, "GET / HTTP/1.1\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "invalid framing not allowed")

	resp, err = TcpSendReceive(serverAddress, "GET /\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "HTTP-version must be present")

	resp, err = TcpSendReceive(serverAddress, "GET HTTP/1.1\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "request-target must be present")

	resp, err = TcpSendReceive(serverAddress, "GET  HTTP/1.1\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "request-target must be present")

	resp, err = TcpSendReceive(serverAddress, "GET / HTTP/x\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "'HTTP/x' invalid http version not allowed")

	resp, err = TcpSendReceive(serverAddress, "get / HTTP/1.1\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "method must be uppercase")

	resp, err = TcpSendReceive(serverAddress, "GET / HTTP1.1\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "'HTTP1.1' invalid http version not allowed")

	resp, err = TcpSendReceive(serverAddress, "/\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request")
}

func HttpTimerSessionDisable(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	s.Log(vpp.Vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress))
	time.Sleep(250 * time.Millisecond)
	resp := vpp.Vppctl("show node http-timer-process")
	s.AssertContains(resp, "node http-timer-process, type process, state \"any wait\"")
	vpp.Vppctl("session disable")
	time.Sleep(1 * time.Second)
	resp = vpp.Vppctl("show node http-timer-process")
	s.AssertContains(resp, "node http-timer-process, type process, state \"not started\"")
	vpp.Vppctl("session enable")
	time.Sleep(100 * time.Millisecond)
	resp = vpp.Vppctl("show node http-timer-process")
	s.AssertContains(resp, "node http-timer-process, type process, state \"any wait\"")
}

func HttpRequestLineTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	vpp.Vppctl("http cli server uri http://" + serverAddress)

	resp, err := TcpSendReceive(serverAddress, "\r\nGET /show/version HTTP/1.1\r\nHost:"+serverAddress+"\r\nUser-Agent:test\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 200 OK")
	s.AssertContains(resp, "<html>", "html content not found")
}

func HttpInvalidTargetSyntaxTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers debug"))

	resp, err := TcpSendReceive(serverAddress, "GET /interface|stats.json HTTP/1.1\r\nHost: example.com\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "'|' not allowed in target path")

	resp, err = TcpSendReceive(serverAddress, "GET /interface#stats.json HTTP/1.1\r\nHost: example.com\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "'#' not allowed in target path")

	resp, err = TcpSendReceive(serverAddress, "GET /interface%stats.json HTTP/1.1\r\nHost: example.com\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request",
		"after '%' there must be two hex-digit characters in target path")

	resp, err = TcpSendReceive(serverAddress, "GET /interface%1stats.json HTTP/1.1\r\nHost: example.com\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request",
		"after '%' there must be two hex-digit characters in target path")

	resp, err = TcpSendReceive(serverAddress, "GET /interface%Bstats.json HTTP/1.1\r\nHost: example.com\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request",
		"after '%' there must be two hex-digit characters in target path")

	resp, err = TcpSendReceive(serverAddress, "GET /interface%stats.json%B HTTP/1.1\r\nHost: example.com\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request",
		"after '%' there must be two hex-digit characters in target path")

	resp, err = TcpSendReceive(serverAddress, "GET /version.json?verbose?>true HTTP/1.1\r\nHost: example.com\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "'>' not allowed in target query")

	resp, err = TcpSendReceive(serverAddress, "GET /version.json?verbose%true HTTP/1.1\r\nHost: example.com\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request",
		"after '%' there must be two hex-digit characters in target query")

	resp, err = TcpSendReceive(serverAddress, "GET /version.json?verbose=%1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request",
		"after '%' there must be two hex-digit characters in target query")

	resp, err = TcpSendReceive(serverAddress, "GET * HTTP/1.1\r\nHost: example.com\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "asterisk-form is only used for a server-wide OPTIONS request")

	resp, err = TcpSendReceive(serverAddress, "GET www.example.com:80 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "authority-form is only used for CONNECT requests")

	resp, err = TcpSendReceive(serverAddress, "CONNECT https://www.example.com/tunnel HTTP/1.1\r\nHost: example.com\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "CONNECT requests must use authority-form only")

	resp, err = TcpSendReceive(serverAddress, "GET index HTTP/1.1\r\nHost: example.com\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request")
}

func HttpInvalidContentLengthTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	vpp.Vppctl("http cli server uri http://" + serverAddress)

	resp, err := TcpSendReceive(serverAddress, "GET /show/version HTTP/1.1\r\nContent-Length:\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "Content-Length value must be present")

	resp, err = TcpSendReceive(serverAddress, "GET /show/version HTTP/1.1\r\nContent-Length: \r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "Content-Length value must be present")

	resp, err = TcpSendReceive(serverAddress, "GET /show/version HTTP/1.1\r\nContent-Length: a\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request",
		"Content-Length value other than digit not allowed")

	resp, err = TcpSendReceive(serverAddress, "GET /show/version HTTP/1.1\r\nContent-Length: 111111111111111111111111111111111111111111111111\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "Content-Length value exceeded U64_MAX")
}

func HttpContentLengthTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers debug max-body-size 12"))
	ifName := s.VppIfName()

	resp, err := TcpSendReceive(serverAddress,
		"POST /interface_stats.json HTTP/1.1\r\nHost: example.com\r\nContent-Length:4\r\n\r\n"+ifName)
	s.AssertNil(err, fmt.Sprint(err))
	validatePostInterfaceStats(s, resp)

	resp, err = TcpSendReceive(serverAddress,
		"POST /interface_stats.json HTTP/1.1\r\nHost: example.com\r\nContent-Length:  4 \r\n\r\n"+ifName)
	s.AssertNil(err, fmt.Sprint(err))
	validatePostInterfaceStats(s, resp)

	resp, err = TcpSendReceive(serverAddress,
		"POST /interface_stats.json HTTP/1.1\r\nHost: example.com\r\nContent-Length:\t\t4\r\n\r\n"+ifName)
	s.AssertNil(err, fmt.Sprint(err))
	validatePostInterfaceStats(s, resp)
}

func HttpHeaderErrorConnectionDropTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers debug max-body-size 12"))
	request := "POST /interface_stats.json HTTP/1.1\r\nHost: example.com\r\nContent-Length: 18234234\r\n\r\n" + s.VppIfName()
	conn, err := net.DialTimeout("tcp", serverAddress, time.Second*30)
	s.AssertNil(err, fmt.Sprint(err))
	err = conn.SetDeadline(time.Now().Add(time.Second * 10))
	s.AssertNil(err, fmt.Sprint(err))
	_, err = conn.Write([]byte(request))
	s.AssertNil(err, fmt.Sprint(err))
	reply := make([]byte, 1024)
	_, err = conn.Read(reply)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(string(reply), "HTTP/1.1 413 Content Too Large")
	check := make([]byte, 1)
	_, err = conn.Read(check)
	s.AssertEqual(err, io.EOF)
}
func HttpMethodNotImplementedTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	vpp.Vppctl("http cli server uri http://" + serverAddress)

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("OPTIONS", "http://"+serverAddress+"/show/version", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, true))
	s.AssertHttpStatus(resp, 501)
	s.AssertHttpHeaderNotPresent(resp, "Content-Type")
	s.AssertHttpContentLength(resp, int64(0))
}

func HttpVersionNotSupportedTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	vpp.Vppctl("http cli server uri http://" + serverAddress)

	resp, err := TcpSendReceive(serverAddress, "GET / HTTP/2\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 505 HTTP Version Not Supported")
}

func HttpUriDecodeTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	vpp.Vppctl("http cli server uri http://" + serverAddress)

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "http://"+serverAddress+"/sh%6fw%20versio%6E%20verbose", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, true))
	s.AssertHttpStatus(resp, 200)
	data, err := io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertNotContains(string(data), "unknown input")
	s.AssertContains(string(data), "Compiler")
	s.AssertHttpHeaderWithValue(resp, "Content-Type", "text/html")
}

func HttpAbsoluteFormUriTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	vpp.Vppctl("http cli server uri http://" + serverAddress)

	resp, err := TcpSendReceive(serverAddress, "GET http://"+serverAddress+"/show/version HTTP/1.1\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 200 OK")
}

func HttpInvalidAuthorityFormUriTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	vpp.Vppctl("test proxy server fifo-size 512k server-uri http://%s", serverAddress)

	resp, err := TcpSendReceive(serverAddress, "CONNECT 1.2.3.4:80a HTTP/1.1\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request")

	resp, err = TcpSendReceive(serverAddress, "CONNECT 1.2.3.4:80000000 HTTP/1.1\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request")

	resp, err = TcpSendReceive(serverAddress, "CONNECT 1.2a3.4:80 HTTP/1.1\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request")

	resp, err = TcpSendReceive(serverAddress, "CONNECT 1.2.4:80 HTTP/1.1\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request")

	resp, err = TcpSendReceive(serverAddress, "CONNECT [dead:beef::1234:443 HTTP/1.1\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request")

	resp, err = TcpSendReceive(serverAddress, "CONNECT [zyx:beef::1234]:443 HTTP/1.1\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request")

	resp, err = TcpSendReceive(serverAddress, "CONNECT dead:beef::1234:443 HTTP/1.1\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request")

	resp, err = TcpSendReceive(serverAddress, "CONNECT example.org:443 HTTP/1.1\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "name resolution not supported")
}

func HttpHeadersTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	vpp.Vppctl("http cli server uri http://" + serverAddress)

	transport := http.DefaultTransport
	transport.(*http.Transport).Proxy = nil
	transport.(*http.Transport).DisableKeepAlives = false
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Second * 30,
	}

	req, err := http.NewRequest("GET", "http://"+serverAddress+"/show/version", nil)
	s.AssertNil(err, fmt.Sprint(err))
	req.Header.Add("Accept", "text/xml")
	req.Header.Add("Accept-Language", "*")
	req.Header.Add("Accept", "text/plain")
	req.Header.Add("Accept", "text/html")
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, true))
	s.AssertHttpStatus(resp, 200)
	s.AssertHttpHeaderWithValue(resp, "Content-Type", "text/plain")
	data, err := io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertNotContains(string(data), "<html>", "html content received instead of plain text")

	req2, err := http.NewRequest("GET", "http://"+serverAddress+"/show/version", nil)
	s.AssertNil(err, fmt.Sprint(err))
	req2.Header.Add("Accept", "text/html")
	resp2, err := client.Do(req2)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp2.Body.Close()
	s.Log(DumpHttpResp(resp2, true))
	s.AssertHttpStatus(resp2, 200)
	s.AssertHttpHeaderWithValue(resp2, "Content-Type", "text/html")
	data2, err := io.ReadAll(resp2.Body)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(string(data2), "<html>", "html content not received")

	/* test cleanup */
	client.CloseIdleConnections()
	for nTries := 0; nTries < 10; nTries++ {
		o := vpp.Vppctl("show session verbose 2")
		if !strings.Contains(o, serverAddress+"->"+s.HostAddr()) {
			break
		}
		time.Sleep(1 * time.Second)
	}
}

func HttpInvalidHeadersTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	vpp.Vppctl("http cli server uri http://" + serverAddress)

	resp, err := TcpSendReceive(serverAddress, "GET /show/version HTTP/1.1\r\nUser-Agent: test\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "Header section must end with CRLF CRLF")

	resp, err = TcpSendReceive(serverAddress, "GET /show/version HTTP/1.1\r\nHost:"+serverAddress+"\r\nUser@Agent:test\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "'@' not allowed in field name")

	resp, err = TcpSendReceive(serverAddress, "GET /show/version HTTP/1.1\r\nHost:"+serverAddress+"\r\nUser-Agent\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "incomplete field line not allowed")

	resp, err = TcpSendReceive(serverAddress, "GET /show/version HTTP/1.1\r\nHost:"+serverAddress+"\r\n: test\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "empty field name not allowed")

	resp, err = TcpSendReceive(serverAddress, "GET /show/version HTTP/1.1\r\nHost:"+serverAddress+"\rUser-Agent:test\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "invalid field line end not allowed")

	resp, err = TcpSendReceive(serverAddress, "GET /show/version HTTP/1.1\r\nHost:"+serverAddress+"\nUser-Agent:test\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "invalid field line end not allowed")

	resp, err = TcpSendReceive(serverAddress, "GET /show/version HTTP/1.1\r\nHost:"+serverAddress+"\r\nUser-Agent:\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "empty field value not allowed")

	resp, err = TcpSendReceive(serverAddress, "GET /show/version HTTP/1.1\r\nHost:"+serverAddress+"\r\nUser-Agent:    \r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "empty field value not allowed")
}

func HeaderServerTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	vpp.Vppctl("http cli server uri http://" + serverAddress)

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "http://"+serverAddress+"/show/version", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, true))
	s.AssertHttpStatus(resp, 200)
	s.AssertHttpHeaderWithValue(resp, "Server", "http_cli_server")
	s.AssertHttpHeaderWithValue(resp, "Content-Type", "text/html")
}

func HttpConnTimeoutTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers debug keepalive-timeout 2"))

	req := "GET /version.json HTTP/1.1\r\nHost:" + serverAddress + "\r\nUser-Agent:test\r\n\r\n"
	conn, err := net.DialTimeout("tcp", serverAddress, time.Second*30)
	s.AssertNil(err, fmt.Sprint(err))
	defer conn.Close()
	err = conn.SetDeadline(time.Now().Add(time.Second * 30))
	s.AssertNil(err, fmt.Sprint(err))
	_, err = conn.Write([]byte(req))
	s.AssertNil(err, fmt.Sprint(err))
	reply := make([]byte, 1024)
	_, err = conn.Read(reply)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(string(reply), "HTTP/1.1 200 OK")
	s.Log(vpp.Vppctl("show session verbose 2"))

	s.Log("waiting for close on the server side")
	time.Sleep(time.Second * 5)
	s.Log(vpp.Vppctl("show session verbose 2"))

	_, err = conn.Write([]byte(req))
	s.AssertNil(err, fmt.Sprint(err))
	reply = make([]byte, 1024)
	_, err = conn.Read(reply)
	s.AssertMatchError(err, io.EOF, "connection not closed by server")
	o := vpp.Vppctl("show http stats")
	s.Log(o)
	s.AssertContains(o, "1 connections timeout")
}

func HttpIgnoreH2UpgradeTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers"))

	transport := http.DefaultTransport
	transport.(*http.Transport).Proxy = nil
	transport.(*http.Transport).DisableKeepAlives = false
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Second * 30,
	}

	req, err := http.NewRequest("GET", "http://"+serverAddress+"/version.json", nil)
	s.AssertNil(err, fmt.Sprint(err))
	req.Header.Add("Connection", "Upgrade")
	req.Header.Add("Upgrade", "HTTP/2.0")
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, true))
	s.AssertHttpStatus(resp, 200)
	s.AssertHttpHeaderNotPresent(resp, "Upgrade")
}

func HttpSendGetAndCloseTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http

	vpp.Container.Exec(false, "mkdir -p "+wwwRootPath)
	content := "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	err := vpp.Container.CreateFile(wwwRootPath+"/index.html", content)
	s.AssertNil(err, fmt.Sprint(err))
	s.Log(vpp.Vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress + " private-segment-size 256m"))

	err = TcpSendAndClose(serverAddress, "GET http://www.example.com/index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))

	// mostly to verify that vpp is still up
	o := vpp.Vppctl("show session verbose proto http")
	s.Log(o)
	s.AssertNotContains(o, "established")
}
