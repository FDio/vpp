package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/http2"

	"github.com/onsi/gomega/ghttp"
	"github.com/onsi/gomega/gmeasure"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterVethTests(HttpCliTest, HttpCliConnectErrorTest, HttpCliConnectNoRouteTest,
		HttpCliListenTcpPortInUseTest, HttpCliTlsTest, HttpCliEchoTest)
	RegisterSoloVethTests(HttpClientGetMemLeakTest)
	RegisterHttp1Tests(HeaderServerTest, HttpPersistentConnectionTest, HttpPipeliningTest,
		HttpCliMethodNotAllowedTest, HttpAbsoluteFormUriTest, HttpCliBadRequestTest,
		HttpInvalidRequestLineTest, HttpIncrementalRequestLineTest, HttpFragmentedH2PrefaceTest, HttpMethodNotImplementedTest, HttpInvalidHeadersTest, HttpMissingHostHeaderTest,
		HttpContentLengthTest, HttpVersionNotSupportedTest, HttpInvalidContentLengthTest, HttpInvalidTargetSyntaxTest, HttpUriDecodeTest,
		HttpHeadersTest, HttpClientTest, HttpClientErrRespTest, HttpClientPostFormTest, HttpClientPostFormPtrTest,
		HttpClientGet128kbResponseTest, HttpClientGetResponseBodyTest, HttpClientGetTlsNoRespBodyTest, HttpClientPostFileTest, HttpClientPostFilePtrTest,
		HttpRequestLineTest, HttpClientGetTimeout, HttpConnTimeoutTest, HttpClientGetRepeatTest, HttpClientPostRepeatTest,
		HttpIgnoreH2UpgradeTest, HttpInvalidAuthorityFormUriTest, HttpHeaderErrorConnectionDropTest,
		HttpClientInvalidHeaderNameTest, HttpTimerSessionDisable, HttpClientBodySizeTest, HttpClientResponseLengthOverflowTest,
		HttpCliSmallRxFifoReplyTest, HttpCliFragmentedReplyTest, HttpContentLengthLongerBodyTest,
		HttpCliClientGetBodyTest, HttpCliClientGetBodyPtrTest,
		HttpCliClientPostBodyTest, HttpCliClientPostBodyPtrTest,
		HttpCliClientPutBodyTest, HttpCliClientPutBodyPtrTest,
		HttpCliClientEmptyBodyTest, HttpCliClientNoHeadersTest,
		HttpCliClientHeadersTest, HttpCliClientLargeHeadersRejectedTest, HttpCliServerEchoTest,
		HttpCliClientStreamGetTest, HttpCliClientStreamPostTest, HttpCliClientStreamPutTest, HttpCliClientStreamTlsTest,
		HttpCliClientStreamEmptyTest, HttpCliClientStreamDrainTest, HttpCliClientStreamCloseTest,
		HttpCliClientStreamEarlyResponseTest, HttpCliClientEarlyResponseFinTest, HttpCliClientStreamWireTest,
		HttpCliClientChunkedTest, HttpCliClientChunkedFragmentedTest, HttpCliClientChunkedTrailersTest,
		HttpCliClientChunkedBackpressureTest, HttpCliClientChunkedHalfCloseTest,
		HttpCliClientChunkedBadFramingTest, HttpCliClientChunkedHeadersTest,
		HttpCliClientChunkedTlsTest, HttpCliClientChunkedEarlyResponseTest,
		HttpCliServerStreamTest, HttpCliServerStreamCloseTest, HttpCliServerStreamDrainTest,
		HttpCliServerStreamBackpressureTest, HttpCliServerStreamTlsTest,
		HttpCliServerChunkedTest, HttpCliServerChunkedFragmentedTest, HttpCliServerChunkedTrailersTest,
		HttpCliServerChunkedBackpressureTest, HttpCliServerChunkedHalfCloseTest, HttpCliServerChunkedLargeFifoTest,
		HttpCliServerChunkedBadFramingTest, HttpCliServerChunkedHeadersTest,
		HttpCliServerChunkedResetBeforeAcceptTest,
		HttpCliServerChunkedEarlyReplyTest, HttpCliServerChunkedCliTest, HttpCliServerChunkedTlsTest,
		HttpCliServerChunkedCurlUploadTest, HttpCliServerChunkedCurlDownloadTest,
		HttpClientNoPrintTest, HttpClientChunkedDownloadTest, HttpClientChunkedBodyTest, HttpClientChunkedRedirectTest,
		HttpClientPutStreamingTest, HttpClientPostRejectedTest,
		HttpClientRedirect302Test, HttpClientRedirect308Test, HttpSendGetAndCloseTest, HttpClientRedirectLimitTest, HttpClientRedirectGetMemLeakTest,
		HttpClientRedirectPostMemLeakTest, HttpGetTpsTest, HttpPostTpsTest, HttpGetTpsInterruptModeTest, HttpPostTpsInterruptModeTest,
		HttpPostTpsTlsTest, HttpGetTpsTlsTest, HttpTpsTest,
		HttpFragmentedHeadersTest, HttpClientFragmentedHeadersTest, HttpClientPartialResponseFinTest,
		HttpPartialRequestPeerResetTest, HttpPartialRequestPeerFinTest, HttpPartialRequestListenerRemovedTest,
		HttpIncompleteHeadersFullFifoTest, HttpClientIncompleteHeadersFullFifoTest,
		HttpIncompleteHeadersTimeoutTest)
	var headerLimitConfig Stanza
	headerLimitConfig.NewStanza("http").NewStanza("http1").Append("max-header-list-size 128").Close().Close()
	RegisterHttp1TestsWithConfig(headerLimitConfig, HttpHeaderListSizeLimitTest)
	var largeHeaderLimitConfig Stanza
	largeHeaderLimitConfig.NewStanza("http").NewStanza("http1").Append("max-header-list-size 131072").Close().Close()
	RegisterHttp1TestsWithConfig(largeHeaderLimitConfig, HttpOversizedHeaderNameTest)
	RegisterHttp1SoloTests(HttpClientPostMemLeakTest, HttpInvalidClientRequestMemLeakTest, HttpTpsMemLeakTest)
	RegisterHttp1MWTests(HttpClientGetRepeatMWTest, HttpClientPtrGetRepeatMWTest, HttpTsFifoMemPressureMWTest)
	RegisterNoTopo6SoloTests(HttpClientGetResponseBody6Test, HttpClientGetTlsResponseBody6Test)
}

const wwwRootPath = "/tmp/www_root"
const defaultHttpTimeout = time.Second * 10

// helper interface for ip4/6 HttpClientGet tests
type httpClientGetInterface interface {
	HostAddr() string
	LogHttpReq(bool) http.HandlerFunc
}

func httpDownloadBenchmark(experiment *gmeasure.Experiment, data any) {
	url, isValid := data.(string)
	AssertEqual(true, isValid)
	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", url, nil)
	AssertNil(err, fmt.Sprint(err))
	t := time.Now()
	resp, err := client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	AssertHttpStatus(resp, 200)
	_, err = io.ReadAll(resp.Body)
	AssertNil(err, fmt.Sprint(err))
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

	vpp.Vppctl("http tps uri http://%s", serverAddress)

	s.RunBenchmark("HTTP tps download 10M", 10, 0, httpDownloadBenchmark, url)
}

func HttpGetTpsTlsTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	url := "https://" + serverAddress + "/test_file_10M"

	vpp.Vppctl("http tps uri https://%s", serverAddress)

	s.RunBenchmark("HTTP tps download 10M", 10, 0, httpDownloadBenchmark, url)
}

func httpUploadBenchmark(experiment *gmeasure.Experiment, data any) {
	url, isValid := data.(string)
	AssertEqual(true, isValid)
	body := make([]byte, 10485760)
	_, err := rand.Read(body)
	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	AssertNil(err, fmt.Sprint(err))
	t := time.Now()
	resp, err := client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	AssertHttpStatus(resp, 200)
	_, err = io.ReadAll(resp.Body)
	AssertNil(err, fmt.Sprint(err))
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

	vpp.Vppctl("http tps uri http://%s", serverAddress)

	s.RunBenchmark("HTTP tps upload 10M", 10, 0, httpUploadBenchmark, url)
}

func HttpPostTpsTlsTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	url := "https://" + serverAddress + "/test_file_10M"

	vpp.Vppctl("http tps uri https://%s", serverAddress)

	s.RunBenchmark("HTTP tps upload 10M", 10, 0, httpUploadBenchmark, url)
}

func HttpPersistentConnectionTest(s *Http1Suite) {
	// testing url handler app do not support multi-thread
	s.SkipIfMultiWorker()
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers"))
	Log(vpp.Vppctl("test-url-handler enable"))

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
	AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	Log(DumpHttpResp(resp, true))
	AssertHttpStatus(resp, 200)
	AssertEqual(false, resp.Close)
	AssertHttpContentLength(resp, int64(0))
	o1 := vpp.Vppctl("show session verbose proto http state ready")
	Log(o1)
	AssertContains(o1, "established")

	req, err = http.NewRequest("GET", "http://"+serverAddress+"/test1", nil)
	AssertNil(err, fmt.Sprint(err))
	clientTrace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			AssertEqual(true, info.Reused, "connection not reused")
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), clientTrace))
	resp, err = client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	Log(DumpHttpResp(resp, true))
	AssertHttpStatus(resp, 200)
	AssertEqual(false, resp.Close)
	AssertHttpBody(resp, "hello")
	o2 := vpp.Vppctl("show session verbose proto http state ready")
	Log(o2)
	AssertContains(o2, "established")
	AssertEqual(o1, o2)

	req, err = http.NewRequest("GET", "http://"+serverAddress+"/test2", nil)
	AssertNil(err, fmt.Sprint(err))
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), clientTrace))
	resp, err = client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	Log(DumpHttpResp(resp, true))
	AssertHttpStatus(resp, 200)
	AssertEqual(false, resp.Close)
	AssertHttpBody(resp, "some data")
	o2 = vpp.Vppctl("show session verbose proto http state ready")
	Log(o2)
	AssertContains(o2, "established")
	AssertEqual(o1, o2)
}

func HttpPipeliningTest(s *Http1Suite) {
	// testing url handler app do not support multi-thread
	s.SkipIfMultiWorker()
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers debug"))
	Log(vpp.Vppctl("test-url-handler enable"))

	req1 := "GET /test_delayed HTTP/1.1\r\nHost:" + serverAddress + "\r\nUser-Agent:test\r\n\r\n"
	req2 := "GET /test1 HTTP/1.1\r\nHost:" + serverAddress + "\r\nUser-Agent:test\r\n\r\n"

	conn, err := net.DialTimeout("tcp", serverAddress, time.Second*30)
	AssertNil(err, fmt.Sprint(err))
	defer conn.Close()
	err = conn.SetDeadline(time.Now().Add(time.Second * 15))
	AssertNil(err, fmt.Sprint(err))
	n, err := conn.Write([]byte(req1))
	AssertNil(err, fmt.Sprint(err))
	AssertEqual(n, len([]rune(req1)))
	// send second request a bit later so first is already in progress
	time.Sleep(500 * time.Millisecond)
	n, err = conn.Write([]byte(req2))
	AssertNil(err, fmt.Sprint(err))
	AssertEqual(n, len([]rune(req2)))
	reply := make([]byte, 1024)
	_, err = conn.Read(reply)
	AssertNil(err, fmt.Sprint(err))
	Log(string(reply))
	AssertContains(string(reply), "delayed data", "first request response not received")
	AssertNotContains(string(reply), "hello", "second request response received")
	// make sure response for second request is not received later
	_, err = conn.Read(reply)
	AssertMatchError(err, os.ErrDeadlineExceeded, "second request response received")
}

func HttpCliTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1

	cliServerCmd := "http cli server uri http://" + serverAddress
	s.Containers.ServerVpp.VppInstance.Vppctl(cliServerCmd)

	o := s.Containers.ClientVpp.VppInstance.Vppctl("http cli client" +
		" uri http://" + serverAddress + "/show/vlib/graph")

	Log(o)
	AssertContains(o, "<html>", "<html> not found in the result!")
	AssertContains(o, "</html>", "</html> not found in the result!")

	/* test client session cleanup */
	clientCleanupDone := false
	for range 30 {
		o := s.Containers.ClientVpp.VppInstance.Vppctl("show session verbose 2")
		if !strings.Contains(o, "->"+serverAddress) {
			clientCleanupDone = true
			break
		}
		time.Sleep(1 * time.Second)
	}
	AssertEqual(true, clientCleanupDone)

	/* test server app stop listen */
	s.Containers.ServerVpp.VppInstance.Vppctl(cliServerCmd + " listener del")
	o = s.Containers.ServerVpp.VppInstance.Vppctl("show session verbose proto http")
	AssertNotContains(o, "LISTEN")

	o = s.Containers.ClientVpp.VppInstance.Vppctl("show http stats")
	Log(o)
	AssertContains(o, "1 connections established")
	AssertContains(o, "1 requests sent")
	AssertContains(o, "1 responses received")
	o = s.Containers.ServerVpp.VppInstance.Vppctl("show http stats")
	Log(o)
	AssertContains(o, "1 connections accepted")
	AssertContains(o, "1 requests received")
	AssertContains(o, "1 responses sent")
}

func HttpCliTlsTest(s *VethsSuite) {
	uri := "https://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1

	s.Containers.ServerVpp.VppInstance.Vppctl("http cli server http1-only uri " + uri)

	o := s.Containers.ClientVpp.VppInstance.Vppctl("http cli client" +
		" uri " + uri + "/show/version")
	Log(o)
	AssertContains(o, "<html>", "<html> not found in the result!")
	AssertContains(o, "</html>", "</html> not found in the result!")

	/* second request to test postponed ho-cleanup */
	o = s.Containers.ClientVpp.VppInstance.Vppctl("http cli client" +
		" uri " + uri + "/show/version")
	Log(o)
	AssertContains(o, "<html>", "<html> not found in the result!")
	AssertContains(o, "</html>", "</html> not found in the result!")
}

func HttpCliConnectErrorTest(s *VethsSuite) {
	uri := "http://" + s.Interfaces.Server.Ip4AddressString() + "/80"

	o := s.Containers.ClientVpp.VppInstance.Vppctl("http cli client" +
		" uri " + uri + "/show/vlib/graph")

	Log(o)
	AssertContains(o, "failed to connect")
}

func HttpCliConnectNoRouteTest(s *VethsSuite) {
	uri := "http://198.51.100.1/no/route"

	o := s.Containers.ClientVpp.VppInstance.Vppctl("http cli client uri " + uri)

	Log(o)
	AssertContains(o, "failed to connect")
}

func HttpCliListenTcpPortInUseTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	conflictAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port2
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("http cli server uri http://" + serverAddress)
	serverVpp.Vppctl("vperf server uri tcp://" +
		s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port2)

	o := serverVpp.Vppctl("http cli server listener add uri http://" + conflictAddress)

	Log(o)
	AssertContains(o, "failed to start listening")
}

func httpCliTestServer(s *Http1Suite) (*ghttp.Server, string) {
	address := net.JoinHostPort(s.HostAddr(), s.Ports.Http)
	listener, err := net.Listen("tcp", address)
	AssertNil(err)
	server := ghttp.NewUnstartedServer()
	server.HTTPTestServer.Listener = listener
	return server, address
}

func httpCliVerifyRequest(method, target, address, body string, headers http.Header, accept bool) http.HandlerFunc {
	return ghttp.CombineHandlers(
		ghttp.VerifyRequest(method, target),
		ghttp.VerifyHeader(headers),
		ghttp.VerifyBody([]byte(body)),
		func(w http.ResponseWriter, r *http.Request) {
			AssertEqual("HTTP/1.1", r.Proto)
			AssertEqual(address, r.Host)
			AssertEqual("http_cli_client", r.UserAgent())
			AssertEmpty(r.TransferEncoding)
			AssertEqual(int64(len(body)), r.ContentLength)
			if len(body) > 0 || method != "GET" {
				AssertEqual(strconv.Itoa(len(body)), r.Header.Get("Content-Length"))
			} else {
				AssertEmpty(r.Header.Get("Content-Length"))
			}
			if accept {
				AssertEqual("text/html", r.Header.Get("Accept"))
			} else {
				AssertEmpty(r.Header.Get("Accept"))
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			_, err := io.WriteString(w, body)
			AssertNil(err)
		},
	)
}

func httpCliClientBodyTest(s *Http1Suite, method string, usePtr bool) {
	vpp := s.Containers.Vpp.VppInstance
	body := strings.Repeat("0123456789AbCdEf", 8*1024)
	file := "/tmp/http-cli-body.txt"
	AssertNil(vpp.Container.CreateFile(file, body))
	server, address := httpCliTestServer(s)
	server.AppendHandlers(httpCliVerifyRequest(method, "/echo", address, body,
		http.Header{"X-Test": {"body"}}, true))
	server.Start()
	defer server.Close()
	options := ""
	if usePtr {
		options = " use-ptr"
	}
	output := vpp.Vppctl("http cli client method %s file %s fifo-size 4 header X-Test:body%s uri http://%s/echo",
		strings.ToLower(method), file, options, address)
	AssertEqual(body, strings.TrimSpace(output))
	AssertEqual(1, len(server.ReceivedRequests()))
}

func HttpCliClientGetBodyTest(s *Http1Suite) {
	httpCliClientBodyTest(s, "GET", false)
}
func HttpCliClientGetBodyPtrTest(s *Http1Suite) {
	httpCliClientBodyTest(s, "GET", true)
}
func HttpCliClientPostBodyTest(s *Http1Suite) {
	httpCliClientBodyTest(s, "POST", false)
}
func HttpCliClientPostBodyPtrTest(s *Http1Suite) {
	httpCliClientBodyTest(s, "POST", true)
}
func HttpCliClientPutBodyTest(s *Http1Suite) {
	httpCliClientBodyTest(s, "PUT", false)
}
func HttpCliClientPutBodyPtrTest(s *Http1Suite) {
	httpCliClientBodyTest(s, "PUT", true)
}

func HttpCliClientEmptyBodyTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	AssertNil(vpp.Container.CreateFile("/tmp/http-cli-empty.txt", ""))
	server, address := httpCliTestServer(s)
	for range 2 {
		for _, method := range []string{"GET", "POST"} {
			server.AppendHandlers(httpCliVerifyRequest(method, "/echo", address, "", nil, true))
		}
		server.AppendHandlers(httpCliVerifyRequest("POST", "/echo", address, "", nil, true))
	}
	server.Start()
	defer server.Close()
	for _, options := range []string{"", "use-ptr"} {
		for _, method := range []string{"get", "post"} {
			output := vpp.Vppctl("http cli client method %s %s uri http://%s/echo", method, options, address)
			AssertEmpty(strings.TrimSpace(output))
		}
		output := vpp.Vppctl("http cli client method post file /tmp/http-cli-empty.txt %s uri http://%s/echo", options, address)
		AssertEmpty(strings.TrimSpace(output))
		output = vpp.Vppctl("http cli client method put %s uri http://%s/echo", options, address)
		AssertContains(output, "transport closed")
	}
	AssertEqual(6, len(server.ReceivedRequests()))
}

func HttpCliClientNoHeadersTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	server, address := httpCliTestServer(s)
	for range 2 {
		server.AppendHandlers(httpCliVerifyRequest("GET", "/echo", address, "", nil, false))
		server.AppendHandlers(httpCliVerifyRequest("POST", "/echo", address, "no-headers-body", nil, false))
	}
	server.Start()
	defer server.Close()
	for _, options := range []string{"", "use-ptr"} {
		output := vpp.Vppctl("http cli client no-headers %s uri http://%s/echo", options, address)
		AssertEmpty(strings.TrimSpace(output))
		output = vpp.Vppctl("http cli client method post data no-headers-body no-headers %s uri http://%s/echo", options, address)
		AssertEqual("no-headers-body", strings.TrimSpace(output))
	}
	AssertEqual(4, len(server.ReceivedRequests()))
}

func HttpCliClientHeadersTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	target := "/" + strings.Repeat("long-target-", 128)
	value := strings.Repeat("header-value-", 128)
	body := "body-after-headers"
	server, address := httpCliTestServer(s)
	for range 2 {
		server.AppendHandlers(httpCliVerifyRequest("POST", target, address, body,
			http.Header{"X-First": {value}, "X-Second": {"second"}, "X-Last": {"last"}}, true))
	}
	server.Start()
	defer server.Close()
	for _, options := range []string{"", "use-ptr"} {
		output := vpp.Vppctl("http cli client method post data %s fifo-size 4 header X-First:%s header X-Second:second header X-Last:last %s uri http://%s%s",
			body, value, options, address, target)
		AssertEqual(body, strings.TrimSpace(output))
	}
	AssertEqual(2, len(server.ReceivedRequests()))
}

func HttpCliClientLargeHeadersRejectedTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	server, address := httpCliTestServer(s)
	server.Start()
	defer server.Close()
	command := fmt.Sprintf("http cli client use-ptr header X-Large:%s uri http://%s/echo\n",
		strings.Repeat("x", 600*1024), address)
	AssertNil(vpp.Container.CreateFile("/tmp/http-cli-large-header.cli", command))
	output := vpp.Vppctl("exec /tmp/http-cli-large-header.cli")
	AssertContains(output, "CLI line error")
	AssertContains(vpp.Vppctl("show http stats"), "1 connections protocol error")
	AssertEmpty(server.ReceivedRequests())
	server.AppendHandlers(httpCliVerifyRequest("GET", "/echo", address, "", nil, true))
	output = vpp.Vppctl("http cli client uri http://%s/echo", address)
	AssertEmpty(strings.TrimSpace(output))
	AssertEqual(1, len(server.ReceivedRequests()))
}

func HttpCliServerEchoTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	vpp.Vppctl("http cli server fifo-size 4 uri http://" + address)
	client := NewHttpClient(defaultHttpTimeout, false)
	defer client.CloseIdleConnections()
	for _, method := range []string{"GET", "POST", "PUT"} {
		for _, body := range []string{"", strings.Repeat("0123456789AbCdEf", 8*1024)} {
			request, err := http.NewRequest(method, "http://"+address+"/echo", bytes.NewBufferString(body))
			AssertNil(err)
			response, err := client.Do(request)
			AssertNil(err)
			AssertHttpStatus(response, http.StatusOK)
			AssertHttpContentLength(response, int64(len(body)))
			data, err := io.ReadAll(response.Body)
			AssertNil(err)
			AssertNil(response.Body.Close())
			AssertEqual(body, string(data))
		}
	}
}

// Streaming bodies deliberately advertise no body length to the transport.
func httpCliClientStreamTest(s *Http1Suite, method, body, options string, secure bool) {
	vpp := s.Containers.Vpp.VppInstance
	file := "/tmp/http-cli-stream.txt"
	AssertNil(vpp.Container.CreateFile(file, body))
	address := net.JoinHostPort(s.HostAddr(), s.Ports.Http)
	protocol := "http"
	if secure {
		protocol = "https"
	}
	server := golangServer(address, protocol)
	server.AppendHandlers(func(w http.ResponseWriter, r *http.Request) {
		AssertEqual(method, r.Method)
		AssertEqual("/echo", r.URL.Path)
		AssertEqual(address, r.Host)
		AssertEqual("http_cli_client", r.UserAgent())
		AssertEqual("stream", r.Header.Get("X-Test"))
		AssertEqual([]string{"chunked"}, r.TransferEncoding)
		AssertEqual(int64(-1), r.ContentLength)
		AssertEmpty(r.Header.Get("Content-Length"))
		AssertEqual(true, r.Close)
		started := time.Now()
		data, err := io.ReadAll(r.Body)
		AssertNil(err)
		AssertEqual(body, string(data))
		AssertEmpty(r.Trailer)
		if strings.Contains(options, "tx-delay") {
			AssertEqual(true, time.Since(started) >= 20*time.Millisecond)
		}
		// A response body larger than the app FIFO also verifies RX after shutdown.
		reply := "stream-complete:" + body
		w.Header().Set("Content-Length", strconv.Itoa(len(reply)))
		_, err = io.WriteString(w, reply)
		AssertNil(err)
	})
	server.Start()
	defer server.Close()
	output := vpp.Vppctl("http cli client stream method %s file %s fifo-size 4 header X-Test:stream %s uri %s://%s/echo",
		strings.ToLower(method), file, options, protocol, address)
	AssertEqual("stream-complete:"+body, strings.TrimSpace(output))
	AssertEqual(1, len(server.ReceivedRequests()))
}

func HttpCliClientStreamGetTest(s *Http1Suite) {
	httpCliClientStreamTest(s, "GET", strings.Repeat("stream-get-body!", 8192), "", false)
}

func HttpCliClientStreamPostTest(s *Http1Suite) {
	httpCliClientStreamTest(s, "POST", strings.Repeat("stream-post-body", 8192), "", false)
}

func HttpCliClientStreamPutTest(s *Http1Suite) {
	httpCliClientStreamTest(s, "PUT", strings.Repeat("stream-put-body!", 8192), "", false)
}

func HttpCliClientStreamEmptyTest(s *Http1Suite) {
	for _, method := range []string{"GET", "POST", "PUT"} {
		for _, options := range []string{"", "eof-after-drain"} {
			httpCliClientStreamTest(s, method, "", options, false)
		}
	}
}

func HttpCliClientStreamDrainTest(s *Http1Suite) {
	httpCliClientStreamTest(s, "POST", strings.Repeat("delayed-stream!", 8192),
		"eof-after-drain tx-delay 0.01", false)
}

func HttpCliClientStreamTlsTest(s *Http1Suite) {
	httpCliClientStreamTest(s, "POST", strings.Repeat("tls-stream-body!", 8192), "eof-after-drain", true)
}

func HttpCliClientStreamCloseTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	for _, body := range []string{"", strings.Repeat("close-stream!", 8192)} {
		AssertNil(vpp.Container.CreateFile("/tmp/http-cli-stream-close.txt", body))
		server, address := httpCliTestServer(s)
		received := make(chan struct{})
		server.AppendHandlers(func(w http.ResponseWriter, r *http.Request) {
			AssertEqual([]string{"chunked"}, r.TransferEncoding)
			data, err := io.ReadAll(r.Body)
			AssertNil(err)
			AssertEqual(body, string(data))
			close(received)
			w.Header().Set("Content-Length", "0")
		})
		server.Start()
		output := vpp.Vppctl("http cli client stream close-after-tx method put file /tmp/http-cli-stream-close.txt fifo-size 4 uri http://%s/echo", address)
		AssertContains(output, "transport closed")
		select {
		case <-received:
		case <-time.After(defaultHttpTimeout):
			AssertEqual(true, false, "server did not receive the complete stream")
		}
		server.Close()
	}
}

func HttpCliClientStreamEarlyResponseTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	AssertNil(vpp.Container.CreateFile("/tmp/http-cli-stream-reject.txt", strings.Repeat("x", 1024*1024)))
	server, address := httpCliTestServer(s)
	server.AppendHandlers(func(w http.ResponseWriter, r *http.Request) {
		AssertEqual([]string{"chunked"}, r.TransferEncoding)
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		w.(http.Flusher).Flush()
	})
	server.Start()
	defer server.Close()
	output := vpp.Vppctl("http cli client stream method post file /tmp/http-cli-stream-reject.txt fifo-size 4 tx-delay 0.01 uri http://%s/echo", address)
	AssertContains(output, "request failed, response code: 413")
}

// An early response abandons the upload without marking the HTTP connection
// closed. FIN must still reach the app after a truncated response is drained.
func HttpCliClientEarlyResponseFinTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	upload := strings.Repeat("x", 1024*1024)
	file := "/tmp/http-cli-early-response.txt"
	AssertNil(vpp.Container.CreateFile(file, upload))
	for _, stream := range []bool{false, true} {
		for _, body := range []string{"", "early-response", strings.Repeat("response!", 2048)} {
			for _, missing := range []int{0, 1} {
				for _, fragmented := range []bool{false, true} {
					Log("early response: stream=%t, body=%d, missing=%d, fragmented=%t",
						stream, len(body), missing, fragmented)
					func() {
						listener, err := net.Listen("tcp", net.JoinHostPort(s.HostAddr(), s.Ports.Http))
						AssertNil(err)
						defer listener.Close()
						AssertNil(listener.(*net.TCPListener).SetDeadline(time.Now().Add(defaultHttpTimeout)))
						finished := make(chan error, 1)
						clientFinished := make(chan struct{})
						go func() {
							finished <- func() error {
								conn, err := listener.Accept()
								if err != nil {
									return err
								}
								defer conn.Close()
								if err = conn.(*net.TCPConn).SetReadBuffer(4096); err != nil {
									return err
								}
								if err = conn.SetDeadline(time.Now().Add(defaultHttpTimeout)); err != nil {
									return err
								}
								reader := bufio.NewReader(conn)
								request, err := http.ReadRequest(reader)
								if err != nil {
									return err
								}
								if stream && (len(request.TransferEncoding) != 1 || request.TransferEncoding[0] != "chunked") {
									return fmt.Errorf("expected a streamed upload, got %v", request.TransferEncoding)
								}
								if !stream && request.ContentLength != int64(len(upload)) {
									return fmt.Errorf("unexpected upload length %d", request.ContentLength)
								}
								headers := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(body)+missing)
								parts := []string{headers + body}
								if fragmented {
									parts = []string{"HTTP/1.1 200 OK\r\nContent-Len",
										fmt.Sprintf("gth: %d\r\n\r\n", len(body)+missing) + body[:len(body)/2]}
									if len(body) != 0 {
										parts = append(parts, body[len(body)/2:])
									}
								}
								// Respond before consuming the request body. Keep the read
								// direction open after FIN to avoid resetting unread uploads.
								for i, part := range parts {
									if _, err = io.WriteString(conn, part); err != nil {
										return err
									}
									if i < len(parts)-1 {
										time.Sleep(100 * time.Millisecond)
									}
								}
								if err = conn.(*net.TCPConn).CloseWrite(); err != nil {
									return err
								}
								// Drain while the client handles FIN, then stop cleanup
								// independently of upload-side TCP completion.
								go func() {
									<-clientFinished
									conn.Close()
								}()
								n, err := io.Copy(io.Discard, reader)
								if err != nil && !errors.Is(err, syscall.ECONNRESET) && !errors.Is(err, net.ErrClosed) {
									return err
								}
								if n >= int64(len(upload)) {
									return fmt.Errorf("response did not interrupt the upload: received %d bytes", n)
								}
								return nil
							}()
						}()
						options := ""
						if stream {
							options = "stream tx-delay 0.01"
						}
						started := time.Now()
						output := vpp.Vppctl("http cli client %s method post file %s fifo-size 4 uri http://%s/test",
							options, file, listener.Addr().String())
						elapsed := time.Since(started)
						close(clientFinished)
						AssertNil(<-finished)
						AssertNotContains(output, "timeout")
						AssertEqual(true, elapsed < defaultHttpTimeout/2, "FIN must close the reply before its timeout")
						if missing != 0 {
							AssertContains(output, "transport closed")
						} else {
							AssertEqual(body, strings.TrimSpace(output))
						}
					}()
				}
			}
		}
	}
	AssertNotContains(vpp.Vppctl("show http stats"), "connections timeout")
}

func HttpCliClientStreamWireTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	address := net.JoinHostPort(s.HostAddr(), s.Ports.Http)
	listener, err := net.Listen("tcp", address)
	AssertNil(err)
	defer listener.Close()
	finished := make(chan error, 1)
	body := strings.Repeat("wire-stream!", 8192)
	AssertNil(vpp.Container.CreateFile("/tmp/http-cli-stream-wire.txt", body))
	go func() {
		finished <- func() error {
			conn, err := listener.Accept()
			if err != nil {
				return err
			}
			defer conn.Close()
			if err = conn.SetDeadline(time.Now().Add(defaultHttpTimeout)); err != nil {
				return err
			}
			reader := bufio.NewReader(conn)
			request, err := http.ReadRequest(reader)
			if err != nil {
				return err
			}
			data, err := io.ReadAll(request.Body)
			if err != nil {
				return err
			}
			if string(data) != body {
				return fmt.Errorf("streamed request body differs")
			}
			if _, err = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"); err != nil {
				return err
			}
			// Extra terminal chunks must not appear after the decoded body.
			if b, err := reader.ReadByte(); err != io.EOF {
				return fmt.Errorf("expected connection EOF after request, got %q, %v", b, err)
			}
			return nil
		}()
	}()
	output := vpp.Vppctl("http cli client stream method put file /tmp/http-cli-stream-wire.txt fifo-size 4 uri http://%s/echo", address)
	AssertEqual("OK", strings.TrimSpace(output))
	AssertNil(<-finished)
}

// Keep the peer open after the response: completion must follow the terminating
// chunk, and the client must close without sending an HTTP error to the server.
func httpCliClientRawReply(s *Http1Suite, command string, reply func(*net.TCPConn) error) string {
	listener, err := net.Listen("tcp", net.JoinHostPort(s.HostAddr(), s.Ports.Http))
	AssertNil(err)
	defer listener.Close()
	finished := make(chan error, 1)
	go func() {
		finished <- func() error {
			conn, err := listener.Accept()
			if err != nil {
				return err
			}
			defer conn.Close()
			if err = conn.SetDeadline(time.Now().Add(defaultHttpTimeout)); err != nil {
				return err
			}
			reader := bufio.NewReader(conn)
			request, err := http.ReadRequest(reader)
			if err != nil {
				return err
			}
			if _, err = io.Copy(io.Discard, request.Body); err != nil {
				return err
			}
			if err = reply(conn.(*net.TCPConn)); err != nil {
				return err
			}
			if b, err := reader.ReadByte(); err != io.EOF {
				return fmt.Errorf("expected client EOF, got %q, %v", b, err)
			}
			return nil
		}()
	}()
	output := s.Containers.Vpp.VppInstance.Vppctl("%s uri http://%s/test", command, listener.Addr().String())
	AssertNil(<-finished)
	return output
}

const httpCliChunkedResponseHeaders = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n"

func HttpCliClientChunkedTest(s *Http1Suite) {
	for _, method := range []string{"get", "post", "put"} {
		for _, body := range []string{"", "small-response", strings.Repeat("chunked-response!", 8192)} {
			output := httpCliClientRawReply(s, "http cli client fifo-size 4 data request method "+method, func(conn *net.TCPConn) error {
				_, err := io.WriteString(conn, httpCliChunkedResponseHeaders+httpCliChunkedBody(body))
				return err
			})
			AssertEqual(body, strings.TrimSpace(output))
		}
	}
}

func HttpCliClientChunkedFragmentedTest(s *Http1Suite) {
	output := httpCliClientRawReply(s, "http cli client fifo-size 4", func(conn *net.TCPConn) error {
		if _, err := io.WriteString(conn, httpCliChunkedResponseHeaders); err != nil {
			return err
		}
		for _, b := range []byte("3;ext=token;quoted=\"a\\\"b\"\r\none\r\n3\r\ntwo\r\n0;end=yes\r\nX-Trailer: discarded\r\n\r\n") {
			if _, err := conn.Write([]byte{b}); err != nil {
				return err
			}
			time.Sleep(time.Millisecond)
		}
		return nil
	})
	AssertEqual("onetwo", strings.TrimSpace(output))
}

func HttpCliClientChunkedTrailersTest(s *Http1Suite) {
	output := httpCliClientRawReply(s, "http cli client fifo-size 4", func(conn *net.TCPConn) error {
		if _, err := io.WriteString(conn, httpCliChunkedResponseHeaders+"2\r\nOK\r\n0\r\nX-Trailer: discarded\r\n"); err != nil {
			return err
		}
		// Neither zero chunk nor trailer field completes the message
		if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			return err
		}
		var b [1]byte
		if _, err := conn.Read(b[:]); err == nil {
			return fmt.Errorf("client sent data before trailer completion")
		} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
			return fmt.Errorf("client closed before trailer completion: %v", err)
		}
		if err := conn.SetReadDeadline(time.Now().Add(defaultHttpTimeout)); err != nil {
			return err
		}
		_, err := io.WriteString(conn, "\r\n")
		return err
	})
	AssertEqual("OK", strings.TrimSpace(output))
}

func HttpCliClientChunkedBackpressureTest(s *Http1Suite) {
	body := strings.Repeat("backpressure-response!", 128*1024)
	for _, fifoSize := range []string{"4", "1024"} {
		output := httpCliClientRawReply(s, "http cli client fifo-size "+fifoSize, func(conn *net.TCPConn) error {
			_, err := io.WriteString(conn, httpCliChunkedResponseHeaders+httpCliChunkedBody(body))
			return err
		})
		AssertEqual(body, strings.TrimSpace(output))
	}
}

func HttpCliClientChunkedHalfCloseTest(s *Http1Suite) {
	for _, body := range []string{"", strings.Repeat("pending-at-fin!", 8192)} {
		output := httpCliClientRawReply(s, "http cli client fifo-size 4", func(conn *net.TCPConn) error {
			if _, err := io.WriteString(conn, httpCliChunkedResponseHeaders+httpCliChunkedBody(body)); err != nil {
				return err
			}
			return conn.CloseWrite()
		})
		AssertEqual(body, strings.TrimSpace(output))
	}
}

func HttpCliClientChunkedBadFramingTest(s *Http1Suite) {
	for _, body := range []string{
		"g\r\n", "10000000000000000\r\n", "1\r\nx!", "0\r\nBad Trailer\r\n\r\n",
		"1;" + strings.Repeat("x", 8192) + "\r\n",
		"", "1\r\n", "1\r\nx", "1\r\nx\r\n", "0\r\n", "0\r\nX: y\r\n",
		fmt.Sprintf("%x\r\n%s", 128*1024+1, strings.Repeat("x", 128*1024)),
	} {
		for _, command := range []string{"http cli client fifo-size 4", "http client fifo-size 4k verbose"} {
			output := httpCliClientRawReply(s, command, func(conn *net.TCPConn) error {
				if _, err := io.WriteString(conn, httpCliChunkedResponseHeaders+body); err != nil {
					return err
				}
				return conn.CloseWrite()
			})
			AssertContains(strings.ToLower(output), "transport closed")
		}
	}
}

func HttpCliClientChunkedHeadersTest(s *Http1Suite) {
	for _, headers := range []string{
		"Transfer-Encoding: chunked\r\nContent-Length: 2\r\n",
		"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
		"Transfer-Encoding: gzip\r\n", "Transfer-Encoding: gzip, chunked\r\n",
		"Transfer-Encoding: chunked, gzip\r\n", "Transfer-Encoding: chunked, chunked\r\n",
	} {
		output := httpCliClientRawReply(s, "http cli client", func(conn *net.TCPConn) error {
			_, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\n"+headers+"\r\n0\r\n\r\n")
			return err
		})
		AssertContains(output, "transport closed")
	}
	for _, status := range []string{"HTTP/1.0 200 OK", "HTTP/1.1 200 OK", "HTTP/1.1 204 No Content", "HTTP/1.1 304 Not Modified"} {
		output := httpCliClientRawReply(s, "http cli client", func(conn *net.TCPConn) error {
			body := ""
			if strings.Contains(status, "200") {
				body = httpCliChunkedBody("OK")
			}
			_, err := io.WriteString(conn, status+"\r\ntRaNsFeR-EnCoDiNg:\tChUnKeD \t\r\n\r\n"+body)
			return err
		})
		switch status {
		case "HTTP/1.0 200 OK":
			AssertContains(output, "transport closed")
		case "HTTP/1.1 200 OK":
			AssertEqual("OK", strings.TrimSpace(output))
		default:
			AssertContains(output, "request failed, response code: "+status[9:12])
		}
	}
}

func HttpCliClientChunkedTlsTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	body := strings.Repeat("tls-chunked!", 8192)
	AssertNil(vpp.Container.CreateFile("/tmp/http-cli-chunked-tls.txt", body))
	address := net.JoinHostPort(s.HostAddr(), s.Ports.Https)
	server := golangServer(address, "https")
	server.AppendHandlers(func(w http.ResponseWriter, r *http.Request) {
		AssertEqual([]string{"chunked"}, r.TransferEncoding)
		data, err := io.ReadAll(r.Body)
		AssertNil(err)
		AssertEqual(body, string(data))
		w.Header().Set("Content-Type", "text/plain")
		w.(http.Flusher).Flush()
		_, err = w.Write(data)
		AssertNil(err)
	})
	server.Start()
	defer server.Close()
	output := vpp.Vppctl("http cli client stream method put file /tmp/http-cli-chunked-tls.txt fifo-size 4 uri https://%s/test", address)
	AssertEqual(body, strings.TrimSpace(output))
}

func HttpCliClientChunkedEarlyResponseTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	AssertNil(vpp.Container.CreateFile("/tmp/http-cli-chunked-reject.txt", strings.Repeat("x", 1024*1024)))
	server, address := httpCliTestServer(s)
	body := strings.Repeat("rejected!", 1024)
	finished := make(chan error, 1)
	server.AppendHandlers(func(w http.ResponseWriter, r *http.Request) {
		// Hijack to respond before consuming the unfinished request body.
		conn, _, err := w.(http.Hijacker).Hijack()
		AssertNil(err)
		defer conn.Close()
		AssertNil(conn.SetDeadline(time.Now().Add(defaultHttpTimeout)))
		_, err = io.WriteString(conn, "HTTP/1.1 413 Content Too Large\r\nTransfer-Encoding: chunked\r\n\r\n")
		AssertNil(err)
		time.Sleep(100 * time.Millisecond)
		_, err = io.WriteString(conn, httpCliChunkedBody(body))
		AssertNil(err)
		// Drain the abandoned upload until the client receives the response and
		// closes. Closing with unread TCP data could reset the response instead.
		_, err = io.Copy(io.Discard, conn)
		finished <- err
	})
	server.Start()
	defer server.Close()
	output := vpp.Vppctl("http cli client stream method post file /tmp/http-cli-chunked-reject.txt fifo-size 4 tx-delay 0.01 uri http://%s/test", address)
	AssertEqual(body, strings.TrimSpace(output))
	AssertNil(<-finished)
}

func httpCliServerStreamResponse(address, target, method, body string, backpressure bool) {
	conn, err := net.DialTimeout("tcp", address, defaultHttpTimeout)
	AssertNil(err)
	defer conn.Close()
	AssertNil(conn.SetDeadline(time.Now().Add(defaultHttpTimeout)))
	if backpressure {
		AssertNil(conn.(*net.TCPConn).SetReadBuffer(4096))
	}
	request, err := http.NewRequest(method, "http://"+address+target, strings.NewReader(body))
	AssertNil(err)
	AssertNil(request.Write(conn))
	if backpressure {
		// Let the response fill the transport FIFO before the peer starts reading.
		time.Sleep(100 * time.Millisecond)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, request)
	AssertNil(err)
	AssertHttpStatus(response, http.StatusOK)
	AssertEqual([]string{"chunked"}, response.TransferEncoding)
	AssertEqual(int64(-1), response.ContentLength)
	AssertEmpty(response.Header.Get("Content-Length"))
	AssertEqual(true, response.Close)
	data, err := io.ReadAll(response.Body)
	AssertNil(err)
	AssertEqual(body, string(data))
	AssertEmpty(response.Trailer)
	AssertNil(response.Body.Close())
	_, err = reader.ReadByte()
	AssertEqual(io.EOF, err, "response must end once, followed by connection close")
}

func HttpCliServerStreamTest(s *Http1Suite) {
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	s.Containers.Vpp.VppInstance.Vppctl("http cli server fifo-size 4 uri http://" + address)
	for _, method := range []string{"GET", "POST", "PUT"} {
		for _, body := range []string{"", "small-stream", strings.Repeat("response-stream!", 8192)} {
			httpCliServerStreamResponse(address, "/echo-stream", method, body, false)
		}
	}
}

func HttpCliServerStreamCloseTest(s *Http1Suite) {
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	s.Containers.Vpp.VppInstance.Vppctl("http cli server fifo-size 4 uri http://" + address)
	for _, body := range []string{"", "small-stream", strings.Repeat("response-close!", 8192)} {
		httpCliServerStreamResponse(address, "/echo-stream-close", "POST", body, false)
	}
}

func HttpCliServerStreamDrainTest(s *Http1Suite) {
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	s.Containers.Vpp.VppInstance.Vppctl("http cli server fifo-size 4 uri http://" + address)
	for _, body := range []string{"", "small-stream", strings.Repeat("response-drain!", 8192)} {
		httpCliServerStreamResponse(address, "/echo-stream-drain", "POST", body, false)
	}
}

func HttpCliServerStreamBackpressureTest(s *Http1Suite) {
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	s.Containers.Vpp.VppInstance.Vppctl("http cli server fifo-size 4 uri http://" + address)
	for _, target := range []string{"/echo-stream", "/echo-stream-drain"} {
		httpCliServerStreamResponse(address, target, "PUT", strings.Repeat("backpressure!", 128*1024), true)
	}
}

func HttpCliServerStreamTlsTest(s *Http1Suite) {
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Https)
	s.Containers.Vpp.VppInstance.Vppctl("http cli server http1-only fifo-size 4 uri https://" + address)
	body := strings.Repeat("tls-response!", 8192)
	client := NewHttpClient(defaultHttpTimeout, false)
	defer client.CloseIdleConnections()
	request, err := http.NewRequest("POST", "https://"+address+"/echo-stream", strings.NewReader(body))
	AssertNil(err)
	response, err := client.Do(request)
	AssertNil(err)
	AssertHttpStatus(response, http.StatusOK)
	AssertEqual([]string{"chunked"}, response.TransferEncoding)
	AssertEqual(int64(-1), response.ContentLength)
	data, err := io.ReadAll(response.Body)
	AssertNil(err)
	AssertNil(response.Body.Close())
	AssertEqual(body, string(data))
}

func httpCliChunkedBody(body string) string {
	if body == "" {
		return "0\r\n\r\n"
	}
	return fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(body), body)
}

func httpCliChunkedConnect(address, method, target, headers, body string) (net.Conn, *bufio.Reader) {
	conn, err := net.DialTimeout("tcp", address, defaultHttpTimeout)
	AssertNil(err)
	AssertNil(conn.SetDeadline(time.Now().Add(defaultHttpTimeout)))
	request := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n%s\r\n%s", method, target, address, headers, body)
	n, err := io.WriteString(conn, request)
	AssertNil(err)
	AssertEqual(len(request), n)
	return conn, bufio.NewReader(conn)
}

func httpCliChunkedReply(conn net.Conn, reader *bufio.Reader, method, body string, status int, streaming bool) {
	response, err := http.ReadResponse(reader, &http.Request{Method: method})
	AssertNil(err)
	AssertHttpStatus(response, status)
	AssertEqual(true, response.Close)
	if streaming {
		AssertEqual([]string{"chunked"}, response.TransferEncoding)
	} else {
		AssertEmpty(response.TransferEncoding)
		AssertEqual(int64(len(body)), response.ContentLength)
	}
	data, err := io.ReadAll(response.Body)
	AssertNil(err)
	AssertEqual(body, string(data))
	AssertEmpty(response.Trailer)
	AssertNil(response.Body.Close())
	_, err = reader.ReadByte()
	AssertEqual(io.EOF, err, "chunked request must permit exactly one response before closing")
	AssertNil(conn.Close())
}

func HttpCliServerChunkedTest(s *Http1Suite) {
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	s.Containers.Vpp.VppInstance.Vppctl("http cli server fifo-size 4 uri http://" + address)
	for _, method := range []string{"GET", "POST", "PUT"} {
		for _, target := range []string{"/echo", "/echo-stream"} {
			for _, body := range []string{"", "small body", strings.Repeat("chunked-body!", 8192)} {
				Log(method, " ", target, " chunked request, body length ", len(body))
				conn, reader := httpCliChunkedConnect(address, method, target, "Transfer-Encoding: chunked\r\n", httpCliChunkedBody(body))
				defer conn.Close()
				httpCliChunkedReply(conn, reader, method, body, http.StatusOK, target != "/echo")
			}
		}
	}
	// Following must not become another request on the same connection
	conn, reader := httpCliChunkedConnect(address, "GET", "/echo", "tRaNsFeR-EnCoDiNg: \tChUnKeD \t\r\n",
		httpCliChunkedBody("first")+"GET /echo HTTP/1.1\r\nHost: "+address+"\r\n\r\n")
	defer conn.Close()
	httpCliChunkedReply(conn, reader, "GET", "first", http.StatusOK, false)
}

func HttpCliServerChunkedFragmentedTest(s *Http1Suite) {
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	s.Containers.Vpp.VppInstance.Vppctl("http cli server fifo-size 4 uri http://" + address)
	wire := "3;foo=\"a\\\";b\"\r\na\x00b\r\nA\r\n0123456789\r\n000;end\r\nX-Test: value\r\nOther:\r\n\r\n"
	conn, reader := httpCliChunkedConnect(address, "PUT", "/echo", "Transfer-Encoding: chunked\r\n", "")
	defer conn.Close()
	for i := range len(wire) {
		_, err := io.WriteString(conn, wire[i:i+1])
		AssertNil(err)
		time.Sleep(time.Millisecond)
	}
	httpCliChunkedReply(conn, reader, "PUT", "a\x00b0123456789", http.StatusOK, false)
}

func HttpCliServerChunkedTrailersTest(s *Http1Suite) {
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	s.Containers.Vpp.VppInstance.Vppctl("http cli server fifo-size 4 uri http://" + address)
	conn, reader := httpCliChunkedConnect(address, "POST", "/echo", "Transfer-Encoding: chunked\r\n",
		"3\r\nabc\r\n0;ignored=yes\r\nX-Checksum: discarded\r\n")
	defer conn.Close()
	// Neither zero chunk nor trailer's CRLF ends the request yet
	AssertNil(conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)))
	_, err := reader.ReadByte()
	netErr, ok := err.(net.Error)
	AssertEqual(true, ok && netErr.Timeout(), "response arrived before the final empty trailer line")
	AssertNil(conn.SetDeadline(time.Now().Add(defaultHttpTimeout)))
	_, err = io.WriteString(conn, "\r\n")
	AssertNil(err)
	httpCliChunkedReply(conn, reader, "POST", "abc", http.StatusOK, false)
}

func HttpCliServerChunkedBackpressureTest(s *Http1Suite) {
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	s.Containers.Vpp.VppInstance.Vppctl("http cli server fifo-size 4 uri http://" + address)
	body := strings.Repeat("backpressure\x00\r\n", 128*1024)
	for _, target := range []string{"/echo", "/echo-stream", "/echo-stream-drain", "/echo-stream-close"} {
		conn, reader := httpCliChunkedConnect(address, "POST", target, "Transfer-Encoding: chunked\r\n", httpCliChunkedBody(body))
		defer conn.Close()
		httpCliChunkedReply(conn, reader, "POST", body, http.StatusOK, target != "/echo")
	}
}

func HttpCliServerChunkedHalfCloseTest(s *Http1Suite) {
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	s.Containers.Vpp.VppInstance.Vppctl("http cli server fifo-size 4 uri http://" + address)
	for _, body := range []string{"", "body before FIN", strings.Repeat("fin-with-pending-data!", 8192)} {
		conn, reader := httpCliChunkedConnect(address, "PUT", "/echo", "Transfer-Encoding: chunked\r\n", httpCliChunkedBody(body))
		defer conn.Close()
		AssertNil(conn.(*net.TCPConn).CloseWrite())
		httpCliChunkedReply(conn, reader, "PUT", body, http.StatusOK, false)
	}
}

func httpCliServerChunkedCurlTest(s *Http1Suite, upload bool) {
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	s.Containers.Vpp.VppInstance.Vppctl("http cli server fifo-size 4 uri http://" + address)
	body := strings.Repeat("curl-interop\x00\r\n!", 8192)
	file := "/tmp/http-cli-curl-body.bin"
	method, target := "GET", "/echo-stream"
	options := "--request=GET --data-binary=@" + file
	if upload {
		method, target = "PUT", "/echo"
		options = "--header=Transfer-Encoding:chunked --upload-file=" + file
	}

	curl := s.Containers.Curl
	curl.ExtraRunningArgs = "curl --http1.1 --verbose --silent --show-error --fail --max-time 10 " +
		"--noproxy * --header=Expect: --write-out=HTTP_STATUS:%{http_code};CURL_EXIT:%{exitcode} " +
		options + " http://" + address + target
	AssertNil(curl.Create())
	AssertNil(curl.CreateFile(file, body))
	AssertNil(curl.Start())
	output, trace := curl.GetOutput()
	Log(trace)
	AssertEqual(body+"HTTP_STATUS:200;CURL_EXIT:0", output)
	AssertContains(trace, "> "+method+" "+target+" HTTP/1.1")
	AssertContains(trace, "< HTTP/1.1 200 OK")
	headers := strings.ReplaceAll(trace, " ", "")
	AssertContains(headers, "<Connection:close")
	AssertNotContains(headers, ">Expect:")
	if upload {
		AssertContains(headers, ">Transfer-Encoding:chunked")
		AssertNotContains(headers, ">Content-Length:")
		AssertContains(headers, "<Content-Length:"+strconv.Itoa(len(body)))
		AssertNotContains(headers, "<Transfer-Encoding:")
	} else {
		AssertContains(headers, ">Content-Length:"+strconv.Itoa(len(body)))
		AssertNotContains(headers, ">Transfer-Encoding:")
		AssertContains(headers, "<Transfer-Encoding:chunked")
		AssertNotContains(headers, "<Content-Length:")
	}
}

func HttpCliServerChunkedCurlUploadTest(s *Http1Suite) {
	httpCliServerChunkedCurlTest(s, true)
}

func HttpCliServerChunkedCurlDownloadTest(s *Http1Suite) {
	httpCliServerChunkedCurlTest(s, false)
}

func HttpCliServerChunkedLargeFifoTest(s *Http1Suite) {
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	s.Containers.Vpp.VppInstance.Vppctl("http cli server fifo-size 2048 uri http://" + address)
	conn, reader := httpCliChunkedConnect(address, "PUT", "/echo", "Transfer-Encoding: chunked\r\n", "")
	defer conn.Close()
	time.Sleep(20 * time.Millisecond)
	body := strings.Repeat("buffered-chunked-body!", 64*1024)
	wire := httpCliChunkedBody(body)
	n, err := io.WriteString(conn, wire)
	AssertNil(err)
	AssertEqual(len(wire), n)
	AssertNil(conn.(*net.TCPConn).CloseWrite())
	httpCliChunkedReply(conn, reader, "PUT", body, http.StatusOK, false)
}

func HttpCliServerChunkedBadFramingTest(s *Http1Suite) {
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	s.Containers.Vpp.VppInstance.Vppctl("http cli server fifo-size 4 uri http://" + address)
	tests := []struct {
		name, body string
		fin        bool
	}{
		{"invalid hex", "g\r\n", false},
		{"overflow", "10000000000000000\r\n", false},
		{"size LF", "1\nx\r\n0\r\n\r\n", false},
		{"data CRLF", "1\r\nx!\r\n0\r\n\r\n", false},
		{"invalid extension", "0;x=\"unterminated\r\n\r\n", false},
		{"invalid trailer", "0\r\nNo-Colon\r\n\r\n", false},
		{"oversized extension", "0;x=" + strings.Repeat("a", 8192) + "\r\n\r\n", false},
		{"oversized trailers", "0\r\nX:" + strings.Repeat("a", 65536) + "\r\n\r\n", false},
		{"FIN before size", "", true},
		{"FIN in size", "a", true},
		{"FIN in payload", "4\r\nab", true},
		{"FIN before last chunk", "1\r\nx\r\n", true},
		{"FIN after backpressured payload", fmt.Sprintf("%x\r\n%s\r\n", 128*1024, strings.Repeat("x", 128*1024)), true},
		{"FIN after zero chunk", "0\r\n", true},
		{"FIN in trailer", "0\r\nX: value\r\n\r", true},
	}
	for _, test := range tests {
		Log(test.name)
		conn, reader := httpCliChunkedConnect(address, "POST", "/echo", "Transfer-Encoding: chunked\r\n", test.body)
		defer conn.Close()
		if test.fin {
			AssertNil(conn.(*net.TCPConn).CloseWrite())
		}
		httpCliChunkedReply(conn, reader, "POST", "", http.StatusBadRequest, false)
	}
	conn, reader := httpCliChunkedConnect(address, "POST", "/echo", "Transfer-Encoding: chunked\r\n", httpCliChunkedBody("still alive"))
	defer conn.Close()
	httpCliChunkedReply(conn, reader, "POST", "still alive", http.StatusOK, false)
}

func HttpCliServerChunkedResetBeforeAcceptTest(s *Http1Suite) {
	s.SkipIfMultiWorker()
	vpp := s.Containers.Vpp.VppInstance
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	Log(vpp.Vppctl("http cli server fifo-size 4 uri http://" + address))
	AssertNotContains(vpp.Vppctl("show interface"), "loop0")

	// Headers and malformed or truncated framing arrive before acceptance.
	for _, test := range []struct {
		body string
		fin  bool
	}{{"g\r\n", false}, {"g\r\n", true}, {"", true}} {
		conn, reader := httpCliChunkedConnect(address, "GET", "/create/loopback/interface",
			"Transfer-Encoding: chunked\r\n", test.body)
		defer conn.Close()
		if test.fin {
			AssertNil(conn.(*net.TCPConn).CloseWrite())
		}
		httpCliChunkedReply(conn, reader, "GET", "", http.StatusBadRequest, false)
		AssertNotContains(vpp.Vppctl("show interface"), "loop0", "malformed body executed a CLI command")
	}

	// A complete chunked body in the same write must still execute the command.
	conn, reader := httpCliChunkedConnect(address, "GET", "/create/loopback/interface",
		"Transfer-Encoding: chunked\r\n", "0\r\n\r\n")
	defer conn.Close()
	response, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
	AssertNil(err)
	defer response.Body.Close()
	AssertHttpStatus(response, http.StatusOK)
	data, err := io.ReadAll(response.Body)
	AssertNil(err)
	AssertContains(string(data), "loop0")
	AssertContains(vpp.Vppctl("show interface"), "loop0")
}

func HttpCliServerChunkedHeadersTest(s *Http1Suite) {
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	s.Containers.Vpp.VppInstance.Vppctl("http cli server fifo-size 4 uri http://" + address)
	for _, headers := range []string{
		"Transfer-Encoding: chunked\r\nContent-Length: 0\r\n",
		"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n",
		"Transfer-Encoding: chunked\r\ntransfer-encoding: chunked\r\n",
		"Transfer-Encoding: chunked, chunked\r\n",
		"Transfer-Encoding: gzip\r\n",
		"Transfer-Encoding: gzip, chunked\r\n",
		"Transfer-Encoding: chunked, gzip\r\n",
		"Transfer-Encoding: chunked,\r\n",
		"Transfer-Encoding: chunked;foo=bar\r\n",
	} {
		Log(headers)
		conn, reader := httpCliChunkedConnect(address, "POST", "/echo", headers, "0\r\n\r\n")
		defer conn.Close()
		httpCliChunkedReply(conn, reader, "POST", "", http.StatusBadRequest, false)
	}
	conn, err := net.DialTimeout("tcp", address, defaultHttpTimeout)
	AssertNil(err)
	defer conn.Close()
	AssertNil(conn.SetDeadline(time.Now().Add(defaultHttpTimeout)))
	_, err = fmt.Fprintf(conn, "POST /echo HTTP/1.0\r\nHost: %s\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", address)
	AssertNil(err)
	httpCliChunkedReply(conn, bufio.NewReader(conn), "POST", "", http.StatusBadRequest, false)
}

func HttpCliServerChunkedEarlyReplyTest(s *Http1Suite) {
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	s.Containers.Vpp.VppInstance.Vppctl("http cli server fifo-size 4 uri http://" + address)
	conn, reader := httpCliChunkedConnect(address, "POST", "/show/version", "Transfer-Encoding: chunked\r\n", "100000\r\npartial")
	defer conn.Close()
	httpCliChunkedReply(conn, reader, "POST", "", http.StatusMethodNotAllowed, false)
}

func HttpCliServerChunkedTlsTest(s *Http1Suite) {
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Https)
	s.Containers.Vpp.VppInstance.Vppctl("http cli server http1-only fifo-size 4 uri https://" + address)
	client := NewHttpClient(defaultHttpTimeout, false)
	defer client.CloseIdleConnections()
	for _, method := range []string{"GET", "POST", "PUT"} {
		body := strings.Repeat("tls-chunked-request!", 8192)
		request, err := http.NewRequest(method, "https://"+address+"/echo", io.NopCloser(strings.NewReader(body)))
		AssertNil(err)
		response, err := client.Do(request)
		AssertNil(err)
		AssertHttpStatus(response, http.StatusOK)
		AssertEqual(int64(len(body)), response.ContentLength)
		AssertEqual(true, response.Close)
		data, err := io.ReadAll(response.Body)
		AssertNil(err)
		AssertEqual(body, string(data))
		AssertNil(response.Body.Close())
	}
}

func HttpCliServerChunkedCliTest(s *Http1Suite) {
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	s.Containers.Vpp.VppInstance.Vppctl("http cli server fifo-size 4 uri http://" + address)
	for _, body := range []string{"", "ignored", strings.Repeat("ignored-body!", 8192)} {
		Log("CLI request body length ", len(body))
		conn, reader := httpCliChunkedConnect(address, "GET", "/show/version",
			"Transfer-Encoding: chunked\r\nAccept: text/plain\r\n", httpCliChunkedBody(body))
		defer conn.Close()
		response, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
		AssertNil(err)
		AssertHttpStatus(response, http.StatusOK)
		AssertEqual(true, response.Close)
		data, err := io.ReadAll(response.Body)
		AssertNil(err)
		AssertContains(string(data), "vpp")
		AssertNil(response.Body.Close())
		_, err = reader.ReadByte()
		AssertEqual(io.EOF, err)
		AssertNil(conn.Close())
	}
}

func HttpCliEchoTest(s *VethsSuite) {
	server := s.Containers.ServerVpp.VppInstance
	client := s.Containers.ClientVpp.VppInstance
	address := net.JoinHostPort(s.Interfaces.Server.Ip4AddressString(), s.Ports.Port1)
	server.Vppctl("http cli server fifo-size 4 uri http://" + address)
	body := strings.Repeat("0123456789AbCdEf", 8*1024)
	AssertNil(client.Container.CreateFile("/tmp/http-cli-echo.txt", body))
	for _, method := range []string{"get", "post", "put"} {
		for _, options := range []string{"", "use-ptr", "stream"} {
			for _, target := range []string{"/echo", "/echo-stream", "/echo-stream-close", "/echo-stream-drain"} {
				output := client.Vppctl("http cli client method %s file /tmp/http-cli-echo.txt fifo-size 4 %s uri http://%s%s",
					method, options, address, target)
				AssertEqual(body, strings.TrimSpace(output))
			}
		}
	}
}

func HttpClientTest(s *Http1Suite) {
	serverAddress := s.HostAddr() + ":" + s.Ports.Http
	server := ghttp.NewUnstartedServer()
	l, err := net.Listen("tcp", serverAddress)
	AssertNil(err, fmt.Sprint(err))
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

	Log(o)
	AssertContains(o, "<html>", "<html> not found in the result!")
	AssertContains(o, "</html>", "</html> not found in the result!")
}

func HttpCliSmallRxFifoReplyTest(s *Http1Suite) {
	serverAddress := s.HostAddr() + ":" + s.Ports.Http
	vpp := s.Containers.Vpp.VppInstance

	server := ghttp.NewUnstartedServer()
	l, err := net.Listen("tcp", serverAddress)
	AssertNil(err, fmt.Sprint(err))
	server.HTTPTestServer.Listener = l
	server.AppendHandlers(
		ghttp.CombineHandlers(
			s.LogHttpReq(false),
			ghttp.VerifyRequest("GET", "/test"),
			ghttp.RespondWith(http.StatusOK, "ok",
				http.Header{"X-Large-Header": {strings.Repeat("a", 6000)}}),
		))
	server.Start()
	defer server.Close()

	uri := "http://" + serverAddress + "/test"
	o := vpp.Vppctl("http cli client fifo-size 1 uri " + uri)

	Log(o)
	AssertContains(o, "transport closed")
}

func HttpCliFragmentedReplyTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	body := strings.Repeat("fragmented-body!", 4096)
	server, address := httpCliTestServer(s)
	server.AppendHandlers(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("Connection", "close")
		for offset, part := 0, 0; offset < len(body); part++ {
			size := 1024
			if part%2 != 0 {
				size = 8192
			}
			end := min(offset+size, len(body))
			_, err := io.WriteString(w, body[offset:end])
			AssertNil(err)
			w.(http.Flusher).Flush()
			offset = end
			// Exercise both waiting for another packet and app FIFO backpressure.
			time.Sleep(10 * time.Millisecond)
		}
	})
	server.Start()
	defer server.Close()
	output := vpp.Vppctl("http cli client fifo-size 4 uri http://%s/test", address)
	AssertEqual(body, strings.TrimSpace(output))
}

func HttpClientChunkedDownloadTest(s *Http1Suite) {
	serverAddress := s.HostAddr() + ":" + s.Ports.Http
	server := ghttp.NewUnstartedServer()
	l, err := net.Listen("tcp", serverAddress)
	AssertNil(err, fmt.Sprint(err))
	server.HTTPTestServer.Listener = l
	data := make([]byte, 128*1024)
	for i := range data {
		data[i] = byte(i)
	}
	response := string(data)
	server.AppendHandlers(
		ghttp.CombineHandlers(
			s.LogHttpReq(true),
			ghttp.VerifyRequest("GET", "/"),
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.(http.Flusher).Flush()
				_, err := io.WriteString(w, response)
				AssertNil(err)
			}),
		))
	server.Start()
	defer server.Close()
	uri := "http://" + serverAddress
	vpp := s.Containers.Vpp.VppInstance
	o := vpp.Vppctl("http client save-to response.txt fifo-size 64k max-body-size 64k uri " + uri)

	Log(o)
	file_contents, err := vpp.Container.Exec(false, "cat /tmp/response.txt")
	AssertNil(err)
	AssertContains(file_contents, response)
	AssertEqual(len(file_contents), len(response))
}

func HttpClientChunkedBodyTest(s *Http1Suite) {
	for _, body := range []string{"", "small-body", strings.Repeat("over-limit!", 8192)} {
		for _, limit := range []string{"4k", "256k"} {
			output := httpCliClientRawReply(s, "http client verbose fifo-size 4k max-body-size "+limit, func(conn *net.TCPConn) error {
				_, err := io.WriteString(conn, httpCliChunkedResponseHeaders+httpCliChunkedBody(body))
				return err
			})
			AssertContains(output, "200 OK")
			if len(body) > 4096 && limit == "4k" {
				AssertContains(output, fmt.Sprintf("response body over limit, read total %d bytes", len(body)))
			} else if body != "" {
				AssertContains(output, body)
			} else {
				AssertNotContains(output, "binary file")
			}
		}
	}
}

func HttpClientChunkedRedirectTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	server, address := httpCliTestServer(s)
	var firstPeer string
	server.AppendHandlers(func(w http.ResponseWriter, r *http.Request) {
		firstPeer = r.RemoteAddr
		w.Header().Set("Location", "/destination")
		w.WriteHeader(http.StatusFound)
		w.(http.Flusher).Flush()
		_, err := io.WriteString(w, "redirecting")
		AssertNil(err)
	}, func(w http.ResponseWriter, r *http.Request) {
		AssertEqual("/destination", r.URL.Path)
		AssertEqual(false, firstPeer == r.RemoteAddr, "streamed response requires a fresh connection")
		w.Header().Set("Content-Type", "text/plain")
		w.(http.Flusher).Flush()
		_, err := io.WriteString(w, "redirect-complete")
		AssertNil(err)
	})
	server.Start()
	defer server.Close()
	output := vpp.Vppctl("http client redirect verbose fifo-size 4k uri http://%s/test", address)
	AssertContains(output, "200 OK")
	AssertContains(output, "redirect-complete")
}

func HttpClientPutStreamingTest(s *Http1Suite) {
	serverAddress := s.HostAddr() + ":" + s.Ports.Http
	vpp := s.Containers.Vpp.VppInstance
	fileName := "/tmp/test_put_streaming.txt"
	body := strings.Repeat("0123456789abcdef", 8*1024)

	AssertNil(vpp.Container.CreateFile(fileName, body))

	server := ghttp.NewUnstartedServer()
	l, err := net.Listen("tcp", serverAddress)
	AssertNil(err, fmt.Sprint(err))
	server.HTTPTestServer.Listener = l
	server.AppendHandlers(
		ghttp.CombineHandlers(
			s.LogHttpReq(false),
			ghttp.VerifyRequest("PUT", "/test"),
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				AssertEqual([]string{"chunked"}, r.TransferEncoding)
				AssertEqual(int64(-1), r.ContentLength)
				data, err := io.ReadAll(r.Body)
				AssertNil(err, fmt.Sprint(err))
				AssertEqual(body, string(data))
				w.WriteHeader(http.StatusCreated)
			}),
		))
	server.Start()
	defer server.Close()

	uri := "http://" + serverAddress + "/test"
	o := vpp.Vppctl("http client put verbose fifo-size 32k uri " + uri + " file " + fileName)

	Log(o)
	AssertContains(o, "201 Created")
}

func HttpClientResponseLengthOverflowTest(s *Http1Suite) {
	for _, length := range []string{
		"18446744073709551558", "18446744073709551559",
		"18446744073709551560", "18446744073709551615",
	} {
		for _, body := range []string{"", "partial"} {
			Log("Content-Length %s, buffered body %q", length, body)
			output := httpCliClientRawReply(s, "http client fifo-size 4k verbose", func(conn *net.TCPConn) error {
				if _, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: "+length+"\r\n\r\n"+body); err != nil {
					return err
				}
				return conn.CloseWrite()
			})
			AssertContains(output, "latency:")
			AssertNotContains(output, "timeout")
		}
	}
	AssertContains(s.Containers.Vpp.VppInstance.Vppctl("show version"), "vpp")
}

func HttpClientBodySizeTest(s *Http1Suite) {
	serverAddress := s.HostAddr() + ":" + s.Ports.Http
	server := ghttp.NewUnstartedServer()
	l, err := net.Listen("tcp", serverAddress)
	AssertNil(err, fmt.Sprint(err))
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

	Log(o)
	AssertContains(o, "* response body over limit", "response body size info not found in result!")
	AssertContains(o, ", read total 38 bytes", "client retrieved invalid amount of bytes!")
}

func HttpClientInvalidHeaderNameTest(s *Http1Suite) {
	serverAddress := s.HostAddr()
	l, err := net.Listen("tcp", serverAddress+":80")
	AssertNil(err, fmt.Sprint(err))
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
	Log(o)
	AssertContains(o, "transport closed")

	/* wait until cleanup to be sure we don't crash */
	httpCleanupDone := false
	tcpSessionCleanupDone := false
	for range 60 {
		o := vpp.Vppctl("show session verbose 2")
		if !strings.Contains(o, "[T]") {
			tcpSessionCleanupDone = true
		}
		if !strings.Contains(o, "[H1]") {
			httpCleanupDone = true
		}
		if httpCleanupDone && tcpSessionCleanupDone {
			Log(o)
			break
		}
		time.Sleep(1 * time.Second)
	}
	AssertEqual(true, tcpSessionCleanupDone, "TCP session not cleanup")
	AssertEqual(true, httpCleanupDone, "HTTP not cleanup")
	o = vpp.Vppctl("show http stats")
	Log(o)
	AssertContains(o, "1 connections protocol error")
}

func HttpClientErrRespTest(s *Http1Suite) {
	serverAddress := s.HostAddr() + ":" + s.Ports.Http
	server := ghttp.NewUnstartedServer()
	l, err := net.Listen("tcp", serverAddress)
	AssertNil(err, fmt.Sprint(err))
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

	Log(o)
	AssertContains(o, "404: Not Found", "error not found in the result!")
}

func httpClientPostFormTest(s *Http1Suite, usePtr bool) {
	serverAddress := s.HostAddr() + ":" + s.Ports.Http
	body := "field1=value1&field2=value2"

	server := ghttp.NewUnstartedServer()
	l, err := net.Listen("tcp", serverAddress)
	AssertNil(err, fmt.Sprint(err))
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
	cmd := "http client post verbose header Hello:World uri " + uri + " data " + body
	if usePtr {
		cmd += " use-ptr"
	}
	o := vpp.Vppctl(cmd)

	Log(o)
	AssertContains(o, "200 OK")
}

func HttpClientPostFormTest(s *Http1Suite) {
	httpClientPostFormTest(s, false)
}

func HttpClientPostFormPtrTest(s *Http1Suite) {
	httpClientPostFormTest(s, true)
}

func HttpClientNoPrintTest(s *Http1Suite) {
	serverAddress := s.HostAddr() + ":" + s.Ports.Http
	server := ghttp.NewUnstartedServer()
	l, err := net.Listen("tcp", serverAddress)
	AssertNil(err, fmt.Sprint(err))
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

	Log(o)
	AssertContains(o, "* binary file, not printing!", "no warning message found!")
	AssertNotContains(o, "</html>", "</html> found in the result!")
}

func HttpClientGetResponseBodyTest(s *Http1Suite) {
	response := "<body>hello world</body>"
	size := len(response)
	httpClientGet(s, s.Containers.Vpp.VppInstance, response, size, "http", s.Ports.Http)
}

func HttpClientGet128kbResponseTest(s *Http1Suite) {
	response := strings.Repeat("a", 128*1024)
	size := len(response)
	httpClientGet(s, s.Containers.Vpp.VppInstance, response, size, "http", s.Ports.Http)
}

func HttpClientGetTlsNoRespBodyTest(s *Http1Suite) {
	response := ""
	httpClientGet(s, s.Containers.Vpp.VppInstance, response, 0, "https", s.Ports.Http)
}

// not using generated ports
func HttpClientGetResponseBody6Test(s *NoTopo6Suite) {
	response := "<body>hello world</body>"
	size := len(response)
	httpClientGet(s, s.Containers.Vpp.VppInstance, response, size, "http", s.Ports.Http)
}

// not using generated ports
func HttpClientGetTlsResponseBody6Test(s *NoTopo6Suite) {
	response := "<body>hello world</body>"
	size := len(response)
	httpClientGet(s, s.Containers.Vpp.VppInstance, response, size, "https", s.Ports.Http)
}

func golangServer(serverAddress string, proto string) *ghttp.Server {
	var l net.Listener
	var err error

	destinationServer := ghttp.NewUnstartedServer()

	if proto == "https" {
		var cer tls.Certificate
		certFile := "resources/cert/localhost.crt"
		keyFile := "resources/cert/localhost.key"
		cer, err = tls.LoadX509KeyPair(certFile, keyFile)
		AssertNil(err)
		tlsConfig := &tls.Config{Certificates: []tls.Certificate{cer}}
		destinationServer.HTTPTestServer.TLS = tlsConfig
		l, err = tls.Listen("tcp", serverAddress, tlsConfig)
	} else {
		l, err = net.Listen("tcp", serverAddress)
	}
	AssertNil(err, fmt.Sprint(err))

	destinationServer.HTTPTestServer.Listener = l

	return destinationServer
}

func httpClientGet(s httpClientGetInterface, vpp *VppInstance, response string, size int, proto string, port string) {
	var err error

	serverAddress := JoinHostPort(s.HostAddr(), port)
	server := golangServer(serverAddress, proto)
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

	uri := proto + "://" + serverAddress + "/"
	cmd := "http client use-ptr verbose header Hello:World header Test-H2:Test-K2 save-to response.txt uri " + uri

	o := vpp.Vppctl(cmd)
	outputLen := len(o)
	if outputLen > 500 {
		Log(o[:500])
		Log("* HST Framework: output limited to 500 chars to avoid flooding the console. Output length: " + fmt.Sprint(outputLen))
	} else {
		Log(o)
	}
	AssertContains(o, "200 OK")
	AssertContains(o, "Content-Length: "+strconv.Itoa(size))

	file_contents, err := vpp.Container.Exec(false, "cat /tmp/response.txt")
	AssertNil(err)
	AssertContains(file_contents, response)
	AssertEqual(len(file_contents), size)
}

func httpClientGetRedirect(s *Http1Suite, requestMethod string, response string, size int, proto string, httpResponseCode int,
	server1Method string, server2Method string, clientUri string) {
	vpp := s.Containers.Vpp.VppInstance
	destinationAddress := s.HostAddr() + ":" + s.Ports.NginxServer
	redirectServerAddress := s.HostAddr() + ":" + s.Ports.Http
	data := "field1=value1&field2=value2"

	redirectServer := golangServer(redirectServerAddress, proto)
	redirectServer.AppendHandlers(
		ghttp.CombineHandlers(
			s.LogHttpReq(true),
			ghttp.VerifyRequest(server1Method, "/"),
			ghttp.VerifyHeaderKV("Hello", "World"),
			ghttp.VerifyHeaderKV("Test-H2", "Test-K2"),
			ghttp.VerifyBody([]byte(data)),
			ghttp.RespondWith(
				httpResponseCode,
				"",
				http.Header{
					"Location": {"/test123"},
				},
			),
		),
		ghttp.CombineHandlers(
			s.LogHttpReq(true),
			ghttp.VerifyRequest(server2Method, "/test123"),
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

	destinationServer := golangServer(destinationAddress, proto)
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
		requestMethod += " data " + data
	}
	cmd := "http client " + requestMethod + " redirect max-redirects 5 verbose use-ptr header Hello:World header Test-H2:Test-K2 save-to response.txt uri " + clientUri

	o := vpp.Vppctl(cmd)
	outputLen := len(o)
	if outputLen > 500 {
		Log(o[:500])
		Log("* HST Framework: output limited to 500 chars to avoid flooding the console. Output length: " + fmt.Sprint(outputLen))
	} else {
		Log(o)
	}

	AssertContains(o, "200 OK")
	AssertContains(o, "Content-Length: "+strconv.Itoa(size))
	file_contents, err := vpp.Container.Exec(false, "cat /tmp/response.txt")
	AssertNil(err)
	AssertContains(file_contents, response)
	AssertEqual(len(file_contents), size)
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
	server := golangServer(serverAddr, "http")
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
	cmd := "http client redirect max-redirects 5 verbose header Hello:World header Test-H2:Test-K2 save-to response.txt uri " + uri

	o := vpp.Vppctl(cmd)
	Log(o)
	AssertContains(o, "redirect limit")
	AssertContains(o, http.StatusPermanentRedirect)
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
	serverAddress := s.Interfaces.Tap.Host.Ip4AddressString() + ":" + s.Ports.NginxServer
	replyCountInt := 0
	repeatAmount := 10000
	durationInSec := 10
	var err error

	s.CreateNginxServer()
	AssertNil(s.Containers.NginxServer.Start())
	logPath := s.Containers.NginxServer.GetContainerWorkDir() + "/" + s.Containers.NginxServer.Name + "-access.log"

	if requestMethod == "post" {
		fileName := "/tmp/test_file.txt"
		Log(vpp.Container.Exec(false, "fallocate -l 64 "+fileName))
		Log(vpp.Container.Exec(false, "ls -la "+fileName))
		requestMethod += " file /tmp/test_file.txt"
	}

	uri := "http://" + serverAddress + "/index"
	cmd := fmt.Sprintf("http client %s %s duration %d header Hello:World uri %s",
		requestMethod, clientArgs, durationInSec, uri)

	Log("Duration %ds", durationInSec)
	o := vpp.Vppctl(cmd)
	Log(o)

	replyCount, err := s.Containers.NginxServer.Exec(false, "awk 'END { print NR }' "+logPath)
	AssertNil(err)
	if replyCount != "" {
		replyCountInt, err = strconv.Atoi(replyCount[:len(replyCount)-1])
		AssertNil(err)
	}
	// empty the log file
	s.Containers.NginxServer.Exec(false, "truncate -s 0 "+logPath)

	Log("Server response count: %d", replyCountInt)
	AssertNotNil(o)
	AssertNotContains(o, "error")
	AssertGreaterEqual(replyCountInt, 10000, "Server reply count below threshold")

	replyCount = ""
	cmd = fmt.Sprintf("http client %s %s repeat %d header Hello:World uri %s",
		requestMethod, clientArgs, repeatAmount, uri)

	AssertNil(err, fmt.Sprint(err))
	Log("Repeat %d", repeatAmount)
	o = vpp.Vppctl(cmd)
	Log(o)

	replyCount, err = s.Containers.NginxServer.Exec(false, "awk 'END { print NR }' "+logPath)
	AssertNil(err)
	if replyCount != "" {
		replyCountInt, err = strconv.Atoi(replyCount[:len(replyCount)-1])
		AssertNil(err)
	}
	Log("Server response count: %d", replyCountInt)
	AssertNotNil(o)
	AssertNotContains(o, "error")
	AssertEqual(repeatAmount, replyCountInt)
}

func HttpClientGetTimeout(s *Http1Suite) {
	serverAddress := s.HostAddr() + ":" + s.Ports.Http
	vpp := s.Containers.Vpp.VppInstance

	server := ghttp.NewUnstartedServer()
	l, err := net.Listen("tcp", serverAddress)
	AssertNil(err, fmt.Sprint(err))
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
	Log(o)
	AssertContains(o, "error: timeout")
}

func httpClientPostFile(s *Http1Suite, usePtr bool, fileSize int) {
	serverAddress := s.HostAddr() + ":" + s.Ports.Http
	vpp := s.Containers.Vpp.VppInstance
	fileName := "/tmp/test_file.txt"
	Log(vpp.Container.Exec(false, "fallocate -l "+strconv.Itoa(fileSize)+" "+fileName))
	Log(vpp.Container.Exec(false, "ls -la "+fileName))

	server := ghttp.NewUnstartedServer()
	l, err := net.Listen("tcp", serverAddress)
	AssertNil(err, fmt.Sprint(err))
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

	Log(o)
	AssertContains(o, "200 OK")
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
	Log(vpp.Container.Exec(false, "fallocate -l "+strconv.Itoa(10<<20)+" "+fileName))
	Log(vpp.Container.Exec(false, "ls -la "+fileName))

	server := ghttp.NewUnstartedServer()
	l, err := net.Listen("tcp", serverAddress)
	AssertNil(err, fmt.Sprint(err))
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

	Log(o)
	AssertContains(o, "403")
	Log(vpp.Vppctl("show session verbose 2"))
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
	AssertNil(err, fmt.Sprint(err))

	clientVpp.Vppctl("http cli client uri " + uri + "/show/vlib/graph")

	/* let's give it some time to clean up sessions */
	time.Sleep(time.Second * 12)

	traces2, err := clientVpp.GetMemoryTrace()
	AssertNil(err, fmt.Sprint(err))
	clientVpp.MemLeakCheck(traces1, traces2)
}

func httpClientRedirectMemLeakFunc(s *Http1Suite, clientMethod string, server1Method string, server2Method string) {
	s.SkipUnlessLeakCheck()

	args := "http://" + s.HostAddr() + ":" + s.Ports.Http + "/"
	if clientMethod == "post" {
		args += " post data field1=value1&field2=value2"
	}
	response := "Hello"
	vpp := s.Containers.Vpp.VppInstance

	/* no goVPP less noise */
	vpp.Disconnect()

	destinationAddress := s.HostAddr() + ":" + s.Ports.NginxServer
	redirectServerAddress := s.HostAddr() + ":" + s.Ports.Http

	redirectServer := golangServer(redirectServerAddress, "http")
	for range 2 {
		redirectServer.AppendHandlers(
			ghttp.CombineHandlers(
				s.LogHttpReq(true),
				ghttp.VerifyRequest(server1Method, "/"),
				ghttp.VerifyHeaderKV("Hello", "World"),
				ghttp.VerifyHeaderKV("Test-H2", "Test-K2"),
				ghttp.RespondWith(
					http.StatusFound,
					"",
					http.Header{
						"Location": {"/test123"},
					},
				),
			),
			ghttp.CombineHandlers(
				s.LogHttpReq(true),
				ghttp.VerifyRequest(server2Method, "/test123"),
				ghttp.VerifyHeaderKV("Hello", "World"),
				ghttp.VerifyHeaderKV("Test-H2", "Test-K2"),
				ghttp.RespondWith(
					http.StatusFound,
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
					http.StatusFound,
					"",
					http.Header{
						"Location": {"http://" + destinationAddress},
					},
				),
			),
		)
	}

	redirectServer.Start()
	defer redirectServer.Close()

	destinationServer := golangServer(destinationAddress, "http")
	for range 2 {
		destinationServer.AppendHandlers(
			ghttp.CombineHandlers(
				s.LogHttpReq(true),
				ghttp.VerifyRequest(server2Method, "/"),
				ghttp.RespondWith(
					http.StatusOK,
					response,
					http.Header{"Content-Length": {strconv.Itoa(len(response))}},
				),
			),
		)
	}
	destinationServer.Start()
	defer destinationServer.Close()

	vpp.Vppctl("http client redirect timeout 5 verbose header Hello:World header Test-H2:Test-K2 save-to response.txt uri " + args)
	// 10s is not enough sometimes
	Log("Sleeping for 12s")
	time.Sleep(time.Second * 12)

	vpp.EnableMemoryTrace()
	traces1, err := vpp.GetMemoryTrace()
	AssertNil(err, fmt.Sprint(err))

	Log(vpp.Vppctl("http client redirect timeout 5 verbose header Hello:World header Test-H2:Test-K2 save-to response.txt uri " + args))
	Log("Sleeping for 12s")
	time.Sleep(time.Second * 12)

	traces2, err := vpp.GetMemoryTrace()
	AssertNil(err, fmt.Sprint(err))
	vpp.MemLeakCheck(traces1, traces2)
}

func HttpClientRedirectGetMemLeakTest(s *Http1Suite) {
	httpClientRedirectMemLeakFunc(s, "", "GET", "GET")
}

func HttpClientRedirectPostMemLeakTest(s *Http1Suite) {
	httpClientRedirectMemLeakFunc(s, "post", "POST", "GET")
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
	AssertNil(err, fmt.Sprint(err))
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
	AssertNil(err, fmt.Sprint(err))

	vpp.Vppctl("http post uri " + uri + " target /test data " + body)

	/* let's give it some time to clean up sessions */
	time.Sleep(time.Second * 12)

	traces2, err := vpp.GetMemoryTrace()
	AssertNil(err, fmt.Sprint(err))
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
	_, err := TcpSendReceive(serverAddress, "\rGET / HTTP/1.1\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))

	/* let's give it some time to clean up sessions, so local port can be reused and we have less noise */
	time.Sleep(time.Second * 12)

	vpp.EnableMemoryTrace()
	traces1, err := vpp.GetMemoryTrace()
	AssertNil(err, fmt.Sprint(err))

	_, err = TcpSendReceive(serverAddress, "\rGET / HTTP/1.1\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))

	/* let's give it some time to clean up sessions */
	time.Sleep(time.Second * 12)

	traces2, err := vpp.GetMemoryTrace()
	AssertNil(err, fmt.Sprint(err))
	vpp.MemLeakCheck(traces1, traces2)

}

func HttpCliMethodNotAllowedTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	vpp.Vppctl("http cli server uri http://" + serverAddress)

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("POST", "http://"+serverAddress+"/test", nil)
	AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	Log(DumpHttpResp(resp, true))
	AssertHttpStatus(resp, 405)
	AssertHttpHeaderWithValue(resp, "Allow", "GET", "server MUST generate an Allow header")
	AssertHttpHeaderNotPresent(resp, "Content-Type")
	AssertHttpContentLength(resp, int64(0))
}

func HttpCliBadRequestTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	vpp.Vppctl("http cli server uri http://" + serverAddress)

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "http://"+serverAddress, nil)
	AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	Log(DumpHttpResp(resp, true))
	AssertHttpStatus(resp, 400)
	AssertHttpHeaderNotPresent(resp, "Content-Type")
	AssertHttpContentLength(resp, int64(0))
}

func validatePostInterfaceStats(s *Http1Suite, data string) {
	AssertContains(data, "interface_stats")
	AssertContains(data, s.VppIfName())
	AssertNotContains(data, "error")
	AssertNotContains(data, "local0")
}

func HttpInvalidRequestLineTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	vpp.Vppctl("http cli server uri http://" + serverAddress)

	resp, err := TcpSendReceive(serverAddress, " GET / HTTP/1.1\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request", "invalid request line start not allowed")

	resp, err = TcpSendReceive(serverAddress, "\rGET / HTTP/1.1\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request", "invalid request line start not allowed")

	resp, err = TcpSendReceive(serverAddress, "\nGET / HTTP/1.1\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request", "invalid request line start not allowed")

	resp, err = TcpSendReceive(serverAddress, "GET /\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request", "HTTP-version must be present")

	resp, err = TcpSendReceive(serverAddress, "GET HTTP/1.1\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request", "request-target must be present")

	resp, err = TcpSendReceive(serverAddress, "GET  HTTP/1.1\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request", "request-target must be present")

	resp, err = TcpSendReceive(serverAddress, "GET / HTTP/x\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request", "'HTTP/x' invalid http version not allowed")

	resp, err = TcpSendReceive(serverAddress, "get / HTTP/1.1\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request", "method must be uppercase")

	resp, err = TcpSendReceive(serverAddress, "GET / HTTP1.1\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request", "'HTTP1.1' invalid http version not allowed")

	resp, err = TcpSendReceive(serverAddress, "/\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request")
}

// HttpIncrementalRequestLineTest requires errors to be detected without waiting
// for a request-line terminator, with enough FIFO space to expose the URI limit.
func HttpIncrementalRequestLineTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	vpp.Vppctl("http static server uri tcp://%s url-handlers fifo-size 128k", address)
	for _, test := range []struct {
		fragments []string
		status    int
	}{
		{[]string{"g"}, http.StatusBadRequest},
		{[]string{"Z"}, http.StatusNotImplemented},
		{[]string{"G", "ETX"}, http.StatusNotImplemented},
		{[]string{"P", "X"}, http.StatusNotImplemented},
		{[]string{"CONNECT", "-"}, http.StatusNotImplemented},
		{[]string{"GET ", " "}, http.StatusBadRequest},
		{[]string{"GET /version.json ", "HTX"}, http.StatusBadRequest},
		{[]string{"GET /version.json HTTP/", "2"}, http.StatusHTTPVersionNotSupported},
		{[]string{"GET /version.json HTTP/1.1", "x"}, http.StatusBadRequest},
		{[]string{"GET /version.json HTTP/1.1\r", "X"}, http.StatusBadRequest},
		{[]string{"GET /", strings.Repeat("x", 65535)}, http.StatusBadRequest},
	} {
		Log("Early request-line rejection: prefix %q, status %d", test.fragments[0], test.status)
		func() {
			conn, err := net.DialTimeout("tcp", address, defaultHttpTimeout)
			AssertNil(err)
			defer conn.Close()
			for i, fragment := range test.fragments {
				AssertNil(conn.SetWriteDeadline(time.Now().Add(defaultHttpTimeout)))
				_, err = io.WriteString(conn, fragment)
				AssertNil(err)
				if i < len(test.fragments)-1 {
					AssertNil(conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)))
					var b [1]byte
					n, readErr := conn.Read(b[:])
					AssertEqual(0, n)
					timeout, ok := readErr.(net.Error)
					AssertEqual(true, ok && timeout.Timeout(), fmt.Sprint(readErr))
				}
			}
			AssertNil(conn.SetReadDeadline(time.Now().Add(2 * time.Second)))
			response, err := http.ReadResponse(bufio.NewReader(conn), nil)
			AssertNil(err)
			AssertHttpStatus(response, test.status)
			AssertNil(response.Body.Close())
		}()
	}
	// Reuse the connection while crossing every single split position of
	// representative request lines, then deliver each line byte by byte.
	conn, err := net.DialTimeout("tcp", address, defaultHttpTimeout)
	AssertNil(err)
	defer conn.Close()
	reader := bufio.NewReader(conn)
	var expectedBody string
	check := func(parts []string) {
		for i, part := range parts {
			AssertNil(conn.SetWriteDeadline(time.Now().Add(defaultHttpTimeout)))
			_, err := io.WriteString(conn, part)
			AssertNil(err)
			if i < len(parts)-1 {
				AssertNil(conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)))
				var b [1]byte
				n, readErr := conn.Read(b[:])
				AssertEqual(0, n)
				timeout, ok := readErr.(net.Error)
				AssertEqual(true, ok && timeout.Timeout(), fmt.Sprint(readErr))
			}
		}
		AssertNil(conn.SetReadDeadline(time.Now().Add(defaultHttpTimeout)))
		response, err := http.ReadResponse(reader, nil)
		AssertNil(err)
		AssertHttpStatus(response, http.StatusOK)
		body, err := io.ReadAll(response.Body)
		AssertNil(err)
		AssertNil(response.Body.Close())
		if expectedBody == "" {
			expectedBody = string(body)
			AssertContains(expectedBody, "build_date")
		}
		AssertEqual(expectedBody, string(body))
	}
	headers := "Host: example.com\r\n\r\n"
	for _, line := range []string{
		"GET /version.json?x=a?b HTTP/1.1\r\n",
		"\r\nGET /version.json?x=a?b HTTP/1.1\r\n",
		"GET http://example.com/version.json?x=a?b HTTP/1.1\r\n",
		"GET /version.json HTTP/1.0\r\n",
	} {
		Log("Request-line fragmentation invariance: %q", line)
		check([]string{line + headers})
		for split := 1; split < len(line); split++ {
			check([]string{line[:split], line[split:] + headers})
		}
		parts := make([]string, 0, len(line)+1)
		for _, c := range line {
			parts = append(parts, string(c))
		}
		check(append(parts, headers))
	}
	// The total target length includes path, '?' and query. Cross both the
	// u16 limit and a FIFO chunk boundary while keeping headers within limits.
	for _, length := range []int{65534, 65535} {
		target := "/version.json?x=" + strings.Repeat("x", length-len("/version.json?x="))
		check([]string{"GET " + target + " HTTP/1.1\r\n" + headers})
		check([]string{"GET " + target[:len(target)-1], target[len(target)-1:] + " HTTP/1.1\r\n" + headers})
	}

	// Put both field-line and final CRLF at bounded header-scan edges.
	for _, boundary := range []int{253, 254, 255, 256, 257} {
		fields := "Host: example.com\r\nX-Pad: "
		fields += strings.Repeat("x", boundary-len(fields))
		check([]string{"GET /version.json HTTP/1.1\r\n" + fields + "\r\n\r\n"})
	}

	// Exercise ambiguous P prefixes and retain a coalesced body after CRLF.
	echoAddress := net.JoinHostPort(s.VppAddr(), s.Ports.Https)
	vpp.Vppctl("http cli server uri http://%s", echoAddress)
	echo, err := net.DialTimeout("tcp", echoAddress, defaultHttpTimeout)
	AssertNil(err)
	defer echo.Close()
	echoReader := bufio.NewReader(echo)
	for _, method := range []string{"GET", "POST", "PUT"} {
		request := method + " /echo?x=a?b HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nbody"
		for split := 1; split <= len(method)+1; split++ {
			AssertNil(echo.SetWriteDeadline(time.Now().Add(defaultHttpTimeout)))
			_, err = io.WriteString(echo, request[:split])
			AssertNil(err)
			AssertNil(echo.SetReadDeadline(time.Now().Add(100 * time.Millisecond)))
			var b [1]byte
			n, readErr := echo.Read(b[:])
			AssertEqual(0, n)
			timeout, ok := readErr.(net.Error)
			AssertEqual(true, ok && timeout.Timeout(), fmt.Sprint(readErr))
			_, err = io.WriteString(echo, request[split:])
			AssertNil(err)
			AssertNil(echo.SetReadDeadline(time.Now().Add(defaultHttpTimeout)))
			response, err := http.ReadResponse(echoReader, nil)
			AssertNil(err)
			AssertHttpStatus(response, http.StatusOK)
			AssertHttpBody(response, "body")
			AssertNil(response.Body.Close())
		}
	}
}

// HttpFragmentedH2PrefaceTest keeps an undecided method prefix intact when
// handing a cleartext HTTP/2 prior-knowledge connection to the HTTP/2 parser.
func HttpFragmentedH2PrefaceTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	vpp.Vppctl("http static server uri tcp://%s url-handlers", address)
	check := func(parts []string) {
		conn, err := net.DialTimeout("tcp", address, defaultHttpTimeout)
		AssertNil(err)
		defer conn.Close()
		AssertNil(conn.SetWriteDeadline(time.Now().Add(defaultHttpTimeout)))
		for i, fragment := range parts {
			_, err = io.WriteString(conn, fragment)
			AssertNil(err)
			if i < len(parts)-1 {
				AssertNil(conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)))
				var b [1]byte
				n, readErr := conn.Read(b[:])
				AssertEqual(0, n)
				timeout, ok := readErr.(net.Error)
				AssertEqual(true, ok && timeout.Timeout(), fmt.Sprint(readErr))
			}
		}
		AssertNil(conn.SetReadDeadline(time.Now().Add(defaultHttpTimeout)))
		framer := http2.NewFramer(conn, conn)
		AssertNil(framer.WriteSettings(http2.Setting{ID: http2.SettingEnablePush, Val: 0}))
		for range 4 {
			frame, err := framer.ReadFrame()
			AssertNil(err)
			if settings, ok := frame.(*http2.SettingsFrame); ok {
				if settings.IsAck() {
					return
				}
				AssertNil(framer.WriteSettingsAck())
			}
		}
		Fail("HTTP/2 did not acknowledge SETTINGS after the fragmented preface")
	}
	check([]string{http2.ClientPreface})
	for split := 1; split < len(http2.ClientPreface); split++ {
		Log("HTTP/2 preface split at %d", split)
		check([]string{http2.ClientPreface[:split], http2.ClientPreface[split:]})
	}
	parts := make([]string, 0, len(http2.ClientPreface))
	for _, c := range http2.ClientPreface {
		parts = append(parts, string(c))
	}
	check(parts)
	AssertNotContains(vpp.Vppctl("show http stats"), "connections protocol error")
}

func HttpTimerSessionDisable(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	Log(vpp.Vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress))
	time.Sleep(250 * time.Millisecond)
	resp := vpp.Vppctl("show node http-timer-process")
	AssertContains(resp, "node http-timer-process, type process, state \"any wait\"")
	vpp.Vppctl("session disable")
	time.Sleep(1 * time.Second)
	resp = vpp.Vppctl("show node http-timer-process")
	AssertContains(resp, "node http-timer-process, type process, state \"not started\"")
	vpp.Vppctl("session enable")
	time.Sleep(100 * time.Millisecond)
	resp = vpp.Vppctl("show node http-timer-process")
	AssertContains(resp, "node http-timer-process, type process, state \"any wait\"")
}

func HttpRequestLineTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	vpp.Vppctl("http cli server uri http://" + serverAddress)

	resp, err := TcpSendReceive(serverAddress, "\r\nGET /show/version HTTP/1.1\r\nHost:"+serverAddress+"\r\nUser-Agent:test\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 200 OK")
	AssertContains(resp, "<html>", "html content not found")
}

func HttpInvalidTargetSyntaxTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers debug"))

	resp, err := TcpSendReceive(serverAddress, "GET /interface|stats.json HTTP/1.1\r\nHost: example.com\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request", "'|' not allowed in target path")

	resp, err = TcpSendReceive(serverAddress, "GET /interface#stats.json HTTP/1.1\r\nHost: example.com\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request", "'#' not allowed in target path")

	resp, err = TcpSendReceive(serverAddress, "GET /interface%stats.json HTTP/1.1\r\nHost: example.com\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request",
		"after '%' there must be two hex-digit characters in target path")

	resp, err = TcpSendReceive(serverAddress, "GET /interface%1stats.json HTTP/1.1\r\nHost: example.com\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request",
		"after '%' there must be two hex-digit characters in target path")

	resp, err = TcpSendReceive(serverAddress, "GET /interface%Bstats.json HTTP/1.1\r\nHost: example.com\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request",
		"after '%' there must be two hex-digit characters in target path")

	resp, err = TcpSendReceive(serverAddress, "GET /interface%stats.json%B HTTP/1.1\r\nHost: example.com\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request",
		"after '%' there must be two hex-digit characters in target path")

	resp, err = TcpSendReceive(serverAddress, "GET /version.json?verbose?>true HTTP/1.1\r\nHost: example.com\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request", "'>' not allowed in target query")

	resp, err = TcpSendReceive(serverAddress, "GET /version.json?verbose%true HTTP/1.1\r\nHost: example.com\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request",
		"after '%' there must be two hex-digit characters in target query")

	resp, err = TcpSendReceive(serverAddress, "GET /version.json?verbose=%1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request",
		"after '%' there must be two hex-digit characters in target query")

	resp, err = TcpSendReceive(serverAddress, "GET * HTTP/1.1\r\nHost: example.com\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request", "asterisk-form is only used for a server-wide OPTIONS request")

	resp, err = TcpSendReceive(serverAddress, "GET www.example.com:80 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request", "authority-form is only used for CONNECT requests")

	resp, err = TcpSendReceive(serverAddress, "CONNECT https://www.example.com/tunnel HTTP/1.1\r\nHost: example.com\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request", "CONNECT requests must use authority-form only")

	resp, err = TcpSendReceive(serverAddress, "GET index HTTP/1.1\r\nHost: example.com\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request")
}

func HttpInvalidContentLengthTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	vpp.Vppctl("http cli server uri http://" + serverAddress)

	resp, err := TcpSendReceive(serverAddress, "GET /show/version HTTP/1.1\r\nContent-Length:\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request", "Content-Length value must be present")

	resp, err = TcpSendReceive(serverAddress, "GET /show/version HTTP/1.1\r\nContent-Length: \r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request", "Content-Length value must be present")

	resp, err = TcpSendReceive(serverAddress, "GET /show/version HTTP/1.1\r\nContent-Length: a\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request",
		"Content-Length value other than digit not allowed")

	resp, err = TcpSendReceive(serverAddress, "GET /show/version HTTP/1.1\r\nContent-Length: 111111111111111111111111111111111111111111111111\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request", "Content-Length value exceeded U64_MAX")
}

func HttpContentLengthTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers debug max-body-size 12"))
	ifName := s.VppIfName()

	resp, err := TcpSendReceive(serverAddress,
		"POST /interface_stats.json HTTP/1.1\r\nHost: example.com\r\nContent-Length:4\r\n\r\n"+ifName)
	AssertNil(err, fmt.Sprint(err))
	validatePostInterfaceStats(s, resp)

	resp, err = TcpSendReceive(serverAddress,
		"POST /interface_stats.json HTTP/1.1\r\nHost: example.com\r\nContent-Length:  4 \r\n\r\n"+ifName)
	AssertNil(err, fmt.Sprint(err))
	validatePostInterfaceStats(s, resp)

	resp, err = TcpSendReceive(serverAddress,
		"POST /interface_stats.json HTTP/1.1\r\nHost: example.com\r\nContent-Length:\t\t4\r\n\r\n"+ifName)
	AssertNil(err, fmt.Sprint(err))
	validatePostInterfaceStats(s, resp)
}

func HttpContentLengthLongerBodyTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers debug max-body-size 12"))

	conn, err := net.DialTimeout("tcp", serverAddress, time.Second*30)
	AssertNil(err, fmt.Sprint(err))
	defer conn.Close()
	err = conn.SetDeadline(time.Now().Add(time.Second * 10))
	AssertNil(err, fmt.Sprint(err))

	request := "POST /interface_stats.json HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\n"
	_, err = conn.Write([]byte(request))
	AssertNil(err, fmt.Sprint(err))

	requestSeen := false
	lastStats := ""
	for i := 0; i < 30; i++ {
		lastStats = vpp.Vppctl("show http stats")
		if strings.Contains(lastStats, "1 requests received") {
			requestSeen = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	AssertEqual(true, requestSeen, lastStats)

	_, err = conn.Write([]byte(s.VppIfName() + strings.Repeat("x", 512)))
	AssertNil(err, fmt.Sprint(err))

	protocolError := false
	for i := 0; i < 30; i++ {
		lastStats = vpp.Vppctl("show http stats")
		if strings.Contains(lastStats, "1 connections protocol error") {
			Log(lastStats)
			protocolError = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	AssertEqual(true, protocolError, lastStats)
}

func HttpHeaderErrorConnectionDropTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers debug max-body-size 12"))
	request := "POST /interface_stats.json HTTP/1.1\r\nHost: example.com\r\nContent-Length: 18234234\r\n\r\n" + s.VppIfName()
	conn, err := net.DialTimeout("tcp", serverAddress, time.Second*30)
	AssertNil(err, fmt.Sprint(err))
	err = conn.SetDeadline(time.Now().Add(time.Second * 10))
	AssertNil(err, fmt.Sprint(err))
	_, err = conn.Write([]byte(request))
	AssertNil(err, fmt.Sprint(err))
	reply := make([]byte, 1024)
	_, err = conn.Read(reply)
	AssertNil(err, fmt.Sprint(err))
	AssertContains(string(reply), "HTTP/1.1 413 Content Too Large")
	check := make([]byte, 1)
	_, err = conn.Read(check)
	AssertEqual(err, io.EOF)
}
func HttpMethodNotImplementedTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	vpp.Vppctl("http cli server uri http://" + serverAddress)

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("OPTIONS", "http://"+serverAddress+"/show/version", nil)
	AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	Log(DumpHttpResp(resp, true))
	AssertHttpStatus(resp, 501)
	AssertHttpHeaderNotPresent(resp, "Content-Type")
	AssertHttpContentLength(resp, int64(0))
}

func HttpVersionNotSupportedTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	vpp.Vppctl("http cli server uri http://" + serverAddress)

	resp, err := TcpSendReceive(serverAddress, "GET / HTTP/2\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 505 HTTP Version Not Supported")
}

func HttpUriDecodeTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	vpp.Vppctl("http cli server uri http://" + serverAddress)

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "http://"+serverAddress+"/sh%6fw%20versio%6E%20verbose", nil)
	AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	Log(DumpHttpResp(resp, true))
	AssertHttpStatus(resp, 200)
	data, err := io.ReadAll(resp.Body)
	AssertNil(err, fmt.Sprint(err))
	AssertNotContains(string(data), "unknown input")
	AssertContains(string(data), "Compiler")
	AssertHttpHeaderWithValue(resp, "Content-Type", "text/html")
}

func HttpAbsoluteFormUriTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	vpp.Vppctl("http cli server uri http://" + serverAddress)

	resp, err := TcpSendReceive(serverAddress, "GET http://"+serverAddress+"/show/version HTTP/1.1\r\nHost: "+serverAddress+"\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 200 OK")
}

func HttpInvalidAuthorityFormUriTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	vpp.Vppctl("test proxy server fifo-size 512k server-uri http://%s", serverAddress)

	resp, err := TcpSendReceive(serverAddress, "CONNECT 1.2.3.4:80a HTTP/1.1\r\nHost: example.com\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request")

	resp, err = TcpSendReceive(serverAddress, "CONNECT 1.2.3.4:80000000 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request")

	resp, err = TcpSendReceive(serverAddress, "CONNECT 1.2a3.4:80 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request")

	resp, err = TcpSendReceive(serverAddress, "CONNECT 1.2.4:80 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request")

	resp, err = TcpSendReceive(serverAddress, "CONNECT [dead:beef::1234:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request")

	resp, err = TcpSendReceive(serverAddress, "CONNECT [zyx:beef::1234]:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request")

	resp, err = TcpSendReceive(serverAddress, "CONNECT dead:beef::1234:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request")

	resp, err = TcpSendReceive(serverAddress, "CONNECT example.org:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request", "name resolution not supported")
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
	AssertNil(err, fmt.Sprint(err))
	req.Header.Add("Accept", "text/xml")
	req.Header.Add("Accept-Language", "*")
	req.Header.Add("X&Name", "valid-token")
	req.Header.Add("Accept", "text/plain")
	req.Header.Add("Accept", "text/html")
	resp, err := client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	Log(DumpHttpResp(resp, true))
	AssertHttpStatus(resp, 200)
	AssertHttpHeaderWithValue(resp, "Content-Type", "text/plain")
	data, err := io.ReadAll(resp.Body)
	AssertNil(err, fmt.Sprint(err))
	AssertNotContains(string(data), "<html>", "html content received instead of plain text")

	req2, err := http.NewRequest("GET", "http://"+serverAddress+"/show/version", nil)
	AssertNil(err, fmt.Sprint(err))
	req2.Header.Add("Accept", "text/html")
	resp2, err := client.Do(req2)
	AssertNil(err, fmt.Sprint(err))
	defer resp2.Body.Close()
	Log(DumpHttpResp(resp2, true))
	AssertHttpStatus(resp2, 200)
	AssertHttpHeaderWithValue(resp2, "Content-Type", "text/html")
	data2, err := io.ReadAll(resp2.Body)
	AssertNil(err, fmt.Sprint(err))
	AssertContains(string(data2), "<html>", "html content not received")

	/* test cleanup */
	client.CloseIdleConnections()
	for range 10 {
		o := vpp.Vppctl("show session verbose 2")
		if !strings.Contains(o, serverAddress+"->"+s.HostAddr()) {
			break
		}
		time.Sleep(1 * time.Second)
	}
}

func HttpMissingHostHeaderTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	vpp.Vppctl("http cli server uri http://" + serverAddress)

	requestLines := []string{
		"GET /show/version HTTP/1.1\r\n",
		"GET http://" + serverAddress + "/show/version HTTP/1.1\r\n",
		"CONNECT 1.2.3.4:443 HTTP/1.1\r\n",
	}
	for _, requestLine := range requestLines {
		for _, headers := range []string{"", "User-Agent: hs-test\r\n"} {
			request := requestLine + headers + "\r\n"
			resp, err := TcpSendReceive(serverAddress, request)
			AssertNil(err, fmt.Sprint(err))
			AssertContains(resp, "HTTP/1.1 400 Bad Request", fmt.Sprintf("missing Host accepted: %q", request))
		}
	}

	// Host field name is case-insensitive
	resp, err := TcpSendReceive(serverAddress, "GET /show/version HTTP/1.1\r\nhOsT: "+serverAddress+"\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 200 OK")
}

func HttpInvalidHeadersTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	vpp.Vppctl("http cli server uri http://" + serverAddress)

	resp, err := TcpSendReceive(serverAddress, "GET /show/version HTTP/1.1\r\nHost:"+serverAddress+"\r\nUser@Agent:test\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request", "'@' not allowed in field name")

	resp, err = TcpSendReceive(serverAddress, "GET /show/version HTTP/1.1\r\nHost:"+serverAddress+"\r\nUser-Agent\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request", "incomplete field line not allowed")

	resp, err = TcpSendReceive(serverAddress, "GET /show/version HTTP/1.1\r\nHost:"+serverAddress+"\r\n: test\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request", "empty field name not allowed")

	resp, err = TcpSendReceive(serverAddress, "GET /show/version HTTP/1.1\r\nHost:"+serverAddress+"\rUser-Agent:test\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request", "invalid field line end not allowed")

	resp, err = TcpSendReceive(serverAddress, "GET /show/version HTTP/1.1\r\nHost:"+serverAddress+"\nUser-Agent:test\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request", "invalid field line end not allowed")

	resp, err = TcpSendReceive(serverAddress, "GET /show/version HTTP/1.1\r\nHost:"+serverAddress+"\r\nUser-Agent:\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request", "empty field value not allowed")

	resp, err = TcpSendReceive(serverAddress, "GET /show/version HTTP/1.1\r\nHost:"+serverAddress+"\r\nUser-Agent:    \r\n\r\n")
	AssertNil(err, fmt.Sprint(err))
	AssertContains(resp, "HTTP/1.1 400 Bad Request", "empty field value not allowed")
}

func HeaderServerTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	vpp.Vppctl("http cli server uri http://" + serverAddress)

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "http://"+serverAddress+"/show/version", nil)
	AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	Log(DumpHttpResp(resp, true))
	AssertHttpStatus(resp, 200)
	AssertHttpHeaderWithValue(resp, "Server", "http_cli_server")
	AssertHttpHeaderWithValue(resp, "Content-Type", "text/html")
}

func HttpConnTimeoutTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers debug keepalive-timeout 2"))

	req := "GET /version.json HTTP/1.1\r\nHost:" + serverAddress + "\r\nUser-Agent:test\r\n\r\n"
	conn, err := net.DialTimeout("tcp", serverAddress, time.Second*30)
	AssertNil(err, fmt.Sprint(err))
	defer conn.Close()
	err = conn.SetDeadline(time.Now().Add(time.Second * 30))
	AssertNil(err, fmt.Sprint(err))
	_, err = conn.Write([]byte(req))
	AssertNil(err, fmt.Sprint(err))
	reply := make([]byte, 1024)
	_, err = conn.Read(reply)
	AssertNil(err, fmt.Sprint(err))
	AssertContains(string(reply), "HTTP/1.1 200 OK")
	Log(vpp.Vppctl("show session verbose 2"))

	Log("waiting for close on the server side")
	time.Sleep(time.Second * 5)
	Log(vpp.Vppctl("show session verbose 2"))

	_, err = conn.Write([]byte(req))
	AssertNil(err, fmt.Sprint(err))
	reply = make([]byte, 1024)
	_, err = conn.Read(reply)
	AssertMatchError(err, io.EOF, "connection not closed by server")
	o := vpp.Vppctl("show http stats")
	Log(o)
	AssertContains(o, "1 connections timeout")
}

// Cover the request-line substates and retained HTTP/2 magic as well as headers
// with the same FIN, RST and inactivity-timeout matrix.
var http1PartialRequestPrefixes = []string{
	"G",
	"P",
	"PR",
	"\r",
	"\r\nG",
	"GET /version.json?x=a",
	"GET /version.json HTT",
	"GET /version.json HTTP/1.",
	"GET /version.json HTTP/1.1",
	"GET /version.json HTTP/1.1\r",
	"PRI * HTTP/2.0\r\n",
	"GET /version.json HTTP/1.1\r\n",
	"GET /version.json HTTP/1.1\r\nHost",
	"GET /version.json HTTP/1.1\r\nHost: ",
	"GET /version.json HTTP/1.1\r\nHost: example",
	"GET /version.json HTTP/1.1\r\nHost: example.com\r",
	"GET /version.json HTTP/1.1\r\nHost: example.com\r\n\r",
	"GET /version.json HTTP/1.1\r\nHost: example.com\r\nX-Incomplete:",
}

// HttpIncompleteHeadersTimeoutTest checks that stalled partial requests expire.
// Start a server with a two-second inactivity timeout, send each partial request,
// verify it initially waits, then stop sending and expect EOF or a TCP reset.
// Require one HTTP timeout per connection and no protocol errors.
func HttpIncompleteHeadersTimeoutTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	vpp.Vppctl("http static server uri tcp://%s url-handlers keepalive-timeout 2", address)
	partials := http1PartialRequestPrefixes
	for _, partial := range partials {
		Log("Checking inactivity timeout for partial request %q", partial)
		conn, err := net.DialTimeout("tcp", address, defaultHttpTimeout)
		AssertNil(err)
		func() {
			defer conn.Close()
			AssertNil(conn.SetWriteDeadline(time.Now().Add(defaultHttpTimeout)))
			n, err := io.WriteString(conn, partial)
			AssertNil(err)
			AssertEqual(len(partial), n)

			// Partial input must wait for more data rather than fail immediately.
			AssertNil(conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)))
			var b [1]byte
			n, err = conn.Read(b[:])
			AssertEqual(0, n)
			timeout, ok := err.(net.Error)
			AssertEqual(true, ok && timeout.Timeout())

			// Send nothing else. The HTTP inactivity timer must close the
			// connection before the client's longer read deadline expires.
			AssertNil(conn.SetReadDeadline(time.Now().Add(defaultHttpTimeout)))
			n, err = conn.Read(b[:])
			AssertEqual(0, n)
			// TCP may reset on close because the partial request is still unread.
			AssertEqual(true, errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET),
				fmt.Sprintf("partial request was not closed by the server: %v", err))
		}()
	}
	stats := vpp.Vppctl("show http stats")
	AssertContains(stats, fmt.Sprintf("%d connections timeout", len(partials)))
	AssertNotContains(stats, "connections protocol error")
}

func HttpIgnoreH2UpgradeTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers"))

	transport := http.DefaultTransport
	transport.(*http.Transport).Proxy = nil
	transport.(*http.Transport).DisableKeepAlives = false
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Second * 30,
	}

	req, err := http.NewRequest("GET", "http://"+serverAddress+"/version.json", nil)
	AssertNil(err, fmt.Sprint(err))
	req.Header.Add("Connection", "Upgrade")
	req.Header.Add("Upgrade", "HTTP/2.0")
	resp, err := client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	Log(DumpHttpResp(resp, true))
	AssertHttpStatus(resp, 200)
	AssertHttpHeaderNotPresent(resp, "Upgrade")
}

func HttpSendGetAndCloseTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http

	vpp.Container.Exec(false, "mkdir -p "+wwwRootPath)
	content := "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	err := vpp.Container.CreateFile(wwwRootPath+"/index.html", content)
	AssertNil(err, fmt.Sprint(err))
	Log(vpp.Vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress + " private-segment-size 256m"))

	err = TcpSendAndClose(serverAddress, "GET http://www.example.com/index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
	AssertNil(err, fmt.Sprint(err))

	// mostly to verify that vpp is still up
	o := vpp.Vppctl("show session verbose proto http")
	Log(o)
	AssertNotContains(o, "established")
}

func HttpTsFifoMemPressureMWTest(s *Http1Suite) {
	var httpConfig Stanza
	httpConfig.NewStanza("http").Append("first-segment-size 4m").Append("add-segment-size 4m").Close()
	s.CpusPerVppContainer = 2

	s.SetupTest(httpConfig)
	vpp := s.Containers.Vpp.VppInstance
	vpp.Container.Exec(false, "mkdir -p "+wwwRootPath)
	serverAddress := "http://" + s.VppAddr() + ":" + s.Ports.Http
	resourceName := "/test_file_10M"
	url := serverAddress + resourceName

	fileName := wwwRootPath + resourceName
	Log(vpp.Container.Exec(false, "fallocate -l 10MB "+fileName))
	Log(vpp.Container.Exec(false, "ls -la "+fileName))
	Log(vpp.Vppctl("http static server cache-size 128m www-root " + wwwRootPath + " uri " + serverAddress))

	s.Containers.Curl.ExtraRunningArgs = fmt.Sprintf("/usr/bin/slow_reader.sh %s 1M 15", url)
	s.Containers.Curl.Run()
	Log(vpp.Vppctl("show session"))
	stdout, _ := s.Containers.Curl.GetOutput()
	Log(stdout)
}

func HttpTpsTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverUri := "http://" + s.VppAddr() + ":" + s.Ports.Http
	serverUriHttps := "https://" + s.VppAddr() + ":" + s.Ports.Https
	url := serverUri + "/test_file_10M"

	Log(vpp.Vppctl("http tps uri %s", serverUri))
	o := vpp.Vppctl("show http tps")
	Log(o)
	AssertContains(o, "listeners: 1")
	o = vpp.Vppctl("show http tps listeners")
	Log(o)
	AssertContains(o, serverUri)
	Log(vpp.Vppctl("http tps listener add uri %s", serverUriHttps))
	o = vpp.Vppctl("show http tps")
	Log(o)
	AssertContains(o, "listeners: 2")
	o = vpp.Vppctl("show http tps listeners")
	Log(o)
	AssertContains(o, serverUriHttps)
	Log(vpp.Vppctl("http tps listener add uri %s h3", serverUriHttps))
	o = vpp.Vppctl("show http tps")
	Log(o)
	AssertContains(o, "listeners: 3")
	o = vpp.Vppctl("show http tps listeners")
	Log(o)
	AssertContains(o, serverUriHttps+"[h3]")
	Log(vpp.Vppctl("http tps listener del uri %s h3", serverUriHttps))
	o = vpp.Vppctl("show http tps")
	Log(o)
	AssertContains(o, "listeners: 2")
	o = vpp.Vppctl("show http tps listeners")
	Log(o)
	AssertNotContains(o, serverUriHttps+"[h3]")
	AssertContains(o, serverUriHttps)
	Log(vpp.Vppctl("http tps listener del uri %s", serverUriHttps))
	o = vpp.Vppctl("show http tps")
	Log(o)
	AssertContains(o, "listeners: 1")
	o = vpp.Vppctl("show http tps listeners")
	Log(o)
	AssertContains(o, serverUri)
	AssertNotContains(o, serverUriHttps)

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", url, nil)
	AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	Log(DumpHttpResp(resp, true))
	AssertHttpStatus(resp, 200)
	AssertHttpContentLength(resp, 10<<20)
	AssertHttpHeaderWithValue(resp, "Content-Type", "application/octet-stream")
	AssertHttpHeaderWithValue(resp, "Cache-Control", "no-store, no-cache, max-age=0, no-transform")
	_, err = io.ReadAll(resp.Body)
	AssertNil(err, fmt.Sprint(err))

	Log(vpp.Vppctl("http tps disable"))
	o = vpp.Vppctl("show app")
	AssertNotContains(o, "http_tps")
	o = vpp.Vppctl("show session")
	Log(o)
	AssertContains(o, "no sessions")

	Log(vpp.Vppctl("http tps fifo-size 4M private-segment-size 256M"))
	o = vpp.Vppctl("show http tps")
	Log(o)
	AssertContains(o, "listeners: 0")
}

func tpsReq(url string, timeout time.Duration) {
	client := NewHttpClient(timeout, false)
	req, err := http.NewRequest("GET", url, nil)
	AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	AssertHttpStatus(resp, 200)
	_, err = io.ReadAll(resp.Body)
	AssertNil(err, fmt.Sprint(err))
}

func HttpTpsMemLeakTest(s *Http1Suite) {
	s.SkipUnlessLeakCheck()

	vpp := s.Containers.Vpp.VppInstance
	serverUri := "http://" + s.VppAddr() + ":" + s.Ports.Http
	url := serverUri + "/test_file_10M"

	/* no goVPP less noise */
	vpp.Disconnect()

	Log(vpp.Vppctl("http tps uri %s", serverUri))

	/* warmup requests (FIB, pool allocations) */
	for range 5 {
		time.Sleep(time.Second * 1)
		tpsReq(url, defaultHttpTimeout)
	}

	/* let's give it some time to clean up sessions, so pool elements can be reused and we have less noise */
	time.Sleep(time.Second * 12)

	vpp.EnableMemoryTrace()
	traces1, err := vpp.GetMemoryTrace()
	AssertNil(err, fmt.Sprint(err))

	/* do couple of requests */
	for range 5 {
		time.Sleep(time.Second * 1)
		tpsReq(url, defaultHttpTimeout)
	}

	/* let's give it some time to clean up sessions */
	time.Sleep(time.Second * 12)

	traces2, err := vpp.GetMemoryTrace()
	AssertNil(err, fmt.Sprint(err))
	vpp.MemLeakCheck(traces1, traces2)
}

// HttpFragmentedHeadersTest checks that valid requests can span receive events.
// Send a long URI query and large headers in fragments, splitting tokens and CRLF,
// and repeat on the same connection. Expect no response until headers complete,
// then a 200 response for each request, counted once, with no protocol errors.
func HttpFragmentedHeadersTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	vpp.Vppctl("http static server uri tcp://%s url-handlers fifo-size 64k", address)
	conn, err := net.DialTimeout("tcp", address, defaultHttpTimeout)
	AssertNil(err)
	defer conn.Close()
	reader := bufio.NewReader(conn)

	// Repeat on the same connection to check that retrying header parsing does
	// not leave stale offsets or headers for the next request.
	for range 2 {
		fragments := []string{
			"\r", "\nG", "ET /version.json?padding=", strings.Repeat("x", 16*1024),
			" HTTP/1.", "1\r", "\n", "Host", ":", " ", address, "\r", "\n",
			"X-Large: ", strings.Repeat("x", 16*1024), "\r", "\nX-Last", ": ", "value", "\r", "\n", "\r", "\n",
		}
		for i, fragment := range fragments {
			AssertNil(conn.SetWriteDeadline(time.Now().Add(defaultHttpTimeout)))
			n, err := io.WriteString(conn, fragment)
			AssertNil(err)
			AssertEqual(len(fragment), n)
			if i == len(fragments)-1 {
				break
			}
			// Give VPP time to process each fragment and verify it neither
			// responds nor closes the connection before the final CRLF.
			AssertNil(conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)))
			var b [1]byte
			n, err = conn.Read(b[:])
			AssertEqual(0, n, fmt.Sprintf("fragment %d (%q): received %q, err %v", i, fragment, b[:n], err))
			timeout, ok := err.(net.Error)
			AssertEqual(true, ok && timeout.Timeout(), fmt.Sprintf("fragment %d: %v", i, err))
		}
		AssertNil(conn.SetReadDeadline(time.Now().Add(defaultHttpTimeout)))
		response, err := http.ReadResponse(reader, nil)
		AssertNil(err)
		AssertHttpStatus(response, http.StatusOK)
		body, err := io.ReadAll(response.Body)
		AssertNil(err)
		AssertNil(response.Body.Close())
		AssertContains(string(body), "build_date")
	}
	stats := vpp.Vppctl("show http stats")
	AssertContains(stats, "2 requests received")
	AssertNotContains(stats, "connections protocol error")
}

// Keep the server connection open until VPP closes it, so a server-side close
// cannot hide a client that is stuck waiting for incomplete headers.
func http1RawResponse(s *Http1Suite, fragments []string, expectRejection bool,
	closeWrite ...bool) string {
	address := net.JoinHostPort(s.HostAddr(), s.Ports.Http)
	listener, err := net.Listen("tcp", address)
	AssertNil(err)
	defer listener.Close()
	done := make(chan error)
	go func() {
		defer GinkgoRecover()
		defer close(done)
		conn, err := listener.Accept()
		AssertNil(err)
		defer conn.Close()
		AssertNil(conn.SetDeadline(time.Now().Add(30 * time.Second)))
		request, err := http.ReadRequest(bufio.NewReader(conn))
		AssertNil(err)
		AssertNil(request.Body.Close())
		for i, fragment := range fragments {
			n, err := io.WriteString(conn, fragment)
			// A full-FIFO rejection can close the connection before the
			// writer finishes sending bytes beyond the usable TCP window.
			if err != nil && expectRejection {
				timeout, ok := err.(net.Error)
				AssertEqual(false, ok && timeout.Timeout())
				return
			}
			AssertNil(err)
			AssertEqual(len(fragment), n)
			if i < len(fragments)-1 {
				time.Sleep(100 * time.Millisecond)
			}
		}
		if len(closeWrite) > 0 && closeWrite[0] {
			AssertNil(conn.(*net.TCPConn).CloseWrite())
		}
		var b [1]byte
		_, err = conn.Read(b[:])
		if expectRejection {
			AssertNotNil(err)
			timeout, ok := err.(net.Error)
			AssertEqual(false, ok && timeout.Timeout())
		} else {
			AssertEqual(io.EOF, err)
		}
	}()
	output := s.Containers.Vpp.VppInstance.Vppctl("http cli client fifo-size 64 uri http://%s/test", address)
	AssertChannelClosed(30*time.Second, done)
	return output
}

// HttpClientFragmentedHeadersTest checks client parsing of fragmented responses.
// Have a raw TCP server split a long status line, large headers, and the body,
// then send a separate response with an empty header section split across writes.
// Expect the complete body or 404 status, each response counted once, and no protocol errors.
func HttpClientFragmentedHeadersTest(s *Http1Suite) {
	body := "fragmented response body"
	fragments := []string{
		"H", "TTP/1.1 200 ", strings.Repeat("x", 4*1024), "\r", "\n",
		"Content-Len", "gth:", " ", fmt.Sprint(len(body)), "\r", "\n",
		"X-Large: ", strings.Repeat("x", 16*1024), "\r", "\nX-Last", ": ", "value", "\r", "\n", "\r",
		"\n" + body[:8], body[8:],
	}
	AssertContains(http1RawResponse(s, fragments, false), body)

	// No header fields: both bytes of the empty header section arrive later
	// than the complete status line. Use an error status with no response body.
	output := http1RawResponse(s, []string{"HTTP/1.1 404 Not Found\r\n", "\r", "\n"}, false)
	AssertContains(output, "request failed, response code:")
	AssertContains(output, "404")
	// Cross bounded lookahead edges in both status-line and header scans,
	// with the complete body already available in the same transport burst.
	for _, boundary := range []int{253, 254, 255, 256, 257} {
		fields := fmt.Sprintf("Content-Length: %d\r\nX-Pad: ", len(body))
		fields += strings.Repeat("x", boundary-len(fields))
		output := http1RawResponse(s, []string{"HTTP/1.1 200 OK\r\n" + fields + "\r\n\r\n" + body}, false)
		AssertContains(output, body)
	}
	for _, boundary := range []int{255, 256, 257} {
		line := "HTTP/1.1 200 "
		line += strings.Repeat("x", boundary-len(line)) + "\r\n"
		fields := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body))
		AssertContains(http1RawResponse(s, []string{line + fields + body}, false), body)
	}
	stats := s.Containers.Vpp.VppInstance.Vppctl("show http stats")
	AssertContains(stats, "10 responses received")
	AssertNotContains(stats, "connections protocol error")
}

// The HTTP transport's default RX FIFO size (http_transport_init).
const http1TransportFifoSize = 512 * 1024

// HttpIncompleteHeadersFullFifoTest checks prompt rejection when no more header bytes can arrive.
// Start a server and fill its usable transport RX capacity with an unfinished
// request line, header name, or header value. Expect a 431 response before the
// client deadline and one protocol error for each rejected connection.
func HttpIncompleteHeadersFullFifoTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	vpp.Vppctl("http cli server uri http://%s", address)
	for _, prefix := range []string{
		"GET /",
		"GET /show/version HTTP/1.1\r\nHost: example.com\r\nX-Long-Name",
		"GET /show/version HTTP/1.1\r\nHost: example.com\r\nX-Long-Value: ",
	} {
		conn, err := net.DialTimeout("tcp", address, defaultHttpTimeout)
		AssertNil(err)
		func() {
			defer conn.Close()
			AssertNil(conn.SetDeadline(time.Now().Add(defaultHttpTimeout)))
			message := prefix + strings.Repeat("x", http1TransportFifoSize-len(prefix))
			n, err := io.WriteString(conn, message)
			if err != nil {
				// The server can reject the request before all queued bytes
				// have been sent. Still require its 431 response below.
				timeout, ok := err.(net.Error)
				AssertEqual(false, ok && timeout.Timeout())
			} else {
				AssertEqual(len(message), n)
			}
			response, err := http.ReadResponse(bufio.NewReader(conn), nil)
			AssertNil(err)
			AssertHttpStatus(response, http.StatusRequestHeaderFieldsTooLarge)
			AssertNil(response.Body.Close())
		}()
	}
	AssertContains(vpp.Vppctl("show http stats"), "3 connections protocol error")
}

// HttpClientIncompleteHeadersFullFifoTest checks the corresponding client rejection path.
// Have a raw TCP server fill the client's usable transport RX capacity with an
// unfinished status line, header name, or header value, then wait for VPP to close.
// Expect transport-closed errors rather than timeouts, and one protocol error per connection.
func HttpClientIncompleteHeadersFullFifoTest(s *Http1Suite) {
	for _, prefix := range []string{
		"HTTP/1.1 200 ",
		"HTTP/1.1 200 OK\r\nX-Long-Name",
		"HTTP/1.1 200 OK\r\nX-Long-Value: ",
	} {
		message := prefix + strings.Repeat("x", http1TransportFifoSize-len(prefix))
		output := http1RawResponse(s, []string{message}, true)
		AssertContains(output, "transport closed")
		AssertNotContains(output, "timeout")
	}
	AssertContains(s.Containers.Vpp.VppInstance.Vppctl("show http stats"), "3 connections protocol error")
}

// HttpPartialRequestPeerResetTest checks that a reset during the first partial
// request does not notify the application before its session is accepted.
func HttpPartialRequestPeerResetTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	vpp.Vppctl("http static server uri tcp://%s url-handlers", address)
	for i, partial := range http1PartialRequestPrefixes {
		Log("Checking RST for partial request %q", partial)
		func() {
			conn, err := net.DialTimeout("tcp", address, defaultHttpTimeout)
			AssertNil(err)
			defer conn.Close()
			AssertNil(conn.SetWriteDeadline(time.Now().Add(defaultHttpTimeout)))
			_, err = io.WriteString(conn, partial)
			AssertNil(err)
			AssertNil(conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)))
			var b [1]byte
			n, readErr := conn.Read(b[:])
			AssertEqual(0, n)
			timeout, ok := readErr.(net.Error)
			AssertEqual(true, ok && timeout.Timeout(), fmt.Sprint(readErr))
			AssertNil(conn.(*net.TCPConn).SetLinger(0))
			AssertNil(conn.Close())
		}()
		expected := fmt.Sprintf("%d connections reset by peer", i+1)
		var stats string
		for range 20 {
			stats = vpp.Vppctl("show http stats")
			if strings.Contains(stats, expected) {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		AssertContains(stats, expected)
		AssertNotContains(stats, "connections accepted")
		AssertNotContains(stats, "connections protocol error")
	}
}

// HttpPartialRequestPeerFinTest checks that FIN during an unaccepted request
// closes promptly and frees the pending session without notifying the app.
func HttpPartialRequestPeerFinTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	vpp.Vppctl("http static server uri tcp://%s url-handlers", address)
	baseline := vpp.Vppctl("show session")
	for _, partial := range http1PartialRequestPrefixes {
		Log("Checking FIN for partial request %q", partial)
		func() {
			conn, err := net.DialTimeout("tcp", address, defaultHttpTimeout)
			AssertNil(err)
			defer conn.Close()
			AssertNil(conn.SetWriteDeadline(time.Now().Add(defaultHttpTimeout)))
			n, err := io.WriteString(conn, partial)
			AssertNil(err)
			AssertEqual(len(partial), n)

			// Give RX processing time to stage the unpublished bytes. The
			// server must wait for more input until the peer sends FIN.
			AssertNil(conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)))
			var b [1]byte
			n, err = conn.Read(b[:])
			AssertEqual(0, n)
			timeout, ok := err.(net.Error)
			AssertEqual(true, ok && timeout.Timeout(), fmt.Sprint(err))
			AssertNil(conn.(*net.TCPConn).CloseWrite())
			AssertNil(conn.SetReadDeadline(time.Now().Add(2 * time.Second)))
			n, err = conn.Read(b[:])
			AssertEqual(0, n)
			AssertEqual(io.EOF, err)
		}()

		// Include the pending application session in the cleanup check,
		// not just the transport connection observed by the peer.
		var sessions string
		for range 20 {
			sessions = vpp.Vppctl("show session")
			if sessions == baseline {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		AssertEqual(baseline, sessions)
	}
	stats := vpp.Vppctl("show http stats")
	AssertNotContains(stats, "connections accepted")
	AssertNotContains(stats, "connections timeout")
	AssertNotContains(stats, "connections protocol error")
}

// HttpPartialRequestListenerRemovedTest checks that completing a partial first
// request cannot accept a session after its listener has been removed.
func HttpPartialRequestListenerRemovedTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	// Keep another listener so removing the tested listener does not detach
	// the app and close its sessions through the application cleanup path.
	otherAddress := net.JoinHostPort(s.VppAddr(), s.Ports.Https)
	AssertEqual("", vpp.Vppctl("http cli server uri http://%s", otherAddress))
	baseline := vpp.Vppctl("show session")
	request := "GET /show/version HTTP/1.1\r\nHost: example.com\r\n\r\n"
	for _, split := range []int{
		len("GET /show/"),
		strings.Index(request, "Host"),
		strings.Index(request, "Host") + 2,
		len(request) - 4,
		len(request) - 1,
	} {
		Log("Removing listener after partial request %q", request[:split])
		AssertEqual("", vpp.Vppctl("http cli server listener add uri http://%s", address))
		func() {
			conn, err := net.DialTimeout("tcp", address, defaultHttpTimeout)
			AssertNil(err)
			defer conn.Close()
			AssertNil(conn.SetWriteDeadline(time.Now().Add(defaultHttpTimeout)))
			_, err = io.WriteString(conn, request[:split])
			AssertNil(err)
			AssertNil(conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)))
			var b [1]byte
			n, err := conn.Read(b[:])
			AssertEqual(0, n)
			timeout, ok := err.(net.Error)
			AssertEqual(true, ok && timeout.Timeout(), fmt.Sprint(err))
			AssertContains(vpp.Vppctl("show session verbose 2 proto http state accepting"),
				"session: state: accepting")

			AssertEqual("", vpp.Vppctl("http cli server listener del uri http://%s", address))
			AssertNotContains(vpp.Vppctl("show session verbose proto http state listening"), address)
			_, err = io.WriteString(conn, request[split:])
			AssertNil(err)
			AssertNil(conn.SetReadDeadline(time.Now().Add(2 * time.Second)))
			n, err = conn.Read(b[:])
			AssertEqual(0, n, "removed listener must not receive a request or send a response")
			AssertEqual(io.EOF, err)
		}()

		// This active close retains the transport and pending app session
		// until TCP's ten-second TIME_WAIT expires and invokes cleanup.
		var sessions string
		for range 75 {
			sessions = vpp.Vppctl("show session")
			if sessions == baseline {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		AssertEqual(baseline, sessions, "pending transport and app sessions must be freed")
	}
	stats := vpp.Vppctl("show http stats")
	AssertNotContains(stats, "connections accepted")
	AssertNotContains(stats, "responses sent")
	AssertNotContains(stats, "connections timeout")
	AssertNotContains(stats, "connections protocol error")

	// The application and its other listener remain usable.
	client := NewHttpClient(defaultHttpTimeout, false)
	defer client.CloseIdleConnections()
	response, err := client.Get("http://" + otherAddress + "/show/version")
	AssertNil(err)
	defer response.Body.Close()
	AssertHttpStatus(response, http.StatusOK)
	_, err = io.Copy(io.Discard, response.Body)
	AssertNil(err)
	AssertContains(vpp.Vppctl("show http stats"), "1 connections accepted")
}

// HttpClientPartialResponseFinTest checks that FIN during response headers
// closes the pending request promptly instead of waiting for its timeout.
func HttpClientPartialResponseFinTest(s *Http1Suite) {
	output := http1RawResponse(s, []string{"HTTP/1.1 200 OK\r\n"}, true, true)
	AssertContains(output, "transport closed")
	AssertNotContains(output, "timeout")
	AssertContains(s.Containers.Vpp.VppInstance.Vppctl("show http stats"),
		"1 connections protocol error")
}

// HttpHeaderListSizeLimitTest checks request and response boundaries with the
// final empty line arriving together, separately, or with CR and LF split.
func HttpHeaderListSizeLimitTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	vpp.Vppctl("http static server uri tcp://%s url-handlers", address)

	const limit = 128
	fragments := func(prefix, body string, split int) []string {
		switch split {
		case 0:
			return []string{prefix + "\r\n" + body}
		case 1:
			return []string{prefix, "\r\n" + body}
		default:
			return []string{prefix + "\r", "\n" + body}
		}
	}
	for _, size := range []int{limit - 1, limit, limit + 1} {
		for split := range 3 {
			Log("request headers: %d bytes, terminator split %d", size, split)
			func() {
				conn, err := net.DialTimeout("tcp", address, defaultHttpTimeout)
				AssertNil(err)
				defer conn.Close()
				fields := "Host: example.com\r\nX-Limit: "
				fields += strings.Repeat("x", size-len(fields)-2) + "\r\n"
				AssertEqual(size, len(fields))
				parts := fragments("GET /version.json HTTP/1.1\r\n"+fields, "", split)
				if size > limit {
					// Reject oversized fields without waiting for a missing terminator.
					parts = parts[:1]
				}
				for i, part := range parts {
					AssertNil(conn.SetWriteDeadline(time.Now().Add(defaultHttpTimeout)))
					_, err = io.WriteString(conn, part)
					AssertNil(err)
					if i < len(parts)-1 {
						AssertNil(conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)))
						var b [1]byte
						n, readErr := conn.Read(b[:])
						AssertEqual(0, n)
						timeout, ok := readErr.(net.Error)
						AssertEqual(true, ok && timeout.Timeout(), fmt.Sprint(readErr))
					}
				}
				AssertNil(conn.SetReadDeadline(time.Now().Add(defaultHttpTimeout)))
				response, err := http.ReadResponse(bufio.NewReader(conn), nil)
				AssertNil(err)
				status := http.StatusOK
				if size > limit {
					status = http.StatusRequestHeaderFieldsTooLarge
				}
				AssertHttpStatus(response, status)
				AssertNil(response.Body.Close())
			}()

			Log("response headers: %d bytes, terminator split %d", size, split)
			body := "limit-ok"
			fields := fmt.Sprintf("Content-Length: %d\r\nX-Limit: ", len(body))
			fields += strings.Repeat("x", size-len(fields)-2) + "\r\n"
			AssertEqual(size, len(fields))
			parts := fragments("HTTP/1.1 200 OK\r\n"+fields, body, split)
			if size > limit {
				parts = parts[:1]
			}
			output := http1RawResponse(s, parts, size > limit)
			if size > limit {
				AssertContains(output, "transport closed")
				AssertNotContains(output, "timeout")
			} else {
				AssertEqual(body, strings.TrimSpace(output))
			}
		}
	}
}

// HttpOversizedHeaderNameTest checks that an overflowing u16 name length
// cannot make a long name match the Content-Length prefix.
func HttpOversizedHeaderNameTest(s *Http1Suite) {
	vpp := s.Containers.Vpp.VppInstance
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	vpp.Vppctl("http static server uri tcp://%s url-handlers", address)

	conn, err := net.DialTimeout("tcp", address, defaultHttpTimeout)
	AssertNil(err)
	defer conn.Close()
	AssertNil(conn.SetDeadline(time.Now().Add(defaultHttpTimeout)))
	request := "GET /version.json HTTP/1.1\r\nHost: example.com\r\nContent-Length" +
		strings.Repeat("x", 65536) + ": invalid\r\n\r\n"
	_, err = io.WriteString(conn, request)
	AssertNil(err)
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	AssertNil(err)
	AssertHttpStatus(response, http.StatusRequestHeaderFieldsTooLarge)
	AssertNil(response.Body.Close())
}
