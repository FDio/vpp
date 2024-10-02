package main

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/onsi/gomega/ghttp"
	"github.com/onsi/gomega/gmeasure"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterVethTests(HttpCliTest, HttpCliConnectErrorTest)
	RegisterSoloVethTests(HttpClientGetMemLeakTest)
	RegisterNoTopoTests(HeaderServerTest, HttpPersistentConnectionTest, HttpPipeliningTest,
		HttpStaticMovedTest, HttpStaticNotFoundTest, HttpCliMethodNotAllowedTest,
		HttpCliBadRequestTest, HttpStaticBuildInUrlGetIfStatsTest, HttpStaticBuildInUrlPostIfStatsTest,
		HttpInvalidRequestLineTest, HttpMethodNotImplementedTest, HttpInvalidHeadersTest,
		HttpContentLengthTest, HttpStaticBuildInUrlGetIfListTest, HttpStaticBuildInUrlGetVersionTest,
		HttpStaticMacTimeTest, HttpStaticBuildInUrlGetVersionVerboseTest, HttpVersionNotSupportedTest,
		HttpInvalidContentLengthTest, HttpInvalidTargetSyntaxTest, HttpStaticPathTraversalTest, HttpUriDecodeTest,
		HttpHeadersTest, HttpStaticFileHandlerTest, HttpStaticFileHandlerDefaultMaxAgeTest, HttpClientTest, HttpClientErrRespTest, HttpClientPostFormTest,
		HttpClientPostFileTest, HttpClientPostFilePtrTest, AuthorityFormTargetTest, HttpRequestLineTest)
	RegisterNoTopoSoloTests(HttpStaticPromTest, HttpGetTpsTest, HttpGetTpsInterruptModeTest, PromConcurrentConnectionsTest,
		PromMemLeakTest, HttpClientPostMemLeakTest, HttpInvalidClientRequestMemLeakTest, HttpPostTpsTest, HttpPostTpsInterruptModeTest,
		PromConsecutiveConnectionsTest)
}

const wwwRootPath = "/tmp/www_root"
const defaultHttpTimeout = time.Second * 10

func httpDownloadBenchmark(s *HstSuite, experiment *gmeasure.Experiment, data interface{}) {
	url, isValid := data.(string)
	s.AssertEqual(true, isValid)
	client := NewHttpClient(defaultHttpTimeout)
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

func HttpGetTpsInterruptModeTest(s *NoTopoSuite) {
	HttpGetTpsTest(s)
}

func HttpGetTpsTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.VppAddr()
	url := "http://" + serverAddress + ":8080/test_file_10M"

	vpp.Vppctl("http tps uri tcp://0.0.0.0/8080")

	s.RunBenchmark("HTTP tps download 10M", 10, 0, httpDownloadBenchmark, url)
}

func httpUploadBenchmark(s *HstSuite, experiment *gmeasure.Experiment, data interface{}) {
	url, isValid := data.(string)
	s.AssertEqual(true, isValid)
	body := make([]byte, 10485760)
	_, err := rand.Read(body)
	client := NewHttpClient(defaultHttpTimeout)
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

func HttpPostTpsInterruptModeTest(s *NoTopoSuite) {
	HttpPostTpsTest(s)
}

func HttpPostTpsTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.VppAddr()
	url := "http://" + serverAddress + ":8080/test_file_10M"

	vpp.Vppctl("http tps uri tcp://0.0.0.0/8080")

	s.RunBenchmark("HTTP tps upload 10M", 10, 0, httpUploadBenchmark, url)
}

func HttpPersistentConnectionTest(s *NoTopoSuite) {
	// testing url handler app do not support multi-thread
	s.SkipIfMultiWorker()
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.VppAddr()
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers"))
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
	req, err := http.NewRequest("POST", "http://"+serverAddress+":80/test3", bytes.NewBuffer(body))
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	s.Log(DumpHttpResp(resp, true))
	s.AssertHttpStatus(resp, 200)
	s.AssertEqual(false, resp.Close)
	s.AssertHttpContentLength(resp, int64(0))
	o1 := vpp.Vppctl("show session verbose proto http state ready")
	s.Log(o1)
	s.AssertContains(o1, "ESTABLISHED")

	req, err = http.NewRequest("GET", "http://"+serverAddress+":80/test1", nil)
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
	s.AssertContains(o2, "ESTABLISHED")
	s.AssertEqual(o1, o2)

	req, err = http.NewRequest("GET", "http://"+serverAddress+":80/test2", nil)
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
	s.AssertContains(o2, "ESTABLISHED")
	s.AssertEqual(o1, o2)

}

func HttpPipeliningTest(s *NoTopoSuite) {
	// testing url handler app do not support multi-thread
	s.SkipIfMultiWorker()
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.VppAddr()
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers debug"))
	s.Log(vpp.Vppctl("test-url-handler enable"))

	req1 := "GET /test_delayed HTTP/1.1\r\nHost:" + serverAddress + ":80\r\nUser-Agent:test\r\n\r\n"
	req2 := "GET /test1 HTTP/1.1\r\nHost:" + serverAddress + ":80\r\nUser-Agent:test\r\n\r\n"

	conn, err := net.DialTimeout("tcp", serverAddress+":80", time.Second*30)
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
	n, err = conn.Read(reply)
	s.AssertNil(err, fmt.Sprint(err))
	s.Log(string(reply))
	s.AssertContains(string(reply), "delayed data", "first request response not received")
	s.AssertNotContains(string(reply), "hello", "second request response received")
	// make sure response for second request is not received later
	_, err = conn.Read(reply)
	s.AssertMatchError(err, os.ErrDeadlineExceeded, "second request response received")
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
	s.AssertContains(o, "</html>", "</html> not found in the result!")
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

func HttpClientTest(s *NoTopoSuite) {
	serverAddress := s.HostAddr()
	server := ghttp.NewUnstartedServer()
	l, err := net.Listen("tcp", serverAddress+":80")
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
	uri := "http://" + serverAddress + "/80"
	vpp := s.GetContainerByName("vpp").VppInstance
	o := vpp.Vppctl("http cli client uri " + uri + " query /test")

	s.Log(o)
	s.AssertContains(o, "<html>", "<html> not found in the result!")
	s.AssertContains(o, "</html>", "</html> not found in the result!")
}

func HttpClientErrRespTest(s *NoTopoSuite) {
	serverAddress := s.HostAddr()
	server := ghttp.NewUnstartedServer()
	l, err := net.Listen("tcp", serverAddress+":80")
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
	uri := "http://" + serverAddress + "/80"
	vpp := s.GetContainerByName("vpp").VppInstance
	o := vpp.Vppctl("http cli client uri " + uri + " query /test")

	s.Log(o)
	s.AssertContains(o, "404: Not Found", "error not found in the result!")
}

func HttpClientPostFormTest(s *NoTopoSuite) {
	serverAddress := s.HostAddr()
	body := "field1=value1&field2=value2"

	server := ghttp.NewUnstartedServer()
	l, err := net.Listen("tcp", serverAddress+":80")
	s.AssertNil(err, fmt.Sprint(err))
	server.HTTPTestServer.Listener = l
	server.AppendHandlers(
		ghttp.CombineHandlers(
			s.LogHttpReq(true),
			ghttp.VerifyRequest("POST", "/test"),
			ghttp.VerifyContentType("application/x-www-form-urlencoded"),
			ghttp.VerifyBody([]byte(body)),
			ghttp.RespondWith(http.StatusOK, nil),
		))
	server.Start()
	defer server.Close()

	uri := "http://" + serverAddress + "/80"
	vpp := s.GetContainerByName("vpp").VppInstance
	o := vpp.Vppctl("http post uri " + uri + " target /test data " + body)

	s.Log(o)
	s.AssertNotContains(o, "error")
}

func httpClientPostFile(s *NoTopoSuite, usePtr bool, fileSize int) {
	serverAddress := s.HostAddr()
	vpp := s.GetContainerByName("vpp").VppInstance
	fileName := "/tmp/test_file.txt"
	s.Log(vpp.Container.Exec("fallocate -l " + strconv.Itoa(fileSize) + " " + fileName))
	s.Log(vpp.Container.Exec("ls -la " + fileName))

	server := ghttp.NewUnstartedServer()
	l, err := net.Listen("tcp", serverAddress+":80")
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

	uri := "http://" + serverAddress + "/80"
	cmd := "http post uri " + uri + " target /test file " + fileName
	if usePtr {
		cmd += " use-ptr"
	}
	o := vpp.Vppctl(cmd)

	s.Log(o)
	s.AssertNotContains(o, "error")
}

func HttpClientPostFileTest(s *NoTopoSuite) {
	httpClientPostFile(s, false, 32768)
}

func HttpClientPostFilePtrTest(s *NoTopoSuite) {
	httpClientPostFile(s, true, 131072)
}

func cliTestAuthority(s *NoTopoSuite, authority string) {
	o := s.GetContainerByName("vpp").VppInstance.Vppctl("test http authority-form " + authority)
	s.AssertNotContains(o, "error")
	s.AssertContains(o, authority)
}

func cliTestAuthorityError(s *NoTopoSuite, authority string) {
	o := s.GetContainerByName("vpp").VppInstance.Vppctl("test http authority-form " + authority)
	s.AssertContains(o, "error")
}

func AuthorityFormTargetTest(s *NoTopoSuite) {
	cliTestAuthority(s, "10.10.2.45:20")
	cliTestAuthority(s, "[dead:beef::1234]:443")
	cliTestAuthorityError(s, "example.com:80")
	cliTestAuthorityError(s, "10.10.2.45")
	cliTestAuthorityError(s, "1000.10.2.45:20")
	cliTestAuthorityError(s, "[xyz0::1234]:443")
}

func HttpStaticPromTest(s *NoTopoSuite) {
	query := "stats.prom"
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.VppAddr()
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers"))
	s.Log(vpp.Vppctl("prom enable"))
	time.Sleep(time.Second * 5)
	client := NewHttpClient(defaultHttpTimeout)
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/"+query, nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, false))
	s.AssertHttpStatus(resp, 200)
	s.AssertHttpHeaderWithValue(resp, "Content-Type", "text/plain")
	s.AssertGreaterThan(resp.ContentLength, 0)
	_, err = io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
}

func promReq(s *NoTopoSuite, url string, timeout time.Duration) {
	client := NewHttpClient(timeout)
	req, err := http.NewRequest("GET", url, nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.AssertHttpStatus(resp, 200)
	_, err = io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
}

func promReqWg(s *NoTopoSuite, url string, wg *sync.WaitGroup) {
	defer GinkgoRecover()
	defer wg.Done()
	promReq(s, url, defaultHttpTimeout)
}

func PromConcurrentConnectionsTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.VppAddr()
	url := "http://" + serverAddress + ":80/stats.prom"

	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers"))
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

func PromConsecutiveConnectionsTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.VppAddr()
	url := "http://" + serverAddress + ":80/stats.prom"

	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers"))
	s.Log(vpp.Vppctl("prom enable"))
	time.Sleep(time.Second * 5)

	for i := 0; i < 1000; i++ {
		promReq(s, url, time.Millisecond*500)
	}
}

func PromMemLeakTest(s *NoTopoSuite) {
	s.SkipUnlessLeakCheck()

	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.VppAddr()
	url := "http://" + serverAddress + ":80/stats.prom"

	/* no goVPP less noise */
	vpp.Disconnect()

	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers"))
	s.Log(vpp.Vppctl("prom enable"))
	time.Sleep(time.Second * 3)

	/* warmup request (FIB) */
	promReq(s, url, defaultHttpTimeout)

	vpp.EnableMemoryTrace()
	traces1, err := vpp.GetMemoryTrace()
	s.AssertNil(err, fmt.Sprint(err))

	/* collect stats couple of times */
	for i := 0; i < 5; i++ {
		time.Sleep(time.Second * 1)
		promReq(s, url, defaultHttpTimeout)
	}

	/* let's give it some time to clean up sessions */
	time.Sleep(time.Second * 5)

	traces2, err := vpp.GetMemoryTrace()
	s.AssertNil(err, fmt.Sprint(err))
	vpp.MemLeakCheck(traces1, traces2)
}

func HttpClientGetMemLeakTest(s *VethsSuite) {
	s.SkipUnlessLeakCheck()

	serverContainer := s.GetContainerByName("server-vpp").VppInstance
	clientContainer := s.GetContainerByName("client-vpp").VppInstance
	serverVeth := s.GetInterfaceByName(ServerInterfaceName)

	/* no goVPP less noise */
	clientContainer.Disconnect()

	serverContainer.Vppctl("http cli server")

	uri := "http://" + serverVeth.Ip4AddressString() + "/80"

	/* warmup request (FIB) */
	clientContainer.Vppctl("http cli client uri " + uri + " query /show/version")

	/* let's give it some time to clean up sessions, so local port can be reused and we have less noise */
	time.Sleep(time.Second * 12)

	clientContainer.EnableMemoryTrace()
	traces1, err := clientContainer.GetMemoryTrace()
	s.AssertNil(err, fmt.Sprint(err))

	clientContainer.Vppctl("http cli client uri " + uri + " query /show/vlib/graph")

	/* let's give it some time to clean up sessions */
	time.Sleep(time.Second * 12)

	traces2, err := clientContainer.GetMemoryTrace()
	s.AssertNil(err, fmt.Sprint(err))
	clientContainer.MemLeakCheck(traces1, traces2)
}

func HttpClientPostMemLeakTest(s *NoTopoSuite) {
	s.SkipUnlessLeakCheck()

	serverAddress := s.HostAddr()
	body := "field1=value1&field2=value2"

	uri := "http://" + serverAddress + "/80"
	vpp := s.GetContainerByName("vpp").VppInstance

	/* no goVPP less noise */
	vpp.Disconnect()

	server := ghttp.NewUnstartedServer()
	l, err := net.Listen("tcp", serverAddress+":80")
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

func HttpInvalidClientRequestMemLeakTest(s *NoTopoSuite) {
	s.SkipUnlessLeakCheck()

	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.VppAddr()

	/* no goVPP less noise */
	vpp.Disconnect()

	vpp.Vppctl("http cli server")

	/* warmup request (FIB) */
	_, err := TcpSendReceive(serverAddress+":80", "GET / HTTP/1.1\r\n")
	s.AssertNil(err, fmt.Sprint(err))

	/* let's give it some time to clean up sessions, so local port can be reused and we have less noise */
	time.Sleep(time.Second * 12)

	vpp.EnableMemoryTrace()
	traces1, err := vpp.GetMemoryTrace()
	s.AssertNil(err, fmt.Sprint(err))

	_, err = TcpSendReceive(serverAddress+":80", "GET / HTTP/1.1\r\n")
	s.AssertNil(err, fmt.Sprint(err))

	/* let's give it some time to clean up sessions */
	time.Sleep(time.Second * 12)

	traces2, err := vpp.GetMemoryTrace()
	s.AssertNil(err, fmt.Sprint(err))
	vpp.MemLeakCheck(traces1, traces2)

}

func HttpStaticFileHandlerDefaultMaxAgeTest(s *NoTopoSuite) {
	HttpStaticFileHandlerTestFunction(s, "default")
}

func HttpStaticFileHandlerTest(s *NoTopoSuite) {
	HttpStaticFileHandlerTestFunction(s, "123")
}

func HttpStaticFileHandlerTestFunction(s *NoTopoSuite, max_age string) {
	var maxAgeFormatted string
	if max_age == "default" {
		maxAgeFormatted = ""
		max_age = "600"
	} else {
		maxAgeFormatted = "max-age " + max_age
	}

	content := "<html><body><p>Hello</p></body></html>"
	content2 := "<html><body><p>Page</p></body></html>"

	vpp := s.GetContainerByName("vpp").VppInstance
	vpp.Container.Exec("mkdir -p " + wwwRootPath)
	err := vpp.Container.CreateFile(wwwRootPath+"/index.html", content)
	s.AssertNil(err, fmt.Sprint(err))
	err = vpp.Container.CreateFile(wwwRootPath+"/page.html", content2)
	s.AssertNil(err, fmt.Sprint(err))
	serverAddress := s.VppAddr()
	s.Log(vpp.Vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress + "/80 debug cache-size 2m " + maxAgeFormatted))

	client := NewHttpClient(defaultHttpTimeout)
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/index.html", nil)
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

	req, err = http.NewRequest("GET", "http://"+serverAddress+":80/page.html", nil)
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

func HttpStaticPathTraversalTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	vpp.Container.Exec("mkdir -p " + wwwRootPath)
	vpp.Container.Exec("mkdir -p " + "/tmp/secret_folder")
	err := vpp.Container.CreateFile("/tmp/secret_folder/secret_file.txt", "secret")
	s.AssertNil(err, fmt.Sprint(err))
	serverAddress := s.VppAddr()
	s.Log(vpp.Vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress + "/80 debug"))

	client := NewHttpClient(defaultHttpTimeout)
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/../secret_folder/secret_file.txt", nil)
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

func HttpStaticMovedTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	vpp.Container.Exec("mkdir -p " + wwwRootPath + "/tmp.aaa")
	err := vpp.Container.CreateFile(wwwRootPath+"/tmp.aaa/index.html", "<html><body><p>Hello</p></body></html>")
	s.AssertNil(err, fmt.Sprint(err))
	serverAddress := s.VppAddr()
	s.Log(vpp.Vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress + "/80 debug"))

	client := NewHttpClient(defaultHttpTimeout)
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/tmp.aaa", nil)
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

func HttpStaticNotFoundTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	vpp.Container.Exec("mkdir -p " + wwwRootPath)
	serverAddress := s.VppAddr()
	s.Log(vpp.Vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress + "/80 debug"))

	client := NewHttpClient(defaultHttpTimeout)
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/notfound.html", nil)
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

func HttpCliMethodNotAllowedTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.VppAddr()
	vpp.Vppctl("http cli server")

	client := NewHttpClient(defaultHttpTimeout)
	req, err := http.NewRequest("POST", "http://"+serverAddress+":80/test", nil)
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

func HttpCliBadRequestTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.VppAddr()
	vpp.Vppctl("http cli server")

	client := NewHttpClient(defaultHttpTimeout)
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, true))
	s.AssertHttpStatus(resp, 400)
	s.AssertHttpHeaderNotPresent(resp, "Content-Type")
	s.AssertHttpContentLength(resp, int64(0))
}

func HttpStaticBuildInUrlGetVersionTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.VppAddr()
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers debug"))

	client := NewHttpClient(defaultHttpTimeout)
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/version.json", nil)
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
	s.AssertNotContains(string(data), "build_by")
	s.AssertNotContains(string(data), "build_host")
	s.AssertNotContains(string(data), "build_dir")
	s.AssertHttpHeaderWithValue(resp, "Content-Type", "application/json")
}

func HttpStaticBuildInUrlGetVersionVerboseTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.VppAddr()
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers debug"))

	client := NewHttpClient(defaultHttpTimeout)
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/version.json?verbose=true", nil)
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

func HttpStaticBuildInUrlGetIfListTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.VppAddr()
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers debug"))

	client := NewHttpClient(defaultHttpTimeout)
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/interface_list.json", nil)
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

func HttpStaticBuildInUrlGetIfStatsTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.VppAddr()
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers debug"))

	client := NewHttpClient(defaultHttpTimeout)
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/interface_stats.json", nil)
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

func validatePostInterfaceStats(s *NoTopoSuite, data string) {
	s.AssertContains(data, "interface_stats")
	s.AssertContains(data, s.VppIfName())
	s.AssertNotContains(data, "error")
	s.AssertNotContains(data, "local0")
}

func HttpStaticBuildInUrlPostIfStatsTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.VppAddr()
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers debug"))
	body := []byte(s.VppIfName())

	client := NewHttpClient(defaultHttpTimeout)
	req, err := http.NewRequest("POST",
		"http://"+serverAddress+":80/interface_stats.json", bytes.NewBuffer(body))
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

func HttpStaticMacTimeTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.VppAddr()
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers debug"))
	s.Log(vpp.Vppctl("mactime enable-disable " + s.VppIfName()))

	client := NewHttpClient(defaultHttpTimeout)
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/mactime.json", nil)
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
	s.AssertContains(string(data), s.GetInterfaceByName(TapInterfaceName).HwAddress.String())
	s.AssertHttpHeaderWithValue(resp, "Content-Type", "application/json")
	parsedTime, err := time.Parse(time.RFC1123, resp.Header.Get("Date"))
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertTimeEqualWithinThreshold(parsedTime, time.Now(), time.Minute*5)
	s.AssertEqual(len(resp.Header.Get("Date")), 29)
}

func HttpInvalidRequestLineTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.VppAddr()
	vpp.Vppctl("http cli server")

	resp, err := TcpSendReceive(serverAddress+":80", " GET / HTTP/1.1")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "invalid request line start not allowed")

	resp, err = TcpSendReceive(serverAddress+":80", "\rGET / HTTP/1.1")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "invalid request line start not allowed")

	resp, err = TcpSendReceive(serverAddress+":80", "\nGET / HTTP/1.1")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 400 Bad Request", "invalid request line start not allowed")

	resp, err = TcpSendReceive(serverAddress+":80", "GET / HTTP/1.1")
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

func HttpRequestLineTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.VppAddr()
	vpp.Vppctl("http cli server")

	resp, err := TcpSendReceive(serverAddress+":80", "\r\nGET /show/version HTTP/1.1\r\nHost:"+serverAddress+":80\r\nUser-Agent:test\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 200 OK")
	s.AssertContains(resp, "<html>", "html content not found")
}

func HttpInvalidTargetSyntaxTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.VppAddr()
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
	serverAddress := s.VppAddr()
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
	serverAddress := s.VppAddr()
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers debug"))
	ifName := s.VppIfName()

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
	serverAddress := s.VppAddr()
	vpp.Vppctl("http cli server")

	client := NewHttpClient(defaultHttpTimeout)
	req, err := http.NewRequest("OPTIONS", "http://"+serverAddress+":80/show/version", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, true))
	s.AssertHttpStatus(resp, 501)
	s.AssertHttpHeaderNotPresent(resp, "Content-Type")
	s.AssertHttpContentLength(resp, int64(0))
}

func HttpVersionNotSupportedTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.VppAddr()
	vpp.Vppctl("http cli server")

	resp, err := TcpSendReceive(serverAddress+":80", "GET / HTTP/2\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 505 HTTP Version Not Supported")
}

func HttpUriDecodeTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.VppAddr()
	vpp.Vppctl("http cli server")

	client := NewHttpClient(defaultHttpTimeout)
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/sh%6fw%20versio%6E%20verbose", nil)
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

func HttpHeadersTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.VppAddr()
	vpp.Vppctl("http cli server")

	resp, err := TcpSendReceive(
		serverAddress+":80",
		"GET /show/version HTTP/1.1\r\nHost:"+serverAddress+":80\r\nUser-Agent:test\r\nAccept:text/xml\r\nAccept:\ttext/plain\t \r\nAccept:text/html\r\n\r\n")
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(resp, "HTTP/1.1 200 OK")
	s.AssertContains(resp, "Content-Type: text/plain")
	s.AssertNotContains(resp, "<html>", "html content received instead of plain text")
}

func HttpInvalidHeadersTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.VppAddr()
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
	serverAddress := s.VppAddr()
	vpp.Vppctl("http cli server")

	client := NewHttpClient(defaultHttpTimeout)
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/show/version", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, true))
	s.AssertHttpStatus(resp, 200)
	s.AssertHttpHeaderWithValue(resp, "Server", "http_cli_server")
	s.AssertHttpHeaderWithValue(resp, "Content-Type", "text/html")
}
