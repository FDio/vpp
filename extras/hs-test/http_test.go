package main

import (
	"bytes"
	"fmt"
	"github.com/onsi/gomega/gmeasure"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"sync"
	"time"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterVethTests(HttpCliTest, HttpCliConnectErrorTest)
	RegisterNoTopoTests(HeaderServerTest, HttpPersistentConnectionTest, HttpPipeliningTest,
		HttpStaticMovedTest, HttpStaticNotFoundTest, HttpCliMethodNotAllowedTest,
		HttpCliBadRequestTest, HttpStaticBuildInUrlGetIfStatsTest, HttpStaticBuildInUrlPostIfStatsTest,
		HttpInvalidRequestLineTest, HttpMethodNotImplementedTest, HttpInvalidHeadersTest,
		HttpContentLengthTest, HttpStaticBuildInUrlGetIfListTest, HttpStaticBuildInUrlGetVersionTest,
		HttpStaticMacTimeTest, HttpStaticBuildInUrlGetVersionVerboseTest, HttpVersionNotSupportedTest,
		HttpInvalidContentLengthTest, HttpInvalidTargetSyntaxTest, HttpStaticPathTraversalTest, HttpUriDecodeTest,
		HttpHeadersTest, HttpStaticFileHandler)
	RegisterNoTopoSoloTests(HttpStaticPromTest, HttpTpsTest, HttpTpsInterruptModeTest, PromConcurrentConnections,
		PromMemLeakTest)
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

func HttpTpsInterruptModeTest(s *NoTopoSuite) {
	HttpTpsTest(s)
}

func HttpTpsTest(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
	url := "http://" + serverAddress + ":8080/test_file_10M"

	vpp.Vppctl("http tps uri tcp://0.0.0.0/8080")

	s.RunBenchmark("HTTP tps 10M", 10, 0, httpDownloadBenchmark, url)
}

func HttpPersistentConnectionTest(s *NoTopoSuite) {
	// testing url handler app do not support multi-thread
	s.SkipIfMultiWorker()
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
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

	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/test1", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, true))
	s.AssertEqual(200, resp.StatusCode)
	s.AssertEqual(false, resp.Close)
	body, err := io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertEqual(string(body), "hello")
	o1 := vpp.Vppctl("show session verbose proto http state ready")
	s.Log(o1)
	s.AssertContains(o1, "ESTABLISHED")

	req, err = http.NewRequest("GET", "http://"+serverAddress+":80/test2", nil)
	s.AssertNil(err, fmt.Sprint(err))
	clientTrace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			s.AssertEqual(true, info.Reused, "connection not reused")
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), clientTrace))
	resp, err = client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, true))
	s.AssertEqual(200, resp.StatusCode)
	s.AssertEqual(false, resp.Close)
	body, err = io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertEqual(string(body), "some data")
	s.AssertNil(err, fmt.Sprint(err))
	o2 := vpp.Vppctl("show session verbose proto http state ready")
	s.Log(o2)
	s.AssertContains(o2, "ESTABLISHED")
	s.AssertEqual(o1, o2)
}

func HttpPipeliningTest(s *NoTopoSuite) {
	// testing url handler app do not support multi-thread
	s.SkipIfMultiWorker()
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
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

func HttpStaticPromTest(s *NoTopoSuite) {
	query := "stats.prom"
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers"))
	s.Log(vpp.Vppctl("prom enable"))
	time.Sleep(time.Second * 5)
	client := NewHttpClient()
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/"+query, nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, false))
	s.AssertEqual(200, resp.StatusCode)
	s.AssertContains(resp.Header.Get("Content-Type"), "text")
	s.AssertContains(resp.Header.Get("Content-Type"), "plain")
	s.AssertNotEqual(int64(0), resp.ContentLength)
	_, err = io.ReadAll(resp.Body)
}

func promReq(s *NoTopoSuite, url string) {
	client := NewHttpClient()
	req, err := http.NewRequest("GET", url, nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.AssertEqual(200, resp.StatusCode)
	_, err = io.ReadAll(resp.Body)
}

func promReqWg(s *NoTopoSuite, url string, wg *sync.WaitGroup) {
	defer GinkgoRecover()
	defer wg.Done()
	promReq(s, url)
}

func PromConcurrentConnections(s *NoTopoSuite) {
	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
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

func PromMemLeakTest(s *NoTopoSuite) {
	s.SkipUnlessLeakCheck()

	vpp := s.GetContainerByName("vpp").VppInstance
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
	url := "http://" + serverAddress + ":80/stats.prom"

	/* no goVPP less noise */
	vpp.Disconnect()

	s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers"))
	s.Log(vpp.Vppctl("prom enable"))
	time.Sleep(time.Second * 3)

	/* warmup request (FIB) */
	promReq(s, url)

	vpp.EnableMemoryTrace()
	traces1, err := vpp.GetMemoryTrace()
	s.AssertNil(err, fmt.Sprint(err))

	/* collect stats couple of times */
	for i := 0; i < 5; i++ {
		time.Sleep(time.Second * 1)
		promReq(s, url)
	}

	/* let's give it some time to clean up sessions */
	time.Sleep(time.Second * 5)

	traces2, err := vpp.GetMemoryTrace()
	s.AssertNil(err, fmt.Sprint(err))
	vpp.MemLeakCheck(traces1, traces2)
}

func HttpStaticFileHandler(s *NoTopoSuite) {
	content := "<http><body><p>Hello</p></body></http>"
	content2 := "<http><body><p>Page</p></body></http>"
	vpp := s.GetContainerByName("vpp").VppInstance
	vpp.Container.Exec("mkdir -p " + wwwRootPath)
	vpp.Container.CreateFile(wwwRootPath+"/index.html", content)
	vpp.Container.CreateFile(wwwRootPath+"/page.html", content2)
	serverAddress := s.GetInterfaceByName(TapInterfaceName).Peer.Ip4AddressString()
	s.Log(vpp.Vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress + "/80 debug cache-size 2m"))

	client := NewHttpClient()
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/index.html", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, true))
	s.AssertEqual(200, resp.StatusCode)
	s.AssertContains(resp.Header.Get("Content-Type"), "html")
	s.AssertContains(resp.Header.Get("Cache-Control"), "max-age=")
	s.AssertEqual(int64(len([]rune(content))), resp.ContentLength)
	body, err := io.ReadAll(resp.Body)
	s.AssertEqual(string(body), content)
	o := vpp.Vppctl("show http static server cache verbose")
	s.Log(o)
	s.AssertContains(o, "index.html")
	s.AssertNotContains(o, "page.html")

	resp, err = client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, true))
	s.AssertEqual(200, resp.StatusCode)
	s.AssertContains(resp.Header.Get("Content-Type"), "html")
	s.AssertContains(resp.Header.Get("Cache-Control"), "max-age=")
	s.AssertEqual(int64(len([]rune(content))), resp.ContentLength)
	body, err = io.ReadAll(resp.Body)
	s.AssertEqual(string(body), content)

	req, err = http.NewRequest("GET", "http://"+serverAddress+":80/page.html", nil)
	s.AssertNil(err, fmt.Sprint(err))
	resp, err = client.Do(req)
	s.AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.Log(DumpHttpResp(resp, true))
	s.AssertEqual(200, resp.StatusCode)
	s.AssertContains(resp.Header.Get("Content-Type"), "html")
	s.AssertContains(resp.Header.Get("Cache-Control"), "max-age=")
	s.AssertEqual(int64(len([]rune(content2))), resp.ContentLength)
	body, err = io.ReadAll(resp.Body)
	s.AssertEqual(string(body), content2)
	o = vpp.Vppctl("show http static server cache verbose")
	s.Log(o)
	s.AssertContains(o, "index.html")
	s.AssertContains(o, "page.html")
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
	s.Log(DumpHttpResp(resp, true))
	s.AssertEqual(404, resp.StatusCode)
	s.AssertEmpty(resp.Header.Get("Content-Type"))
	s.AssertEmpty(resp.Header.Get("Cache-Control"))
	s.AssertEqual(int64(0), resp.ContentLength)
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
	s.Log(DumpHttpResp(resp, true))
	s.AssertEqual(301, resp.StatusCode)
	s.AssertEqual("http://"+serverAddress+"/tmp.aaa/index.html", resp.Header.Get("Location"))
	s.AssertEmpty(resp.Header.Get("Content-Type"))
	s.AssertEmpty(resp.Header.Get("Cache-Control"))
	s.AssertEqual(int64(0), resp.ContentLength)
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
	s.Log(DumpHttpResp(resp, true))
	s.AssertEqual(404, resp.StatusCode)
	s.AssertEmpty(resp.Header.Get("Content-Type"))
	s.AssertEmpty(resp.Header.Get("Cache-Control"))
	s.AssertEqual(int64(0), resp.ContentLength)
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
	s.Log(DumpHttpResp(resp, true))
	s.AssertEqual(405, resp.StatusCode)
	s.AssertNotEqual("", resp.Header.Get("Allow"), "server MUST generate an Allow header")
	s.AssertEmpty(resp.Header.Get("Content-Type"))
	s.AssertEqual(int64(0), resp.ContentLength)
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
	s.Log(DumpHttpResp(resp, true))
	s.AssertEqual(400, resp.StatusCode)
	s.AssertEmpty(resp.Header.Get("Content-Type"))
	s.AssertEqual(int64(0), resp.ContentLength)
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
	s.Log(DumpHttpResp(resp, true))
	s.AssertEqual(200, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(string(data), "vpp_details")
	s.AssertContains(string(data), "version")
	s.AssertContains(string(data), "build_date")
	s.AssertNotContains(string(data), "build_by")
	s.AssertNotContains(string(data), "build_host")
	s.AssertNotContains(string(data), "build_dir")
	s.AssertContains(resp.Header.Get("Content-Type"), "json")
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
	s.Log(DumpHttpResp(resp, true))
	s.AssertEqual(200, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(string(data), "vpp_details")
	s.AssertContains(string(data), "version")
	s.AssertContains(string(data), "build_date")
	s.AssertContains(string(data), "build_by")
	s.AssertContains(string(data), "build_host")
	s.AssertContains(string(data), "build_dir")
	s.AssertContains(resp.Header.Get("Content-Type"), "json")
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
	s.Log(DumpHttpResp(resp, true))
	s.AssertEqual(200, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(string(data), "interface_list")
	s.AssertContains(string(data), s.GetInterfaceByName(TapInterfaceName).Peer.Name())
	s.AssertContains(resp.Header.Get("Content-Type"), "json")
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
	s.Log(DumpHttpResp(resp, true))
	s.AssertEqual(200, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(string(data), "interface_stats")
	s.AssertContains(string(data), "local0")
	s.AssertContains(string(data), s.GetInterfaceByName(TapInterfaceName).Peer.Name())
	s.AssertContains(resp.Header.Get("Content-Type"), "json")
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
	s.Log(DumpHttpResp(resp, true))
	s.AssertEqual(200, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
	validatePostInterfaceStats(s, string(data))
	s.AssertContains(resp.Header.Get("Content-Type"), "json")
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
	s.Log(DumpHttpResp(resp, true))
	s.AssertEqual(200, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertContains(string(data), "mactime")
	s.AssertContains(string(data), s.GetInterfaceByName(TapInterfaceName).Ip4AddressString())
	s.AssertContains(string(data), s.GetInterfaceByName(TapInterfaceName).HwAddress.String())
	s.AssertContains(resp.Header.Get("Content-Type"), "json")
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
	s.Log(DumpHttpResp(resp, true))
	s.AssertEqual(501, resp.StatusCode)
	s.AssertEmpty(resp.Header.Get("Content-Type"))
	s.AssertEqual(int64(0), resp.ContentLength)
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
	s.Log(DumpHttpResp(resp, true))
	s.AssertEqual(200, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	s.AssertNil(err, fmt.Sprint(err))
	s.AssertNotContains(string(data), "unknown input")
	s.AssertContains(string(data), "Compiler")
	s.AssertContains(resp.Header.Get("Content-Type"), "html")
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
	s.Log(DumpHttpResp(resp, true))
	s.AssertEqual(200, resp.StatusCode)
	s.AssertEqual("http_cli_server", resp.Header.Get("Server"))
	s.AssertContains(resp.Header.Get("Content-Type"), "html")
}
