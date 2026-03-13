package main

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"time"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterHttpStaticSrvTests(HttpStaticMovedTest, HttpStaticNotFoundTest, HttpStaticBuildInUrlGetIfStatsTest, HttpStaticBuildInUrlPostIfStatsTest,
		HttpStaticPostTest, HttpStaticBuildInUrlGetIfListTest, HttpStaticBuildInUrlGetVersionTest,
		HttpStaticMacTimeTest, HttpStaticBuildInUrlGetVersionVerboseTest, HttpStaticPathSanitizationTest, HttpStaticFileHandlerTest, HttpStaticFileHandlerDefaultMaxAgeTest,
		HttpStaticFileHandlerWrkTest, HttpStaticUrlHandlerWrkTest, HttpStaticHttp1OnlyTest, HttpStaticRedirectTest, HttpStaticPromTest, PromConcurrentConnectionsTest,
		PromConsecutiveConnectionsTest)
	RegisterHttpStaticSrvSoloTests(PromMemLeakTest)
}

func HttpStaticPostTest(s *HttpStaticSrvSuite) {
	// testing url handler app do not support multi-thread
	s.SkipIfMultiWorker()
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers debug max-body-size 1m"))
	Log(vpp.Vppctl("test-url-handler enable"))

	body := make([]byte, 131072)
	_, err := rand.Read(body)
	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("POST", "http://"+serverAddress+"/test3", bytes.NewBuffer(body))
	AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	AssertHttpStatus(resp, 200)
	_, err = io.ReadAll(resp.Body)
	AssertNil(err, fmt.Sprint(err))
}

func HttpStaticPromTest(s *HttpStaticSrvSuite) {
	query := "stats.prom"
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers"))
	Log(vpp.Vppctl("prom enable"))
	time.Sleep(time.Second * 5)
	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "http://"+serverAddress+"/"+query, nil)
	AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	Log(DumpHttpResp(resp, false))
	AssertHttpStatus(resp, 200)
	AssertHttpHeaderWithValue(resp, "Content-Type", "text/plain")
	AssertGreaterEqual(resp.ContentLength, 0)
	_, err = io.ReadAll(resp.Body)
	AssertNil(err, fmt.Sprint(err))
}

func promReq(url string, timeout time.Duration) {
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

func promReqWg(url string, wg *sync.WaitGroup) {
	defer GinkgoRecover()
	defer wg.Done()
	promReq(url, defaultHttpTimeout)
}

func PromConcurrentConnectionsTest(s *HttpStaticSrvSuite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	url := "http://" + serverAddress + "/stats.prom"

	Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers"))
	Log(vpp.Vppctl("prom enable"))
	time.Sleep(time.Second * 5)

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go promReqWg(url, &wg)
	}
	wg.Wait()
	Log(vpp.Vppctl("show session verbose proto http"))
}

func PromConsecutiveConnectionsTest(s *HttpStaticSrvSuite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	url := "http://" + serverAddress + "/stats.prom"

	Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers"))
	Log(vpp.Vppctl("prom enable"))
	time.Sleep(time.Second * 5)

	for range 1000 {
		promReq(url, time.Millisecond*500)
	}
}

func PromMemLeakTest(s *HttpStaticSrvSuite) {
	s.SkipUnlessLeakCheck()

	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	url := "http://" + serverAddress + "/stats.prom"

	/* no goVPP less noise */
	vpp.Disconnect()

	Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers"))
	Log(vpp.Vppctl("prom enable"))
	time.Sleep(time.Second * 3)

	/* warmup requests (FIB, pool allocations) */
	for range 5 {
		time.Sleep(time.Second * 1)
		promReq(url, defaultHttpTimeout)
	}

	/* let's give it some time to clean up sessions, so pool elements can be reused and we have less noise */
	time.Sleep(time.Second * 12)

	vpp.EnableMemoryTrace()
	traces1, err := vpp.GetMemoryTrace()
	AssertNil(err, fmt.Sprint(err))

	/* collect stats couple of times */
	for range 5 {
		time.Sleep(time.Second * 1)
		promReq(url, defaultHttpTimeout)
	}

	/* let's give it some time to clean up sessions */
	time.Sleep(time.Second * 12)

	traces2, err := vpp.GetMemoryTrace()
	AssertNil(err, fmt.Sprint(err))
	vpp.MemLeakCheck(traces1, traces2)
}

func runWrkPerf(s *HttpStaticSrvSuite) {
	nConnections := 1000
	serverAddress := s.VppAddr() + ":" + s.Ports.Http

	args := fmt.Sprintf("-c %d -t 2 -d 30s http://%s/64B", nConnections, serverAddress)
	s.Containers.Wrk.ExtraRunningArgs = args
	s.Containers.Wrk.Run()
	Log("Please wait for 30s, test is running.")
	o, err := s.Containers.Wrk.GetOutput()
	Log(o)
	AssertEmpty(err, "err: '%s'", err)
}

func HttpStaticFileHandlerWrkTest(s *HttpStaticSrvSuite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	vpp.Container.Exec(false, "mkdir -p "+wwwRootPath)
	content := "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	err := vpp.Container.CreateFile(wwwRootPath+"/64B", content)
	AssertNil(err, fmt.Sprint(err))
	Log(vpp.Vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress + " private-segment-size 256m"))
	runWrkPerf(s)
}

func HttpStaticUrlHandlerWrkTest(s *HttpStaticSrvSuite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers private-segment-size 256m"))
	Log(vpp.Vppctl("test-url-handler enable"))
	runWrkPerf(s)
}

func HttpStaticFileHandlerDefaultMaxAgeTest(s *HttpStaticSrvSuite) {
	HttpStaticFileHandlerTestFunction(s, "default")
}

func HttpStaticFileHandlerTest(s *HttpStaticSrvSuite) {
	HttpStaticFileHandlerTestFunction(s, "123")
}

func HttpStaticFileHandlerTestFunction(s *HttpStaticSrvSuite, max_age string) {
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
	AssertNil(err, fmt.Sprint(err))
	err = vpp.Container.CreateFile(wwwRootPath+"/page.html", content2)
	AssertNil(err, fmt.Sprint(err))
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	Log(vpp.Vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress + " debug cache-size 2m " + maxAgeFormatted))

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "http://"+serverAddress+"/index.html", nil)
	AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	AssertNil(err, fmt.Sprint(err))

	Log(DumpHttpResp(resp, true))
	AssertHttpStatus(resp, 200)
	AssertHttpHeaderWithValue(resp, "Content-Type", "text/html")
	AssertHttpHeaderWithValue(resp, "Cache-Control", "max-age="+max_age)
	parsedTime, err := time.Parse(time.RFC1123, resp.Header.Get("Last-Modified"))
	AssertNil(err, fmt.Sprint(err))
	AssertTimeEqualWithinThreshold(parsedTime, time.Now(), time.Minute*5)
	AssertEqual(len(resp.Header.Get("Last-Modified")), 29)
	AssertHttpContentLength(resp, int64(len([]rune(content))))
	AssertHttpBody(resp, content)
	o := vpp.Vppctl("show http static server cache verbose")
	Log(o)
	AssertContains(o, "index.html")
	AssertNotContains(o, "page.html")

	resp, err = client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	Log(DumpHttpResp(resp, true))
	AssertHttpStatus(resp, 200)
	AssertHttpHeaderWithValue(resp, "Content-Type", "text/html")
	AssertHttpHeaderWithValue(resp, "Cache-Control", "max-age="+max_age)
	AssertHttpContentLength(resp, int64(len([]rune(content))))
	AssertHttpBody(resp, content)

	req, err = http.NewRequest("GET", "http://"+serverAddress+"/page.html", nil)
	AssertNil(err, fmt.Sprint(err))
	resp, err = client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	Log(DumpHttpResp(resp, true))
	AssertHttpStatus(resp, 200)
	AssertHttpHeaderWithValue(resp, "Content-Type", "text/html")
	AssertHttpHeaderWithValue(resp, "Cache-Control", "max-age="+max_age)
	AssertHttpContentLength(resp, int64(len([]rune(content2))))
	AssertHttpBody(resp, content2)
	o = vpp.Vppctl("show http static server cache verbose")
	Log(o)
	AssertContains(o, "index.html")
	AssertContains(o, "page.html")
}

func HttpStaticPathSanitizationTest(s *HttpStaticSrvSuite) {
	vpp := s.Containers.Vpp.VppInstance
	vpp.Container.Exec(false, "mkdir -p "+wwwRootPath)
	vpp.Container.Exec(false, "mkdir -p "+"/tmp/secret_folder")
	err := vpp.Container.CreateFile("/tmp/secret_folder/secret_file.txt", "secret")
	AssertNil(err, fmt.Sprint(err))
	indexContent := "<html><body>index</body></html>"
	err = vpp.Container.CreateFile(wwwRootPath+"/index.html", indexContent)
	AssertNil(err, fmt.Sprint(err))
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	Log(vpp.Vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress + " debug"))

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "http://"+serverAddress+"/../secret_folder/secret_file.txt", nil)
	AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	Log(DumpHttpResp(resp, true))
	AssertHttpStatus(resp, 404)
	AssertHttpHeaderNotPresent(resp, "Content-Type")
	AssertHttpHeaderNotPresent(resp, "Cache-Control")
	AssertHttpContentLength(resp, int64(0))

	req, err = http.NewRequest("GET", "http://"+serverAddress+"//////fake/directory///../././//../../secret_folder/secret_file.txt", nil)
	AssertNil(err, fmt.Sprint(err))
	resp, err = client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	Log(DumpHttpResp(resp, true))
	AssertHttpStatus(resp, 404)
	AssertHttpHeaderNotPresent(resp, "Content-Type")
	AssertHttpHeaderNotPresent(resp, "Cache-Control")
	AssertHttpContentLength(resp, int64(0))

	req, err = http.NewRequest("GET", "http://"+serverAddress+"/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////", nil)
	AssertNil(err, fmt.Sprint(err))
	resp, err = client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	Log(DumpHttpResp(resp, true))
	AssertHttpStatus(resp, 301)
	AssertHttpHeaderWithValue(resp, "Location", "http://"+serverAddress+"/index.html")
}

func HttpStaticMovedTest(s *HttpStaticSrvSuite) {
	vpp := s.Containers.Vpp.VppInstance
	vpp.Container.Exec(false, "mkdir -p "+wwwRootPath+"/tmp.aaa")
	err := vpp.Container.CreateFile(wwwRootPath+"/tmp.aaa/index.html", "<html><body><p>Hello</p></body></html>")
	AssertNil(err, fmt.Sprint(err))
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	Log(vpp.Vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress + " debug"))

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "http://"+serverAddress+"/tmp.aaa", nil)
	AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	Log(DumpHttpResp(resp, true))
	AssertHttpStatus(resp, 301)
	AssertHttpHeaderWithValue(resp, "Location", "http://"+serverAddress+"/tmp.aaa/index.html")
	AssertHttpHeaderNotPresent(resp, "Content-Type")
	AssertHttpHeaderNotPresent(resp, "Cache-Control")
	AssertHttpContentLength(resp, int64(0))
}

func HttpStaticRedirectTest(s *HttpStaticSrvSuite) {
	vpp := s.Containers.Vpp.VppInstance
	vpp.Container.Exec(false, "mkdir -p "+wwwRootPath)
	err := vpp.Container.CreateFile(wwwRootPath+"/index.html", "<html><body><p>Hello</p></body></html>")
	AssertNil(err, fmt.Sprint(err))
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	Log(vpp.Vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress + " debug"))

	req := "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"

	conn, err := net.DialTimeout("tcp", serverAddress, time.Second*30)
	AssertNil(err, fmt.Sprint(err))
	defer conn.Close()
	err = conn.SetDeadline(time.Now().Add(time.Second * 5))
	AssertNil(err, fmt.Sprint(err))
	n, err := conn.Write([]byte(req))
	AssertNil(err, fmt.Sprint(err))
	AssertEqual(n, len([]rune(req)))
	reply := make([]byte, 1024)
	_, err = conn.Read(reply)
	AssertNil(err, fmt.Sprint(err))
	Log(string(reply))
	expectedLocation := "Location: http://example.com/index.html"
	AssertContains(string(reply), expectedLocation)
}

func HttpStaticNotFoundTest(s *HttpStaticSrvSuite) {
	vpp := s.Containers.Vpp.VppInstance
	vpp.Container.Exec(false, "mkdir -p "+wwwRootPath)
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	Log(vpp.Vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress + " debug"))

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "http://"+serverAddress+"/notfound.html", nil)
	AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	Log(DumpHttpResp(resp, true))
	AssertHttpStatus(resp, 404)
	AssertHttpHeaderNotPresent(resp, "Content-Type")
	AssertHttpHeaderNotPresent(resp, "Cache-Control")
	AssertHttpContentLength(resp, int64(0))
}

func HttpStaticHttp1OnlyTest(s *HttpStaticSrvSuite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	Log(vpp.Vppctl("http static server uri tls://" + serverAddress + " url-handlers http1-only debug"))

	client := NewHttpClient(defaultHttpTimeout, true)
	req, err := http.NewRequest("GET", "https://"+serverAddress+"/version.json", nil)
	AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	Log(DumpHttpResp(resp, true))
	AssertHttpStatus(resp, 200)
	AssertEqual(1, resp.ProtoMajor)
	data, err := io.ReadAll(resp.Body)
	AssertNil(err, fmt.Sprint(err))
	AssertContains(string(data), "version")
}

func HttpStaticBuildInUrlGetVersionTest(s *HttpStaticSrvSuite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	Log(vpp.Vppctl("http static server uri tls://" + serverAddress + " url-handlers debug"))

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "https://"+serverAddress+"/version.json", nil)
	AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	Log(DumpHttpResp(resp, true))
	AssertHttpStatus(resp, 200)
	AssertEqual(1, resp.ProtoMajor)
	data, err := io.ReadAll(resp.Body)
	AssertNil(err, fmt.Sprint(err))
	AssertContains(string(data), "vpp_details")
	AssertContains(string(data), "version")
	AssertContains(string(data), "build_date")
	AssertNotContains(string(data), "build_by")
	AssertNotContains(string(data), "build_host")
	AssertNotContains(string(data), "build_dir")
	AssertHttpHeaderWithValue(resp, "Content-Type", "application/json")
}

func HttpStaticBuildInUrlGetVersionVerboseTest(s *HttpStaticSrvSuite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers debug"))

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "http://"+serverAddress+"/version.json?verbose=true", nil)
	AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	Log(DumpHttpResp(resp, true))
	AssertHttpStatus(resp, 200)
	data, err := io.ReadAll(resp.Body)
	AssertNil(err, fmt.Sprint(err))
	AssertContains(string(data), "vpp_details")
	AssertContains(string(data), "version")
	AssertContains(string(data), "build_date")
	AssertContains(string(data), "build_by")
	AssertContains(string(data), "build_host")
	AssertContains(string(data), "build_dir")
	AssertHttpHeaderWithValue(resp, "Content-Type", "application/json")
}

func HttpStaticBuildInUrlGetIfListTest(s *HttpStaticSrvSuite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers debug"))

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "http://"+serverAddress+"/interface_list.json", nil)
	AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	Log(DumpHttpResp(resp, true))
	AssertHttpStatus(resp, 200)
	data, err := io.ReadAll(resp.Body)
	AssertNil(err, fmt.Sprint(err))
	AssertContains(string(data), "interface_list")
	AssertContains(string(data), s.VppIfName())
	AssertHttpHeaderWithValue(resp, "Content-Type", "application/json")
}

func HttpStaticBuildInUrlGetIfStatsTest(s *HttpStaticSrvSuite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers debug"))

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "http://"+serverAddress+"/interface_stats.json", nil)
	AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	Log(DumpHttpResp(resp, true))
	AssertHttpStatus(resp, 200)
	data, err := io.ReadAll(resp.Body)
	AssertNil(err, fmt.Sprint(err))
	AssertContains(string(data), "interface_stats")
	AssertContains(string(data), "local0")
	AssertContains(string(data), s.VppIfName())
	AssertHttpHeaderWithValue(resp, "Content-Type", "application/json")
}

func HttpStaticBuildInUrlPostIfStatsTest(s *HttpStaticSrvSuite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers debug"))
	body := []byte(s.VppIfName())

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("POST",
		"http://"+serverAddress+"/interface_stats.json", bytes.NewBuffer(body))
	AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	Log(DumpHttpResp(resp, true))
	AssertHttpStatus(resp, 200)
	data, err := io.ReadAll(resp.Body)
	AssertNil(err, fmt.Sprint(err))
	AssertContains(string(data), "interface_stats")
	AssertContains(string(data), s.VppIfName())
	AssertNotContains(string(data), "error")
	AssertNotContains(string(data), "local0")
	AssertHttpHeaderWithValue(resp, "Content-Type", "application/json")
}

func HttpStaticMacTimeTest(s *HttpStaticSrvSuite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers debug"))
	Log(vpp.Vppctl("mactime enable-disable " + s.VppIfName()))

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "http://"+serverAddress+"/mactime.json", nil)
	AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	Log(DumpHttpResp(resp, true))
	AssertHttpStatus(resp, 200)
	data, err := io.ReadAll(resp.Body)
	AssertNil(err, fmt.Sprint(err))
	AssertContains(string(data), "mactime")
	AssertContains(string(data), s.HostAddr())
	AssertContains(string(data), s.Interfaces.Tap.Host.HwAddress.String())
	AssertHttpHeaderWithValue(resp, "Content-Type", "application/json")
	parsedTime, err := time.Parse(time.RFC1123, resp.Header.Get("Date"))
	AssertNil(err, fmt.Sprint(err))
	AssertTimeEqualWithinThreshold(parsedTime, time.Now(), time.Minute*5)
	AssertEqual(len(resp.Header.Get("Date")), 29)
}
