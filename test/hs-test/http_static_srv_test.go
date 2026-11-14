package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func init() {
	RegisterHttpStaticSrvTests(HttpStaticMovedTest, HttpStaticNotFoundTest, HttpStaticBuildInUrlGetIfStatsTest, HttpStaticBuildInUrlPostIfStatsTest,
		HttpStaticChunkedGetTest, HttpStaticChunkedRequestRejectedTest,
		HttpStaticHttp2StreamedGetTest, HttpStaticHttp3StreamedGetTest,
		HttpStaticHttp3StreamedGetBodyLimitTest, HttpStaticHttp3StreamedGetResetTest,
		HttpStaticBodyReaderReuseTest, HttpStaticHttp3StreamedGetUrlHandlerTest,
		HttpStaticPostTest, HttpStaticBuildInUrlGetIfListTest, HttpStaticBuildInUrlGetVersionTest,
		HttpStaticMacTimeTest, HttpStaticBuildInUrlGetVersionVerboseTest, HttpStaticPathSanitizationTest, HttpStaticFileHandlerTest, HttpStaticFileHandlerDefaultMaxAgeTest,
		HttpStaticFileHandlerWrkTest, HttpStaticUrlHandlerWrkTest, HttpStaticHttp1OnlyTest, HttpStaticRedirectTest, HttpStaticPromTest, PromConcurrentConnectionsTest,
		PromConsecutiveConnectionsTest, HttpStaticListenerAddDelTest, HttpStaticListenerAddDelMismatchTest,
		HttpStaticAltSvcNoHdrTest, HttpStaticAltSvcInvalidPortTest, HttpStaticAltSvcBorderlinePortTest,
		HttpStaticAltSvcHttp1Test, HttpStaticAltSvcHttps1Test, HttpStaticAltSvcHttp2Test, HttpStaticAltSvcHttps2Test,
		HttpStaticAltSvcListenerNoHdrTest, HttpStaticAltSvcListenerDelTest)
	RegisterHttpStaticSrvSoloTests(PromMemLeakTest)
}

const httpStaticStreamedGetContent = "<html><body>streamed GET completed</body></html>"

func httpStaticStreamedGetServer(s *HttpStaticSrvSuite, h3 bool) string {
	vpp := s.Containers.Vpp.VppInstance
	vpp.Container.Exec(false, "mkdir -p "+wwwRootPath)
	AssertNil(vpp.Container.CreateFile(wwwRootPath+"/index.html", httpStaticStreamedGetContent))
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	scheme, options := "http", ""
	if h3 {
		scheme, options = "https", "http3 "
	}
	AssertEmpty(vpp.Vppctl("http static server " + options + "url-handlers www-root " + wwwRootPath +
		" fifo-size 4k max-body-size 64k ptr-thresh 1m cache-size 4m uri " + scheme + "://" + address))
	return address
}

func httpStaticAssertNoResponse(stream interface {
	io.Reader
	SetReadDeadline(time.Time) error
}) {
	AssertNil(stream.SetReadDeadline(time.Now().Add(100 * time.Millisecond)))
	n, err := stream.Read(make([]byte, 1))
	AssertEqual(0, n, "request must complete before the handler responds")
	var timeout net.Error
	AssertEqual(true, errors.As(err, &timeout) && timeout.Timeout(),
		"expected no response before request completion, got %v", err)
	AssertNil(stream.SetReadDeadline(time.Now().Add(defaultHttpTimeout)))
}

func HttpStaticChunkedGetTest(s *HttpStaticSrvSuite) {
	address := httpStaticStreamedGetServer(s, false)
	for _, body := range []string{"", strings.Repeat("discarded!", 3200)} {
		By(fmt.Sprintf("chunked GET with %d body bytes", len(body)))
		func() {
			conn, reader := httpCliChunkedConnect(address, "GET", "/index.html",
				"Transfer-Encoding: chunked\r\n", "")
			defer conn.Close()
			httpStaticAssertNoResponse(conn)
			if body != "" {
				_, err := fmt.Fprintf(conn, "%x\r\n%s\r\n", len(body), body)
				AssertNil(err)
				httpStaticAssertNoResponse(conn)
			}
			_, err := io.WriteString(conn, "0\r\n\r\n")
			AssertNil(err)
			httpCliChunkedReply(conn, reader, "GET", httpStaticStreamedGetContent, http.StatusOK, false)
		}()
	}
}

func HttpStaticHttp2StreamedGetTest(s *HttpStaticSrvSuite) {
	address := httpStaticStreamedGetServer(s, false)
	p := http2RxConnect(address)
	defer p.conn.Close()
	for i, body := range []string{"", strings.Repeat("discarded!", 3200)} {
		By(fmt.Sprintf("HTTP/2 GET with %d body bytes and separate END_STREAM", len(body)))
		id := uint32(1 + i*4)
		fields := http2RxRequest(address, "GET")
		fields[3].Value = "/index.html"
		AssertNil(p.headers(id, fields, false, false))
		AssertNil(p.data(id, []byte(body), false, 0))

		// An incomplete GET must not block another stream or produce an early 411.
		AssertNil(p.headers(id+2, fields, true, false))
		data, status, err := p.response(id + 2)
		AssertNil(err)
		AssertEqual("200", status)
		AssertEqual(httpStaticStreamedGetContent, string(data))

		AssertNil(p.data(id, nil, true, 0))
		data, status, err = p.response(id)
		AssertNil(err)
		AssertEqual("200", status)
		AssertEqual(httpStaticStreamedGetContent, string(data))
	}
}

func HttpStaticHttp3StreamedGetTest(s *HttpStaticSrvSuite) {
	address := httpStaticStreamedGetServer(s, true)
	vpp := s.Containers.Vpp.VppInstance
	inline := strings.Repeat("inline-response!", 8192)
	pointer := strings.Repeat("pointer-response", 131072)
	AssertNil(vpp.Container.CreateFile(wwwRootPath+"/inline.bin", inline))
	AssertNil(vpp.Container.CreateFile(wwwRootPath+"/pointer.bin", pointer))
	conn := http3StreamingTxConnect(address)
	defer conn.CloseWithError(0, "")
	for _, tc := range []struct {
		name, path, body, response string
	}{
		{"empty request, separate FIN", "/index.html", "", httpStaticStreamedGetContent},
		{"body exactly at limit", "/index.html", strings.Repeat("x", 64<<10), httpStaticStreamedGetContent},
		{"inline response larger than FIFO", "/inline.bin", "discard me", inline},
		{"pointer response", "/pointer.bin", "", pointer},
	} {
		By(tc.name)
		stream, err := conn.OpenStream()
		AssertNil(err)
		AssertNil(stream.SetDeadline(time.Now().Add(defaultHttpTimeout)))
		_, err = stream.Write(http3FinHeaders("GET", tc.path, ""))
		AssertNil(err)
		// No Content-Length and no FIN: reproduce Defensics' split send/close steps.
		httpStaticAssertNoResponse(stream)
		for body := []byte(tc.body); len(body) > 0; {
			n := min(len(body), 4096)
			_, err = stream.Write(http3FinFrame(0, body[:n]))
			AssertNil(err)
			body = body[n:]
		}
		if tc.body != "" {
			httpStaticAssertNoResponse(stream)
		}
		AssertNil(stream.Close(), "GET input must not be canceled by an early response")
		data, status := http3StreamingRxRead(stream)
		AssertEqual("200", status)
		AssertEqual(tc.response, string(data), "response must be complete through FIN")
	}
	AssertNil(context.Cause(conn.Context()))
	AssertNotContains(vpp.Vppctl("show session verbose"), " closed ")
}

func HttpStaticHttp3StreamedGetBodyLimitTest(s *HttpStaticSrvSuite) {
	address := httpStaticStreamedGetServer(s, true)
	conn := http3StreamingTxConnect(address)
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStream()
	AssertNil(err)
	AssertNil(stream.SetDeadline(time.Now().Add(defaultHttpTimeout)))
	_, err = stream.Write(http3FinHeaders("GET", "/index.html", ""))
	AssertNil(err)
	httpStaticAssertNoResponse(stream)
	for range 16 {
		_, err = stream.Write(http3FinFrame(0, bytes.Repeat([]byte("x"), 4096)))
		AssertNil(err)
	}
	httpStaticAssertNoResponse(stream)
	_, err = stream.Write(http3FinFrame(0, []byte("x")))
	AssertNil(err)
	// The 65537th content byte must trigger 413 without requiring request FIN.
	AssertEmpty(http3ReadEarlyResponse(stream, "413"))
	next := http3StreamingTxRequest(conn, "GET", "/index.html", "known body", false)
	data, status := http3StreamingRxRead(next)
	AssertEqual("200", status)
	AssertEqual(httpStaticStreamedGetContent, string(data))
	AssertNil(context.Cause(conn.Context()), "body limit must affect only the rejected stream")
}

func HttpStaticHttp3StreamedGetResetTest(s *HttpStaticSrvSuite) {
	address := httpStaticStreamedGetServer(s, true)
	conn := http3StreamingTxConnect(address)
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStream()
	AssertNil(err)
	AssertNil(stream.SetDeadline(time.Now().Add(defaultHttpTimeout)))
	_, err = stream.Write(append(http3FinHeaders("GET", "/index.html", ""), http3FinFrame(0, []byte("unfinished"))...))
	AssertNil(err)
	httpStaticAssertNoResponse(stream)
	stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	data, err := io.ReadAll(stream)
	AssertEmpty(data, "request reset must not be mistaken for successful request completion")
	if err != nil {
		var reset *quic.StreamError
		AssertEqual(true, errors.As(err, &reset), "expected FIN or stream reset, got %v", err)
		AssertEqual(true, reset.Remote)
	}
	next := http3StreamingTxRequest(conn, "GET", "/index.html", "", true)
	data, status := http3StreamingRxRead(next)
	AssertEqual("200", status)
	AssertEqual(httpStaticStreamedGetContent, string(data))
	AssertNil(context.Cause(conn.Context()), "canceling a GET must preserve the connection")
}

func HttpStaticBodyReaderReuseTest(s *HttpStaticSrvSuite) {
	s.SkipIfMultiWorker()
	address := httpStaticStreamedGetServer(s, false)
	AssertEmpty(s.Containers.Vpp.VppInstance.Vppctl("test-url-handler enable"))
	body := strings.Repeat("discarded!", 3200)
	for _, tc := range []struct{ path, response string }{
		{"/index.html", httpStaticStreamedGetContent},
		{"/test3", ""},
	} {
		By("known-length POST followed by GET on the same connection: " + tc.path)
		func() {
			conn, reader := httpCliChunkedConnect(address, "POST", tc.path,
				fmt.Sprintf("Content-Length: %d\r\n", len(body)), "")
			defer conn.Close()
			// Ensure the file/URL body reader is installed before sending content.
			httpStaticAssertNoResponse(conn)
			_, err := io.WriteString(conn, body)
			AssertNil(err)
			response, err := http.ReadResponse(reader, &http.Request{Method: "POST"})
			AssertNil(err)
			AssertHttpStatus(response, http.StatusOK)
			data, err := io.ReadAll(response.Body)
			AssertNil(err)
			AssertEqual(tc.response, string(data))
			AssertNil(response.Body.Close())
			AssertEqual(false, response.Close)

			_, err = fmt.Fprintf(conn, "GET /index.html HTTP/1.1\r\nHost: %s\r\n\r\n", address)
			AssertNil(err)
			response, err = http.ReadResponse(reader, &http.Request{Method: "GET"})
			AssertNil(err)
			AssertHttpStatus(response, http.StatusOK)
			data, err = io.ReadAll(response.Body)
			AssertNil(err)
			AssertEqual(httpStaticStreamedGetContent, string(data), "completed body reader must not consume the next request")
			AssertNil(response.Body.Close())
		}()
	}
}

func HttpStaticHttp3StreamedGetUrlHandlerTest(s *HttpStaticSrvSuite) {
	s.SkipIfMultiWorker()
	address := httpStaticStreamedGetServer(s, true)
	AssertEmpty(s.Containers.Vpp.VppInstance.Vppctl("test-url-handler enable"))
	conn := http3StreamingTxConnect(address)
	defer conn.CloseWithError(0, "")
	for _, path := range []string{"/version.json", "/test1"} {
		By("streamed GET dispatched to URL handler after FIN: " + path)
		stream, err := conn.OpenStream()
		AssertNil(err)
		AssertNil(stream.SetDeadline(time.Now().Add(defaultHttpTimeout)))
		_, err = stream.Write(append(http3FinHeaders("GET", path, ""), http3FinFrame(0, []byte("discarded"))...))
		AssertNil(err)
		httpStaticAssertNoResponse(stream)
		AssertNil(stream.Close())
		data, status := http3StreamingRxRead(stream)
		AssertEqual("200", status)
		if path == "/test1" {
			AssertEqual("hello", string(data))
		} else {
			AssertContains(string(data), "build_date")
		}
	}
}

func HttpStaticChunkedRequestRejectedTest(s *HttpStaticSrvSuite) {
	s.SkipIfMultiWorker()
	vpp := s.Containers.Vpp.VppInstance
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	Log(vpp.Vppctl("http static server url-handlers fifo-size 4k uri http://" + address))
	Log(vpp.Vppctl("test-url-handler enable"))

	conn, reader := httpCliChunkedConnect(address, "POST", "/test3",
		"Transfer-Encoding: chunked\r\n", "")
	defer conn.Close()
	response, err := http.ReadResponse(reader, &http.Request{Method: "POST"})
	AssertNil(err)
	defer response.Body.Close()
	AssertHttpStatus(response, http.StatusLengthRequired)
	AssertEqual(true, response.Close)
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

func HttpStaticListenerAddDelTest(s *HttpStaticSrvSuite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Https

	Log(vpp.Vppctl("http static server"))

	o := vpp.Vppctl("show http static server listeners")
	Log(o)
	AssertNotContains(o, "listener")

	Log(vpp.Vppctl("http static listener add uri http://" + serverAddress + " url-handlers"))

	o = vpp.Vppctl("show http static server listeners")
	Log(o)
	AssertContains(o, "listener")

	Log(vpp.Vppctl("http static listener del uri http://" + serverAddress + " url-handlers"))

	o = vpp.Vppctl("show http static server listeners")
	Log(o)
	AssertNotContains(o, "listener")
}

func HttpStaticListenerAddDelMismatchTest(s *HttpStaticSrvSuite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Https
	serverAddress2 := s.VppAddr() + ":" + s.Ports.Http

	Log(vpp.Vppctl("http static server"))

	o := vpp.Vppctl("show http static server listeners")
	Log(o)
	AssertNotContains(o, "listener")

	Log(vpp.Vppctl("http static listener add uri https://" + serverAddress + " url-handlers"))

	o = vpp.Vppctl("show http static server listeners")
	Log(o)
	AssertContains(o, "listener")

	o = vpp.Vppctl("http static listener del uri https://" + serverAddress2 + " url-handlers")
	Log(o)
	AssertContains(o, "endpoint not found")

	o = vpp.Vppctl("show http static server listeners")
	Log(o)
	AssertContains(o, "listener")

	o = vpp.Vppctl("http static listener del uri http://" + serverAddress + " url-handlers")
	Log(o)
	AssertContains(o, "endpoint not found")

	o = vpp.Vppctl("show http static server listeners")
	Log(o)
	AssertContains(o, "listener")

	o = vpp.Vppctl("http static listener del uri https://" + serverAddress + " url-handlers")
	Log(o)
	AssertNotContains(o, "endpoint not found")

	o = vpp.Vppctl("show http static server listeners")
	Log(o)
	AssertNotContains(o, "listener")
}

func HttpStaticAltSvcInvalidPortTest(s *HttpStaticSrvSuite) {
	vpp := s.Containers.Vpp.VppInstance

	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	o := vpp.Vppctl("http static server uri http://" + serverAddress +
		" url-handlers h3-alt-svc-port")
	Log(o)
	AssertContains(o, "unknown input `h3-alt-svc-port'")

	vpp.Vppctl("http static server")
	o = vpp.Vppctl("http static listener add uri http://" + serverAddress +
		" url-handlers h3-alt-svc-port")
	Log(o)
	AssertContains(o, "unknown input `h3-alt-svc-port'")

	Log(vpp.Vppctl("http static server disable"))
	for _, port := range []string{"0", "65536"} {
		o := vpp.Vppctl("http static server uri http://" + serverAddress +
			" url-handlers h3-alt-svc-port " + port)
		Log(o)
		AssertContains(o, "h3-alt-svc-port must be between 1 and 65535")
	}

	Log(vpp.Vppctl("http static server"))
	for _, port := range []string{"0", "65536"} {
		o := vpp.Vppctl("http static listener add uri http://" + serverAddress +
			" url-handlers h3-alt-svc-port " + port)
		AssertContains(o, "h3-alt-svc-port must be between 1 and 65535")
	}
}

func HttpStaticAltSvcBorderlinePortTest(s *HttpStaticSrvSuite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	client := NewHttpClient(defaultHttpTimeout, false)
	defer client.CloseIdleConnections()

	runCLI := func(command string) {
		o := vpp.Vppctl(command)
		Log(o)
		AssertEmpty(strings.TrimSpace(o), command)
	}
	checkPort := func(port string) {
		o := vpp.Vppctl("show http static server listeners")
		Log(o)
		AssertContains(o, "h3-alt-svc-port "+port)

		resp, err := client.Get("http://" + serverAddress + "/version.json")
		AssertNil(err, fmt.Sprint(err))
		defer resp.Body.Close()
		Log(DumpHttpResp(resp, false))

		AssertHttpStatus(resp, http.StatusOK)
		AssertEqual(1, resp.ProtoMajor)
		AssertHttpHeaderWithValue(resp, "Alt-Svc", fmt.Sprintf(`h3=":%s"`, port))
		_, err = io.Copy(io.Discard, resp.Body)
		AssertNil(err, fmt.Sprint(err))
	}

	for _, port := range []string{"1", "65535"} {
		runCLI("http static server uri http://" + serverAddress +
			" url-handlers h3-alt-svc-port " + port)
		checkPort(port)
		runCLI("http static server disable")
	}

	runCLI("http static server")
	for _, port := range []string{"1", "65535"} {
		runCLI("http static listener add uri http://" + serverAddress +
			" url-handlers h3-alt-svc-port " + port)
		checkPort(port)
		runCLI("http static listener del uri http://" + serverAddress)
		runCLI("show http static server listeners")
	}
}

func HttpStaticAltSvcHttp1Test(s *HttpStaticSrvSuite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	Log(vpp.Vppctl("http static server uri http://" + serverAddress +
		" url-handlers http1-only h3-alt-svc-port 8443"))

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "http://"+serverAddress+"/version.json", nil)
	AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	Log(DumpHttpResp(resp, false))
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()

	AssertHttpStatus(resp, 200)
	AssertEqual(1, resp.ProtoMajor)
	AssertHttpHeaderWithValue(resp, "Alt-Svc", `h3=":8443"`)

	o := vpp.Vppctl("show http static server listeners")
	Log(o)
	AssertContains(o, "h3-alt-svc-port 8443")
}

func HttpStaticAltSvcHttps1Test(s *HttpStaticSrvSuite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Https
	Log(vpp.Vppctl("http static server uri https://" + serverAddress +
		" url-handlers http1-only h3-alt-svc-port 8443"))

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "https://"+serverAddress+"/version.json", nil)
	AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	Log(DumpHttpResp(resp, false))
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()

	AssertHttpStatus(resp, 200)
	AssertEqual(1, resp.ProtoMajor)
	AssertHttpHeaderWithValue(resp, "Alt-Svc", `h3=":8443"`)

	o := vpp.Vppctl("show http static server listeners")
	Log(o)
	AssertContains(o, "h3-alt-svc-port 8443")
}

func HttpStaticAltSvcHttp2Test(s *HttpStaticSrvSuite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Http
	Log(vpp.Vppctl("http static server uri http://" + serverAddress +
		" url-handlers h3-alt-svc-port 8443"))

	client := NewHttpClient(defaultHttpTimeout, true)
	// allow HTTP 2.0 unencrypted
	transport := client.Transport.(*http.Transport)
	transport.Protocols = new(http.Protocols)
	transport.Protocols.SetUnencryptedHTTP2(true)

	req, err := http.NewRequest("GET", "http://"+serverAddress+"/version.json", nil)
	AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	Log(DumpHttpResp(resp, false))
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()

	AssertHttpStatus(resp, 200)
	AssertEqual(2, resp.ProtoMajor)
	AssertHttpHeaderWithValue(resp, "Alt-Svc", `h3=":8443"`)

	o := vpp.Vppctl("show http static server listeners")
	Log(o)
	AssertContains(o, "h3-alt-svc-port 8443")
}

func HttpStaticAltSvcHttps2Test(s *HttpStaticSrvSuite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Https
	Log(vpp.Vppctl("http static server uri https://" + serverAddress +
		" url-handlers h3-alt-svc-port 8443"))

	client := NewHttpClient(defaultHttpTimeout, true)
	req, err := http.NewRequest("GET", "https://"+serverAddress+"/version.json", nil)
	AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	Log(DumpHttpResp(resp, false))
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()

	AssertHttpStatus(resp, 200)
	AssertEqual(2, resp.ProtoMajor)
	AssertHttpHeaderWithValue(resp, "Alt-Svc", `h3=":8443"`)

	o := vpp.Vppctl("show http static server listeners")
	Log(o)
	AssertContains(o, "h3-alt-svc-port 8443")
}

func HttpStaticAltSvcNoHdrTest(s *HttpStaticSrvSuite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Https
	Log(vpp.Vppctl("http static server uri https://" + serverAddress +
		" url-handlers"))

	o := vpp.Vppctl("show http static server listeners")
	Log(o)
	AssertNotContains(o, "h3-alt-svc-port 8443")

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "https://"+serverAddress+"/version.json", nil)
	AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	Log(DumpHttpResp(resp, false))
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()

	AssertHttpStatus(resp, 200)
	AssertEqual(1, resp.ProtoMajor)
	AssertHttpHeaderNotPresent(resp, "Alt-Svc")
}

func HttpStaticAltSvcListenerNoHdrTest(s *HttpStaticSrvSuite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Https
	Log(vpp.Vppctl("http static server debug"))

	o := vpp.Vppctl("show http static server listeners")
	Log(o)
	AssertNotContains(o, "h3-alt-svc-port 8443")

	Log(vpp.Vppctl("http static listener add uri https://" + serverAddress +
		" url-handlers"))

	o = vpp.Vppctl("show http static server listeners")
	Log(o)

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "https://"+serverAddress+"/version.json", nil)
	AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	Log(DumpHttpResp(resp, false))
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()

	AssertHttpStatus(resp, 200)
	AssertEqual(1, resp.ProtoMajor)
	AssertHttpHeaderNotPresent(resp, "Alt-Svc")
}

// listener del checks only uri not h3-alt-svc-port
func HttpStaticAltSvcListenerDelTest(s *HttpStaticSrvSuite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Https
	Log(vpp.Vppctl("http static server debug"))

	o := vpp.Vppctl("show http static server listeners")
	Log(o)
	AssertNotContains(o, "h3-alt-svc-port 8443")

	Log(vpp.Vppctl("http static listener add uri https://" + serverAddress +
		" url-handlers h3-alt-svc-port 8443"))

	o = vpp.Vppctl("show http static server listeners")
	Log(o)
	AssertContains(o, "h3-alt-svc-port 8443")

	client := NewHttpClient(defaultHttpTimeout, false)
	req, err := http.NewRequest("GET", "https://"+serverAddress+"/version.json", nil)
	AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	Log(DumpHttpResp(resp, false))
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()

	AssertHttpStatus(resp, 200)
	AssertEqual(1, resp.ProtoMajor)
	AssertHttpHeaderWithValue(resp, "Alt-Svc", `h3=":8443"`)

	o = vpp.Vppctl("http static listener del uri https://" + serverAddress)
	Log(o)
	AssertNotContains(o, "endpoint not found")

	o = vpp.Vppctl("show http static server listeners")
	Log(o)
	AssertNotContains(o, "h3-alt-svc-port 8443")
}
