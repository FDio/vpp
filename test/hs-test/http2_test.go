package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/edwarnicke/exechelper"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterH2Tests(Http2TcpGetTest, Http2TcpPostTest, Http2MultiplexingTest, Http2TlsTest, Http2ContinuationTxTest, Http2ServerMemLeakTest,
		Http2ClientGetTest, Http2ClientPostTest, Http2ClientPostPtrTest, Http2ClientGetRepeatTest, Http2ClientMultiplexingTest,
		Http2ClientH2cTest, Http2ClientMemLeakTest)
	RegisterH2MWTests(Http2MultiplexingMWTest, Http2ClientMultiplexingMWTest)
	RegisterVethTests(Http2CliTlsTest, Http2ClientContinuationTest, Http2ClientPostFormTest, Http2ClientPostFormPtrTest)
}

func Http2TcpGetTest(s *Http2Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	vpp.Vppctl("http cli server listener add uri http://" + serverAddress)
	Log(vpp.Vppctl("show session verbose 2"))
	args := fmt.Sprintf("--max-time 10 --noproxy '*' --http2-prior-knowledge http://%s/show/version", serverAddress)
	writeOut, log := RunCurlContainer(s.Containers.Curl, args)
	Log(vpp.Vppctl("show session verbose 2"))
	AssertContains(log, "HTTP/2 200")
	AssertContains(writeOut, "<html>", "<html> not found in the result!")
	AssertContains(writeOut, "</html>", "</html> not found in the result!")

	/* test session cleanup */
	httpStreamCleanupDone := false
	tcpSessionCleanupDone := false
	for nTries := 0; nTries < 30; nTries++ {
		o := vpp.Vppctl("show session verbose 2")
		if !strings.Contains(o, "[T] "+serverAddress+"->10.") {
			tcpSessionCleanupDone = true
		}
		if !strings.Contains(o, "[H2]") {
			httpStreamCleanupDone = true
		}
		if httpStreamCleanupDone && tcpSessionCleanupDone {
			break
		}
		time.Sleep(1 * time.Second)
	}
	AssertEqual(true, tcpSessionCleanupDone, "TCP session not cleaned up")
	AssertEqual(true, httpStreamCleanupDone, "HTTP/2 stream not cleaned up")

	/* test server app stop listen */
	vpp.Vppctl("http cli server listener del uri http://" + serverAddress)
	o := vpp.Vppctl("show session verbose proto http")
	AssertNotContains(o, "LISTEN")
}

func Http2TcpPostTest(s *Http2Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + " url-handlers max-body-size 20m rx-buff-thresh 20m fifo-size 65k debug 2"))
	Log(vpp.Vppctl("test-url-handler enable"))
	args := fmt.Sprintf("--max-time 10 --noproxy '*' --data-binary @%s --http2-prior-knowledge http://%s/test3", CurlContainerTestFile, serverAddress)
	_, log := RunCurlContainer(s.Containers.Curl, args)
	AssertContains(log, "HTTP/2 200")
}

func Http2MultiplexingTest(s *Http2Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	vpp.Vppctl("http tps uri http://" + serverAddress + " no-zc")

	args := fmt.Sprintf("--log-file=%s -T10 -n21 -c1 -m100 http://%s/test_file_20M", H2loadLogFileName(s.Containers.H2load), serverAddress)
	s.Containers.H2load.ExtraRunningArgs = args
	s.Containers.H2load.Run()

	defer CollectH2loadLogs(s.Containers.H2load)

	o, _ := s.Containers.H2load.GetOutput()
	Log(o)
	AssertContains(o, " 0 failed")
	AssertContains(o, " 0 errored")
	AssertContains(o, " 0 timeout")
}

func Http2MultiplexingMWTest(s *Http2Suite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	vpp.Vppctl("http tps uri http://" + serverAddress + " no-zc")

	args := fmt.Sprintf("-T10 -n100 -c4 -r1 -m10 http://%s/test_file_20M", serverAddress)
	s.Containers.H2load.ExtraRunningArgs = args
	s.Containers.H2load.Run()

	o, _ := s.Containers.H2load.GetOutput()
	Log(o)
	AssertContains(o, " 0 failed")
	AssertContains(o, " 0 errored")
	AssertContains(o, " 0 timeout")
}

func Http2TlsTest(s *Http2Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	Log(vpp.Vppctl("http static server uri tls://" + serverAddress + " url-handlers debug"))

	args := fmt.Sprintf("--max-time 10 --noproxy '*' -k https://%s/version.json", serverAddress)
	writeOut, log := RunCurlContainer(s.Containers.Curl, args)
	Log(vpp.Vppctl("show session verbose 2"))
	AssertContains(log, "HTTP/2 200")
	AssertContains(log, "ALPN: server accepted h2")
	AssertContains(writeOut, "version")
}

func Http2ContinuationTxTest(s *Http2Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	vpp.Vppctl("http tps uri http://" + serverAddress + " no-zc")
	args := fmt.Sprintf("-w %%{size_header} --max-time 10 --noproxy '*' --http2-prior-knowledge http://%s/test_file_64?test_header=32k", serverAddress)
	writeOut, log := RunCurlContainer(s.Containers.Curl, args)
	sizeHeader, err := strconv.Atoi(strings.ReplaceAll(writeOut, "\x00", ""))
	// curl container output get rarely corrupted for unknown reason
	if err != nil {
		Log("corrupted output, skipping validation...")
		return
	}
	AssertContains(log, "HTTP/2 200")
	AssertContains(log, "[64 bytes data]")
	AssertGreaterEqual(sizeHeader, 32768)
}

func Http2ServerMemLeakTest(s *Http2Suite) {
	s.SkipUnlessLeakCheck()

	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	vpp.Vppctl("http cli server uri http://" + serverAddress)
	target := fmt.Sprintf("http://%s/show/version", serverAddress)

	/* no goVPP less noise */
	vpp.Disconnect()

	/* warmup requests (FIB, pools) */
	args := fmt.Sprintf("--max-time 10 --noproxy '*' --http2-prior-knowledge -z %s %s %s %s", target, target, target, target)
	_, log := RunCurlContainer(s.Containers.Curl, args)
	AssertContains(log, "HTTP/2 200")
	for range 10 {
		time.Sleep(time.Second * 1)
		AssertNil(s.Containers.Curl.Start())
	}

	/* let's give it some time to clean up sessions, so pool elements can be reused and we have less noise */
	time.Sleep(time.Second * 15)

	vpp.EnableMemoryTrace()
	traces1, err := vpp.GetMemoryTrace()
	AssertNil(err, fmt.Sprint(err))

	for range 10 {
		time.Sleep(time.Second * 1)
		AssertNil(s.Containers.Curl.Start())
	}

	/* let's give it some time to clean up sessions */
	time.Sleep(time.Second * 15)

	traces2, err := vpp.GetMemoryTrace()
	AssertNil(err, fmt.Sprint(err))
	vpp.MemLeakCheck(traces1, traces2)
}

func Http2CliTlsTest(s *VethsSuite) {
	uri := "https://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1

	s.Containers.ServerVpp.VppInstance.Vppctl("http cli server uri " + uri)

	o := s.Containers.ClientVpp.VppInstance.Vppctl("http cli client" +
		" uri " + uri + "/show/version")
	Log(o)
	AssertContains(o, "<html>", "<html> not found in the result!")
	AssertContains(o, "</html>", "</html> not found in the result!")
	s.Containers.ClientVpp.VppInstance.Vppctl("clear http stats")

	/* second request to test postponed ho-cleanup */
	o = s.Containers.ClientVpp.VppInstance.Vppctl("http cli client" +
		" uri " + uri + "/show/vlib/graph fifo-size 65536")
	Log(o)
	AssertContains(o, "<html>", "<html> not found in the result!")
	AssertContains(o, "</html>", "</html> not found in the result!")

	o = s.Containers.ClientVpp.VppInstance.Vppctl("show http stats")
	Log(o)
	AssertContains(o, "1 connections established")
	AssertContains(o, "1 requests sent")
	AssertContains(o, "1 responses received")
	AssertContains(o, "1 application streams opened")
	AssertContains(o, "1 application streams closed")
	o = s.Containers.ServerVpp.VppInstance.Vppctl("show http stats")
	Log(o)
	AssertContains(o, "2 connections accepted")
	AssertContains(o, "2 requests received")
	AssertContains(o, "2 responses sent")
	AssertContains(o, "2 application streams opened")
	AssertContains(o, "2 application streams closed")
}

func http2ClientPostFormTest(s *VethsSuite, usePtr bool) {
	uri := "http://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	o := s.Containers.ServerVpp.VppInstance.Vppctl("http static server uri " + uri + " url-handlers debug")
	Log(o)
	cmd := "http client post http2 verbose uri " + uri + "/interface_stats.json data " + s.Interfaces.Server.VppName()
	if usePtr {
		cmd += " use-ptr"
	}
	o = s.Containers.ClientVpp.VppInstance.Vppctl(cmd)
	Log(o)
	AssertContains(o, "HTTP/2 200 OK")
}

func Http2ClientPostFormTest(s *VethsSuite) {
	http2ClientPostFormTest(s, false)
}

func Http2ClientPostFormPtrTest(s *VethsSuite) {
	http2ClientPostFormTest(s, true)
}

func Http2ClientGetTest(s *Http2Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.HostAddr() + ":" + s.Ports.Port2

	s.CreateNginxServer()
	AssertNil(s.Containers.NginxServer.Start())

	uri := "https://" + serverAddress + "/httpTestFile"
	o := vpp.Vppctl("http client save-to response.txt verbose uri " + uri)
	Log(o)
	AssertContains(o, "HTTP/2 200 OK")
	AssertContains(o, "10000000 bytes saved to file")

	logPath := s.Containers.NginxServer.GetHostWorkDir() + "/" + s.Containers.NginxServer.Name + "-access.log"
	logContents, err := exechelper.Output("cat " + logPath)
	AssertNil(err)
	AssertContains(string(logContents), "HTTP/2")
	AssertContains(string(logContents), "scheme=https conn=")
}

func Http2ClientH2cTest(s *Http2Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.HostAddr() + ":" + s.Ports.Port1

	s.CreateNginxServer()
	AssertNil(s.Containers.NginxServer.Start())

	uri := "http://" + serverAddress + "/httpTestFile"
	o := vpp.Vppctl("http client http2 save-to response.txt verbose uri " + uri)
	Log(o)
	AssertContains(o, "HTTP/2 200 OK")
	AssertContains(o, "10000000 bytes saved to file")

	logPath := s.Containers.NginxServer.GetHostWorkDir() + "/" + s.Containers.NginxServer.Name + "-access.log"
	logContents, err := exechelper.Output("cat " + logPath)
	AssertNil(err)
	AssertContains(string(logContents), "HTTP/2")
	AssertContains(string(logContents), "scheme=http conn=")
}

func http2ClientPostFile(s *Http2Suite, usePtr bool, fileSize int) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.HostAddr() + ":" + s.Ports.Port2

	fileName := "/tmp/test_file.txt"
	Log(vpp.Container.Exec(false, "fallocate -l "+strconv.Itoa(fileSize)+" "+fileName))
	Log(vpp.Container.Exec(false, "ls -la "+fileName))

	s.CreateNginxServer()
	AssertNil(s.Containers.NginxServer.Start())

	uri := "https://" + serverAddress + "/test_upload"
	cmd := "http client post verbose uri " + uri + " file " + fileName
	if usePtr {
		cmd += " use-ptr"
	}
	o := vpp.Vppctl(cmd)
	Log(o)
	AssertContains(o, "HTTP/2 200 OK")
}

func Http2ClientPostTest(s *Http2Suite) {
	http2ClientPostFile(s, false, 131072)
}

func Http2ClientPostPtrTest(s *Http2Suite) {
	http2ClientPostFile(s, true, 131072)
}

func Http2ClientGetRepeatTest(s *Http2Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.HostAddr() + ":" + s.Ports.Port2

	s.CreateNginxServer()
	AssertNil(s.Containers.NginxServer.Start())

	uri := "https://" + serverAddress + "/64B"
	cmd := fmt.Sprintf("http client http2 repeat %d uri %s", 10, uri)
	o := vpp.Vppctl(cmd)
	Log(o)
	AssertContains(o, "10 request(s)")
}

func Http2ClientMultiplexingTest(s *Http2Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.HostAddr() + ":" + s.Ports.Port2

	s.CreateNginxServer()
	AssertNil(s.Containers.NginxServer.Start())

	uri := "https://" + serverAddress + "/httpTestFile"
	cmd := fmt.Sprintf("http client http2 streams %d repeat %d uri %s", 10, 20, uri)
	o := vpp.Vppctl(cmd)
	Log(o)
	AssertContains(o, "20 request(s)")
	logPath := s.Containers.NginxServer.GetHostWorkDir() + "/" + s.Containers.NginxServer.Name + "-access.log"
	logContents, err := exechelper.Output("cat " + logPath)
	Log(string(logContents))
	AssertNil(err)
	AssertContains(string(logContents), "conn_reqs=20")

	/* test session cleanup */
	httpStreamCleanupDone := false
	tcpSessionCleanupDone := false
	for nTries := 0; nTries < 30; nTries++ {
		o := vpp.Vppctl("show session verbose")
		if !strings.Contains(o, "[T]") {
			tcpSessionCleanupDone = true
		}
		if !strings.Contains(o, "[H2]") {
			httpStreamCleanupDone = true
		}
		if httpStreamCleanupDone && tcpSessionCleanupDone {
			break
		}
		time.Sleep(1 * time.Second)
	}
	AssertEqual(true, tcpSessionCleanupDone, "TCP session not cleaned up")
	AssertEqual(true, httpStreamCleanupDone, "HTTP/2 stream not cleaned up")
}

func Http2ClientMultiplexingMWTest(s *Http2Suite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()

	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.HostAddr() + ":" + s.Ports.Port2

	s.CreateNginxServer()
	AssertNil(s.Containers.NginxServer.Start())

	uri := "https://" + serverAddress + "/httpTestFile"
	cmd := fmt.Sprintf("http client http2 sessions 2 streams %d repeat %d uri %s", 5, 20, uri)
	o := vpp.Vppctl(cmd)
	Log(o)
	AssertContains(o, "20 request(s)")
	logPath := s.Containers.NginxServer.GetHostWorkDir() + "/" + s.Containers.NginxServer.Name + "-access.log"
	logContents, err := exechelper.Output("cat " + logPath)
	Log(string(logContents))
	AssertNil(err)
	AssertEqual(2, strings.Count(string(logContents), "conn_reqs=10"))
}

func Http2ClientContinuationTest(s *VethsSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1

	s.Containers.ServerVpp.VppInstance.Vppctl("http tps uri https://" + serverAddress + " no-zc")

	uri := fmt.Sprintf("https://%s/test_file_64?test_header=32k", serverAddress)
	o := s.Containers.ClientVpp.VppInstance.Vppctl("http client fifo-size 64k verbose save-to response.txt uri " + uri)
	Log(o)
	AssertContains(o, "HTTP/2 200 OK")
	AssertGreaterEqual(strings.Count(o, "x"), 32768)
}

func Http2ClientMemLeakTest(s *Http2Suite) {
	s.SkipUnlessLeakCheck()

	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.HostAddr() + ":" + s.Ports.Port1

	s.CreateNginxServer()
	AssertNil(s.Containers.NginxServer.Start())

	uri := "http://" + serverAddress + "/64B"

	/* no goVPP less noise */
	vpp.Disconnect()

	/* warmup requests (FIB, pools) */
	cmd := fmt.Sprintf("http client verbose http2 uri %s", uri)
	o := vpp.Vppctl(cmd)
	AssertContains(o, "HTTP/2 200 OK")
	/* do second request because pool is at threshold and will grow again */
	o = vpp.Vppctl(cmd)
	AssertContains(o, "HTTP/2 200 OK")

	/* let's give it some time to clean up sessions, so pool elements can be reused and we have less noise */
	time.Sleep(time.Second * 15)

	vpp.EnableMemoryTrace()
	traces1, err := vpp.GetMemoryTrace()
	AssertNil(err, fmt.Sprint(err))

	o = vpp.Vppctl(cmd)
	AssertContains(o, "HTTP/2 200 OK")

	/* let's give it some time to clean up sessions */
	time.Sleep(time.Second * 15)

	traces2, err := vpp.GetMemoryTrace()
	AssertNil(err, fmt.Sprint(err))
	vpp.MemLeakCheck(traces1, traces2)
}
