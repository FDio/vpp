package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	. "fd.io/hs-test/infra"
	"github.com/edwarnicke/exechelper"
	. "github.com/onsi/ginkgo/v2"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func init() {
	RegisterH3Tests(Http3GetTest, Http3DownloadTest, Http3PostTest, Http3UploadTest, Http3ClientGetRepeatTest,
		Http3ClientGetMultiplexingTest, Http3PeerResetStream, Http3ClientRequestIncompleteTest,
		Http3MissingPseudoHeaderTest, Http3MissingSchemePseudoHeaderTest, Http3MissingPathPseudoHeaderTest,
		Http3MissingAuthorityPseudoHeaderTest, Http3ConnectWithSchemePathPseudoHeadersTest,
		Http3PseudoHeaderAfterRegularTest, Http3ReservedFrameTest, Http3DataFrameOnCtrlStreamTest,
		Http3GoawayOnReqStreamTest, Http3SecondSettingsFrameTest,
		Http3ReservedSettingsTest, Http3MissingSettingsTest, Http3SecondCtrlStreamTest,
		Http3SecondQpackDecoderStreamTest, Http3SecondQpackEncoderStreamTest, Http3CtrlStreamClosedTest,
		Http3QpackDecompressionFailedTest, Http3ClientOpenPushStreamTest, Http3DataBeforeHeadersTest,
		Http3LongerDataThanContentLengthTest, Http3HalfClosedBeforeAllDataTest, Http3StaticGetTest,
		Http3MaxHeaderListSizeTest)
	RegisterH3MWTests(Http3ClientFailedConnectMWTest, Http3TsFifoMemPressureMWTest)
	RegisterVethTests(Http3CliTest, Http3ClientPostTest, Http3ClientPostPtrTest)
}

func http3TestSessionCleanupServer(s *Http3Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	udpCleanupDone := false
	quicCleanupDone := false
	httpCleanupDone := false
	for range 5 {
		o := vpp.Vppctl("show session verbose 2")
		if !strings.Contains(o, "[U] "+serverAddress+"->10.") {
			udpCleanupDone = true
		}
		if strings.Count(o, "[Q]") == 1 {
			quicCleanupDone = true
		}
		if !strings.Contains(o, "[H3]") {
			httpCleanupDone = true
		}
		if httpCleanupDone && udpCleanupDone && quicCleanupDone {
			break
		}
		time.Sleep(1 * time.Second)
	}
	AssertEqual(true, udpCleanupDone, "UDP session not cleaned up")
	AssertEqual(true, quicCleanupDone, "QUIC not cleaned up")
	AssertEqual(true, httpCleanupDone, "HTTP/3 not cleaned up")
}

func Http3StaticGetTest(s *Http3Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	Log(vpp.Vppctl("http static server http3 uri https://" + serverAddress + " url-handlers"))
	Log(vpp.Vppctl("test-url-handler enable"))
	args := fmt.Sprintf("-k --max-time 10 --noproxy '*' --http3-only https://%s/version.json", serverAddress)
	writeOut, log := RunCurlContainer(s.Containers.Curl, args)
	Log(vpp.Vppctl("show session verbose 2"))
	AssertContains(log, "HTTP/3 200")
	AssertContains(writeOut, "build_date")
}

func Http3GetTest(s *Http3Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	Log(vpp.Vppctl("http cli server http3-enabled listener add uri https://" + serverAddress))
	Log(vpp.Vppctl("show session verbose 2"))
	args := fmt.Sprintf("-k --max-time 10 --noproxy '*' --http3-only https://%s/show/version", serverAddress)
	writeOut, log := RunCurlContainer(s.Containers.Curl, args)
	Log(vpp.Vppctl("show session verbose 2"))
	AssertContains(log, "HTTP/3 200")
	AssertContains(writeOut, "<html>", "<html> not found in the result!")
	AssertContains(writeOut, "</html>", "</html> not found in the result!")

	/* test session cleanup */
	http3TestSessionCleanupServer(s)
	o := vpp.Vppctl("show http stats")
	Log(o)
	AssertContains(o, "1 connections accepted")
	AssertContains(o, "1 application streams opened")
	AssertContains(o, "1 application streams closed")
	AssertContains(o, "1 requests received")
	AssertContains(o, "1 responses sent")
	ctrlStreamsOpened := 0
	ctrlStreamsClosed := 0
	lines := strings.SplitSeq(o, "\n")
	for line := range lines {
		if strings.Contains(line, "control streams opened") {
			tmp := strings.Split(line, " ")
			ctrlStreamsOpened, _ = strconv.Atoi(tmp[1])
		}
		if strings.Contains(line, "control streams closed") {
			tmp := strings.Split(line, " ")
			ctrlStreamsClosed, _ = strconv.Atoi(tmp[1])
		}
	}
	AssertEqual(ctrlStreamsOpened-ctrlStreamsClosed, 0, "control streams not cleaned up")

	/* test server app stop listen */
	Log(vpp.Vppctl("http cli server listener del uri https://" + serverAddress))
	o = vpp.Vppctl("show session verbose")
	AssertNotContains(o, "LISTEN")
}

func Http3DownloadTest(s *Http3Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	Log(vpp.Vppctl("http tps no-zc h3 uri https://" + serverAddress))

	uri := fmt.Sprintf("https://%s/test_file_10M", serverAddress)
	finished := make(chan error, 1)
	go func() {
		defer GinkgoRecover()
		StartCurl(finished, uri, "", "200", 30, []string{"--http3-only"})
	}()
	Log(vpp.Vppctl("show session verbose 2"))
	AssertNil(<-finished)
}

func Http3PostTest(s *Http3Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	Log(vpp.Vppctl("http tps no-zc h3 uri https://" + serverAddress))

	args := fmt.Sprintf("-k --max-time 30 --noproxy '*' --http3-only -d XXXXXXXX https://%s/test_file_8", serverAddress)
	_, log := RunCurlContainer(s.Containers.Curl, args)
	Log(vpp.Vppctl("show session verbose 2"))
	AssertContains(log, "HTTP/3 200")
}

func Http3UploadTest(s *Http3Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	Log(vpp.Vppctl("http tps no-zc h3 uri https://" + serverAddress))

	args := fmt.Sprintf("-k --max-time 30 --noproxy '*' --http3-only --data-binary @/tmp/testFile https://%s/test_file_10M",
		serverAddress)
	_, log := RunCurlContainer(s.Containers.Curl, args)
	Log(vpp.Vppctl("show session verbose 2"))
	AssertContains(log, "HTTP/3 200")
}

func Http3CliTest(s *VethsSuite) {
	uri := "https://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance
	Log(serverVpp.Vppctl("http cli server http3-enabled listener add uri " + uri))
	o := clientVpp.Vppctl("http cli client http3 uri " + uri + "/show/version")
	Log(o)
	AssertContains(o, "<html>", "<html> not found in the result!")
	AssertContains(o, "</html>", "</html> not found in the result!")
}

func Http3ClientFailedConnectMWTest(s *Http3Suite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	vpp := s.Containers.Vpp.VppInstance
	invalidAddress := net.ParseIP(s.VppAddr())
	invalidAddress = invalidAddress.To4()
	invalidAddress[3] += 5
	serverAddress := invalidAddress.String() + ":" + s.Ports.Port1

	s.StartNginx()

	uri := "https://" + serverAddress
	cmd := fmt.Sprintf("http client http3 timeout 5 uri %s", uri)
	o := vpp.Vppctl(cmd)
	Log(o)
	// depends who win race and timeout first, both outcomes are valid
	connectFailed := strings.Contains(o, "timeout") || strings.Contains(o, "failed to connect")
	AssertEqual(connectFailed, true)
	// short wait for cleanup
	time.Sleep(1 * time.Second)
	o = vpp.Vppctl("show session verbose 2")
	Log(o)
	AssertNotContains(o, "[U]", "UDP session not cleaned up")
	AssertNotContains(o, "[Q]", "QUIC not cleaned up")
	AssertNotContains(o, "[H", "HTTP not cleaned up")
	// wait to be sure http or quic connection timers are not running
	time.Sleep(10 * time.Second)
	Log(vpp.Vppctl("show session verbose 2"))
}

func Http3ClientGetRepeatTest(s *Http3Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.HostAddr() + ":" + s.Ports.Port1

	s.StartNginx()

	uri := "https://" + serverAddress + "/64B"
	cmd := fmt.Sprintf("http client http3 repeat %d uri %s", 10, uri)
	o := vpp.Vppctl(cmd)
	Log(o)
	Log(vpp.Vppctl("show session verbose 2"))
	AssertContains(o, "10 request(s)")
	AssertNotContains(o, "error")
	o = vpp.Vppctl("show http stats")
	Log(o)
	AssertContains(o, "1 connections established")
	AssertContains(o, "1 application streams opened")
	AssertContains(o, "1 application streams closed")
	AssertContains(o, "10 requests sent")
	AssertContains(o, "10 responses received")

	logPath := s.Containers.Nginx.GetHostWorkDir() + "/" + s.Containers.Nginx.Name + "-access.log"
	logContents, err := exechelper.Output("cat " + logPath)
	AssertNil(err)
	AssertContains(string(logContents), "conn_reqs=10")
}

func Http3ClientGetMultiplexingTest(s *Http3Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.HostAddr() + ":" + s.Ports.Port1

	s.StartNginx()

	uri := "https://" + serverAddress + "/64B"
	cmd := fmt.Sprintf("http client http3 streams %d repeat %d uri %s", 10, 1000, uri)

	var lastOutput string
	done := make(chan string, 1)
	go func() {
		done <- vpp.Vppctl(cmd)
	}()

	/* test session sanity and cleanup */
	deadline := time.Now().Add(time.Duration(10) * time.Second)
	for time.Now().Before(deadline) {
		output := vpp.Vppctl("show session verbose 2")
		if output != "" {
			lastOutput = output
		}
		time.Sleep(100 * time.Millisecond)
	}

	o := <-done

	Log(o)
	AssertContains(o, "1000 request(s)")
	AssertNotContains(o, "error")
	o = vpp.Vppctl("show http stats")
	Log(o)
	AssertContains(o, "1 connections established")
	AssertContains(o, "10 application streams opened")
	AssertContains(o, "10 application streams closed")
	AssertContains(o, "1000 requests sent")
	AssertContains(o, "1000 responses received")

	logPath := s.Containers.Nginx.GetHostWorkDir() + "/" + s.Containers.Nginx.Name
	logContents, err := exechelper.Output("cat " + logPath + "-access.log")
	AssertNil(err)
	AssertContains(string(logContents), "conn_reqs=1000")
	logContents, err = exechelper.Output("cat " + logPath + "-error.log")
	AssertNil(err)
	AssertNotContains(string(logContents), "client closed connection while waiting for request")

	Log(lastOutput)
	AssertNotContains(lastOutput, "[U]", "UDP session not cleaned up")
	AssertNotContains(lastOutput, "[Q]", "QUIC not cleaned up")
	AssertNotContains(lastOutput, "[H3]", "HTTP/3 not cleaned up")
}

func http3ClientPostFile(s *VethsSuite, usePtr bool) {
	uri := "https://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance
	Log(serverVpp.Vppctl("http tps no-zc h3 uri " + uri))

	fileName := "/tmp/test_file.txt"
	Log(clientVpp.Container.Exec(false, "fallocate -l 10M "+fileName))
	Log(clientVpp.Container.Exec(false, "ls -la "+fileName))

	cmd := "http client post http3 verbose uri " + uri + "/test_file_10M file " + fileName
	if usePtr {
		cmd += " use-ptr"
	}
	o := clientVpp.Vppctl(cmd)
	Log(o)
	AssertContains(o, "HTTP/3 200 OK")
}

func Http3ClientPostTest(s *VethsSuite) {
	http3ClientPostFile(s, false)
}

func Http3ClientPostPtrTest(s *VethsSuite) {
	http3ClientPostFile(s, true)
}

func Http3MaxHeaderListSizeTest(s *Http3Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	uri := "https://" + serverAddress
	Log(vpp.Vppctl("http tps fifo-size 8k no-zc h3 uri " + uri))

	conn := H3ClientConnect(serverAddress)
	defer conn.CloseWithError(0, "")
	h3c := (&http3.Transport{}).NewClientConn(conn)
	req, err := http.NewRequest(http.MethodGet, uri+"/test_file_64", nil)
	AssertNil(err)
	req.Header = http.Header{"x-test": {strings.Repeat("A", 8192)}}
	stream, err := h3c.OpenRequestStream(context.Background())
	AssertNil(err)
	err = stream.SendRequestHeader(req)
	AssertNil(err)
	resp, err := stream.ReadResponse()
	Log(DumpHttpResp(resp, true))
	AssertHttpStatus(resp, 431)
}

func Http3PeerResetStream(s *Http3Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	Log(vpp.Vppctl("http tps no-zc h3 uri https://" + serverAddress))

	conn := H3ClientConnect(serverAddress)
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStream()
	AssertNil(err)
	// send incomplete headers frame and wait a bit to be sure stream was accepted before we reset it
	stream.Write([]byte{0x01, 0x09})
	time.Sleep(500 * time.Millisecond)
	stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	time.Sleep(500 * time.Millisecond)
	o := vpp.Vppctl("show http stats")
	Log(o)
	AssertContains(o, "1 streams reset by peer")
}

func http3SenInvalidReqExpectStreamError(s *Http3Suite, p []byte, expectedErrorCode http3.ErrCode) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	Log(vpp.Vppctl("http tps no-zc h3 uri https://" + serverAddress))

	conn := H3ClientConnect(serverAddress)
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStream()
	AssertNil(err)
	stream.Write(p)
	time.Sleep(500 * time.Millisecond)
	stream.SetReadDeadline(time.Now().Add(time.Second))
	_, err = stream.Read([]byte{0})
	AssertNotNil(err, "expected stream reset")
	Log(err)
	expectedErr := quic.StreamError{
		StreamID:  stream.StreamID(),
		ErrorCode: quic.StreamErrorCode(expectedErrorCode),
		Remote:    true,
	}
	AssertMatchError(err, &expectedErr, "expected error code "+expectedErrorCode.String())
}

func Http3ClientRequestIncompleteTest(s *Http3Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	Log(vpp.Vppctl("http tps no-zc h3 uri https://" + serverAddress))

	conn := H3ClientConnect(serverAddress)
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStream()
	AssertNil(err)
	// send just frame header and close stream
	stream.Write([]byte{0x01, 0x09})
	stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	time.Sleep(500 * time.Millisecond)
	// server should reset stream with H3_REQUEST_INCOMPLETE
	stream.SetReadDeadline(time.Now().Add(time.Second))
	_, err = stream.Read([]byte{0})
	AssertNotNil(err, "expected stream reset")
	Log(err)
	expectedErr := quic.StreamError{
		StreamID:  stream.StreamID(),
		ErrorCode: quic.StreamErrorCode(http3.ErrCodeRequestIncomplete),
		Remote:    true,
	}
	AssertMatchError(err, &expectedErr, "expected error code H3_REQUEST_INCOMPLETE")
}

func Http3MissingPseudoHeaderTest(s *Http3Suite) {
	// method pseudo header is missing
	// server should reset stream with H3_MESSAGE_ERROR
	http3SenInvalidReqExpectStreamError(
		s,
		[]byte{
			0x01, 0x0D, 0x00, 0x00, 0xD7, 0x50, 0x01, 0x61,
			0xC1, 0x23, 0x61, 0x62, 0x63, 0x01, 0x5A,
		},
		http3.ErrCodeMessageError)
}

func Http3MissingSchemePseudoHeaderTest(s *Http3Suite) {
	// scheme pseudo header is missing
	// server should reset stream with H3_MESSAGE_ERROR
	http3SenInvalidReqExpectStreamError(
		s,
		[]byte{
			0x01, 0x07, 0x00, 0x00, 0xD1, 0x50, 0x01, 0x61,
			0xC1,
		},
		http3.ErrCodeMessageError)
}

func Http3MissingPathPseudoHeaderTest(s *Http3Suite) {
	// path pseudo header is missing
	// server should reset stream with H3_MESSAGE_ERROR
	http3SenInvalidReqExpectStreamError(
		s,
		[]byte{
			0x01, 0x07, 0x00, 0x00, 0xD1, 0xD7, 0x50, 0x01,
			0x61,
		},
		http3.ErrCodeMessageError)
}

func Http3MissingAuthorityPseudoHeaderTest(s *Http3Suite) {
	// authority pseudo header is missing
	// server should reset stream with H3_MESSAGE_ERROR
	http3SenInvalidReqExpectStreamError(
		s,
		[]byte{
			0x01, 0x05, 0x00, 0x00, 0xD1, 0xD7, 0xC1,
		},
		http3.ErrCodeMessageError)
}

func Http3ConnectWithSchemePathPseudoHeadersTest(s *Http3Suite) {
	// plain CONNECT request must omit scheme and path pseudo headers
	// server should reset stream with H3_MESSAGE_ERROR
	http3SenInvalidReqExpectStreamError(
		s,
		[]byte{
			0x01, 0x08, 0x00, 0x00, 0xCF, 0xD7, 0xC1, 0x50,
			0x01, 0x61,
		},
		http3.ErrCodeMessageError)
}

func Http3PseudoHeaderAfterRegularTest(s *Http3Suite) {
	// pseudo header after regular header
	// server should reset stream with H3_MESSAGE_ERROR
	http3SenInvalidReqExpectStreamError(
		s,
		[]byte{
			0x01, 0x14, 0x00, 0x00, 0xD7, 0x50, 0x01, 0x61,
			0xC1, 0x23, 0x61, 0x62, 0x63, 0x01, 0x5A, 0x23,
			0x61, 0x62, 0x63, 0x01, 0x5A, 0xD1,
		},
		http3.ErrCodeMessageError)
}

func Http3DataBeforeHeadersTest(s *Http3Suite) {
	http3SendReqExpectConnError(s, []byte{0x00, 0x01, 0xEE}, http3.ErrCodeFrameUnexpected)
}

func Http3LongerDataThanContentLengthTest(s *Http3Suite) {
	// content-length is 4, but DATA frame has 5 bytes
	http3SendReqExpectConnError(
		s,
		[]byte{
			0x01, 0x0B, 0x00, 0x00, 0xD4, 0xD7, 0xC1, 0x50,
			0x01, 0x61, 0x54, 0x01, 0x34, 0x00, 0x05, 0x78,
			0x78, 0x78, 0x78, 0x78,
		},
		http3.ErrCodeGeneralProtocolError)
}

func Http3HalfClosedBeforeAllDataTest(s *Http3Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	Log(vpp.Vppctl("http tps no-zc h3 uri https://" + serverAddress))

	conn := H3ClientConnect(serverAddress)
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStream()
	AssertNil(err)
	// content-length is 5, but DATA frame has 4 bytes and then FIN
	_, err = stream.Write([]byte{
		0x01, 0x0B, 0x00, 0x00, 0xD4, 0xD7, 0xC1, 0x50,
		0x01, 0x61, 0x54, 0x01, 0x35, 0x00, 0x04, 0x78,
		0x78, 0x78, 0x78,
	})
	AssertNil(err)
	AssertNil(stream.Close())

	stream.SetReadDeadline(time.Now().Add(time.Second))
	_, err = stream.Read([]byte{0})
	AssertNotNil(err, "expected stream reset")
	Log(err)
	expectedErr := quic.StreamError{
		StreamID:  stream.StreamID(),
		ErrorCode: quic.StreamErrorCode(http3.ErrCodeRequestIncomplete),
		Remote:    true,
	}
	AssertMatchError(err, &expectedErr, "expected error code "+http3.ErrCodeRequestIncomplete.String())
}

func http3SendCtrlExpectConnError(s *Http3Suite, p []byte, expectedErrorCode http3.ErrCode) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	Log(vpp.Vppctl("http tps no-zc h3 uri https://" + serverAddress))

	conn := H3ClientConnect(serverAddress)
	stream, err := conn.OpenUniStream()
	AssertNil(err)
	stream.Write(append([]byte{0x00}, p[:]...))
	select {
	case <-conn.Context().Done():
		err := context.Cause(conn.Context())
		Log(err)
		expectedErr := quic.ApplicationError{
			ErrorCode: quic.ApplicationErrorCode(expectedErrorCode),
			Remote:    true,
		}
		AssertMatchError(err, &expectedErr, "expected connection error "+expectedErrorCode.String())
	case <-time.After(time.Second):
		AssertNotNil(nil, "timeout")
	}
}

func http3SendReqExpectConnError(s *Http3Suite, p []byte, expectedErrorCode http3.ErrCode) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	Log(vpp.Vppctl("http tps no-zc h3 uri https://" + serverAddress))

	conn := H3ClientConnect(serverAddress)
	stream, err := conn.OpenStream()
	AssertNil(err)
	stream.Write(p)
	select {
	case <-conn.Context().Done():
		err := context.Cause(conn.Context())
		Log(err)
		expectedErr := quic.ApplicationError{
			ErrorCode: quic.ApplicationErrorCode(expectedErrorCode),
			Remote:    true,
		}
		AssertMatchError(err, &expectedErr, "expected connection error "+expectedErrorCode.String())
	case <-time.After(time.Second):
		AssertNotNil(nil, "timeout")
	}
}

func Http3ReservedFrameTest(s *Http3Suite) {
	// frame type 0x06 is reserved (PING in h2)
	http3SendCtrlExpectConnError(s, []byte{0x06, 0x02, 0x00, 0x00}, http3.ErrCodeFrameUnexpected)
	/* test session cleanup */
	http3TestSessionCleanupServer(s)
}

func Http3DataFrameOnCtrlStreamTest(s *Http3Suite) {
	http3SendCtrlExpectConnError(s, []byte{0x01, 0x02, 0x0A, 0x0B}, http3.ErrCodeFrameUnexpected)
}

func Http3GoawayOnReqStreamTest(s *Http3Suite) {
	http3SendReqExpectConnError(s, []byte{0x07, 0x02, 0x7B, 0xBD}, http3.ErrCodeFrameUnexpected)
}

func Http3SecondSettingsFrameTest(s *Http3Suite) {
	http3SendCtrlExpectConnError(s, []byte{0x04, 0x00, 0x04, 0x00}, http3.ErrCodeFrameUnexpected)
}

func Http3ReservedSettingsTest(s *Http3Suite) {
	http3SendCtrlExpectConnError(s, []byte{0x04, 0x02, 0x04, 0x00}, http3.ErrCodeSettingsError)
}

func Http3MissingSettingsTest(s *Http3Suite) {
	http3SendCtrlExpectConnError(s, []byte{0x0D, 0x01, 0x04}, http3.ErrCodeMissingSettings)
}

func Http3QpackDecompressionFailedTest(s *Http3Suite) {
	http3SendReqExpectConnError(
		s,
		[]byte{
			0x01, 0x12, 0x00, 0x00, 0xd1, 0xd7, 0x50, 0x09,
			0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e,
			0x31, 0xc1, 0xff, 0x24,
		},
		http3.ErrCodeQPACKDecompressionFailed)
}

func Http3ClientOpenPushStreamTest(s *Http3Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	Log(vpp.Vppctl("http tps no-zc h3 uri https://" + serverAddress))

	conn := H3ClientConnect(serverAddress)
	stream, err := conn.OpenUniStream()
	AssertNil(err)
	stream.Write([]byte{0x01, 0x01})
	select {
	case <-conn.Context().Done():
		err := context.Cause(conn.Context())
		Log(err)
		expectedErr := quic.ApplicationError{
			ErrorCode: quic.ApplicationErrorCode(http3.ErrCodeStreamCreationError),
			Remote:    true,
		}
		AssertMatchError(err, &expectedErr, "expected connection error H3_STREAM_CREATION_ERROR")
	case <-time.After(time.Second):
		AssertNotNil(nil, "timeout")
	}
}

func Http3SecondCtrlStreamTest(s *Http3Suite) {
	http3SecondUniStreamExpectConnError(s, 0x00)
}

func Http3SecondQpackDecoderStreamTest(s *Http3Suite) {
	http3SecondUniStreamExpectConnError(s, 0x03)
}

func Http3SecondQpackEncoderStreamTest(s *Http3Suite) {
	http3SecondUniStreamExpectConnError(s, 0x02)
}

func http3SecondUniStreamExpectConnError(s *Http3Suite, streamType byte) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	Log(vpp.Vppctl("http tps no-zc h3 uri https://" + serverAddress))

	conn := H3ClientConnect(serverAddress)
	stream1, err := conn.OpenUniStream()
	AssertNil(err)
	_, err = stream1.Write([]byte{streamType})
	AssertNil(err)
	stream2, err := conn.OpenUniStream()
	AssertNil(err)
	_, err = stream2.Write([]byte{streamType})
	AssertNil(err)
	select {
	case <-conn.Context().Done():
		err := context.Cause(conn.Context())
		Log(err)
		expectedErr := quic.ApplicationError{
			ErrorCode: quic.ApplicationErrorCode(http3.ErrCodeStreamCreationError),
			Remote:    true,
		}
		AssertMatchError(err, &expectedErr, "expected connection error H3_STREAM_CREATION_ERROR")
	case <-time.After(time.Second):
		AssertNotNil(nil, "timeout")
	}
}

func Http3CtrlStreamClosedTest(s *Http3Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	Log(vpp.Vppctl("http tps no-zc h3 uri https://" + serverAddress))

	conn := H3ClientConnect(serverAddress)
	stream, err := conn.OpenUniStream()
	AssertNil(err)
	stream.Write([]byte{0x00})
	time.Sleep(500 * time.Millisecond)
	stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeInternalError))
	select {
	case <-conn.Context().Done():
		err := context.Cause(conn.Context())
		Log(err)
		expectedErr := quic.ApplicationError{
			ErrorCode: quic.ApplicationErrorCode(http3.ErrCodeClosedCriticalStream),
			Remote:    true,
		}
		AssertMatchError(err, &expectedErr, "expected connection error H3_CLOSED_CRITICAL_STREAM")
	case <-time.After(time.Second):
		AssertNotNil(nil, "timeout")
	}
}

func Http3TsFifoMemPressureMWTest(s *Http3Suite) {
	var httpConfig Stanza
	httpConfig.NewStanza("http").Append("first-segment-size 4m").Append("add-segment-size 4m").Close()
	s.CpusPerVppContainer = 2

	s.SetupTest(httpConfig)
	vpp := s.Containers.Vpp.VppInstance
	vpp.Container.Exec(false, "mkdir -p "+wwwRootPath)
	serverAddress := "https://" + s.VppAddr() + ":" + s.Ports.Port1
	resourceName := "/test_file_10M"
	url := serverAddress + resourceName

	fileName := wwwRootPath + resourceName
	Log(vpp.Container.Exec(false, "fallocate -l 10MB "+fileName))
	Log(vpp.Container.Exec(false, "ls -la "+fileName))
	Log(vpp.Vppctl("http static server http3 cache-size 128m www-root " + wwwRootPath + " uri " + serverAddress))

	s.Containers.Curl.ExtraRunningArgs = fmt.Sprintf("/usr/bin/slow_reader_h3.sh %s 1M 15", url)
	s.Containers.Curl.Run()
	Log(vpp.Vppctl("show session"))
	stdout, _ := s.Containers.Curl.GetOutput()
	Log(stdout)
}
