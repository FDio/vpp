package main

import (
	"context"
	"fmt"
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
		Http3MissingPseudoHeaderTest, Http3PseudoHeaderAfterRegularTest, Http3ReservedFrameTest,
		Http3DataFrameOnCtrlStreamTest, Http3GoawayOnReqStreamTest, Http3SecondSettingsFrameTest,
		Http3ReservedSettingsTest, Http3MissingSettingsTest, Http3SecondCtrlStreamTest, Http3CtrlStreamClosedTest,
		Http3QpackDecompressionFailedTest, Http3ClientOpenPushStreamTest, Http3DataBeforeHeadersTest,
		Http3StaticGetTest)
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
	Log(vpp.Vppctl("http tps no-zc h3 uri https://" + serverAddress + " fifo-size 1M"))

	args := fmt.Sprintf("-k --max-time 30 --noproxy '*' --http3-only --data-binary @/tmp/testFile https://%s/test_file_10M fifo-size 1M",
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

	uri := "https://" + serverAddress + "/httpTestFile"
	cmd := fmt.Sprintf("http client http3 streams %d repeat %d uri %s fifo-size 1M", 10, 20, uri)
	o := vpp.Vppctl(cmd)
	Log(o)
	AssertContains(o, "20 request(s)")
	AssertNotContains(o, "error")
	o = vpp.Vppctl("show http stats")
	Log(o)
	AssertContains(o, "1 connections established")
	AssertContains(o, "10 application streams opened")
	AssertContains(o, "10 application streams closed")
	AssertContains(o, "20 requests sent")
	AssertContains(o, "20 responses received")

	logPath := s.Containers.Nginx.GetHostWorkDir() + "/" + s.Containers.Nginx.Name
	logContents, err := exechelper.Output("cat " + logPath + "-access.log")
	AssertNil(err)
	AssertContains(string(logContents), "conn_reqs=20")
	logContents, err = exechelper.Output("cat " + logPath + "-error.log")
	AssertNil(err)
	AssertNotContains(string(logContents), "client closed connection while waiting for request")

	/* test session cleanup */
	udpCleanupDone := false
	quicCleanupDone := false
	httpCleanupDone := false
	for range 5 {
		o := vpp.Vppctl("show session verbose 2")
		if !strings.Contains(o, "[U]") {
			udpCleanupDone = true
		}
		if !strings.Contains(o, "[Q]") {
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
	Log(vpp.Vppctl("show session verbose 2"))
	AssertEqual(true, udpCleanupDone, "UDP session not cleaned up")
	AssertEqual(true, quicCleanupDone, "QUIC not cleaned up")
	AssertEqual(true, httpCleanupDone, "HTTP/3 not cleaned up")
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
	// metod pseudo header is missing
	// server should reset stream with H3_MESSAGE_ERROR
	http3SenInvalidReqExpectStreamError(
		s,
		[]byte{
			0x01, 0x0D, 0x00, 0x00, 0xD7, 0x50, 0x01, 0x61,
			0xC1, 0x23, 0x61, 0x62, 0x63, 0x01, 0x5A,
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
			0x01, 0x00, 0x00, 0x00, 0xd1, 0xd7, 0x50, 0x09,
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
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	Log(vpp.Vppctl("http tps no-zc h3 uri https://" + serverAddress))

	conn := H3ClientConnect(serverAddress)
	stream1, err := conn.OpenUniStream()
	AssertNil(err)
	stream1.Write([]byte{0x00})
	stream2, err := conn.OpenUniStream()
	AssertNil(err)
	stream2.Write([]byte{0x00})
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
