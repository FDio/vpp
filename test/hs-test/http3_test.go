package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	. "fd.io/hs-test/infra"
	"github.com/edwarnicke/exechelper"
	. "github.com/onsi/ginkgo/v2"
	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/http2/hpack"
)

func init() {
	RegisterH3Tests(Http3GetTest, Http3AltSvcCompoundListenerTest, Http3DownloadTest, Http3PostTest, Http3UploadTest, Http3ClientGetRepeatTest,
		Http3ClientGetMultiplexingTest, Http3PeerResetStream, Http3ClientRequestIncompleteTest,
		Http3RequestFinCompleteTest, Http3RequestFinErrorsTest,
		Http3MissingPseudoHeaderTest, Http3MissingSchemePseudoHeaderTest, Http3MissingPathPseudoHeaderTest,
		Http3MissingAuthorityPseudoHeaderTest, Http3ConnectWithSchemePathPseudoHeadersTest,
		Http3PseudoHeaderAfterRegularTest, Http3ReservedFrameTest, Http3DataFrameOnCtrlStreamTest,
		Http3GoawayOnReqStreamTest, Http3UnknownFrameOnReqStreamTest, Http3GoawayInvalidLengthTest, Http3GoawayEmptyTest,
		Http3GoawayTruncatedIdTest, Http3GoawayExtraBytesTest, Http3SecondSettingsFrameTest,
		Http3PushControlFrameErrorsTest, Http3MaxPushIdTest, Http3ClientPushControlFramesTest,
		Http3ReservedSettingsTest, Http3MissingSettingsTest, Http3SecondCtrlStreamTest,
		Http3SecondQpackDecoderStreamTest, Http3SecondQpackEncoderStreamTest, Http3CtrlStreamClosedTest,
		Http3FragmentedStreamTypeTest, Http3IncompleteStreamTypeCloseTest,
		Http3QpackDecompressionFailedTest, Http3ClientOpenPushStreamTest, Http3DataBeforeHeadersTest,
		Http3LongerDataThanContentLengthTest, Http3HalfClosedBeforeAllDataTest, Http3StaticGetTest,
		Http3MaxHeaderListSizeTest, Http3ServerHeadersFrameTooLargeTest, Http3ClientHeadersFrameTooLargeTest,
		Http3Early431UploadTest, Http3Early431DecodedUploadTest, Http3Early501UploadTest,
		Http3Early501CompletedRequestTest, Http3EarlyApplicationUploadTest,
		Http3UnsupportedMethodTest, Http3MalformedMethodTest, Http3SupportedMethodsTest,
		Http3EmptyAuthorityTest,
		Http3PseudoHeadersTest, Http3ResponsePseudoHeadersTest,
		Http3EarlyUnsupportedMethodUploadTest, Http3EarlyUnsupportedMethodCompletedTest,
		Http3EarlyUnsupportedSchemeUploadTest, Http3EarlyUnsupportedSchemeCompletedTest,
		Http3ClientOversizedBodyTest,
		Http3ServerMemLeakTest, Http3ClientMemLeakTest)
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

func Http3AltSvcCompoundListenerTest(s *Http3Suite) {
	vpp := s.Containers.Vpp.VppInstance
	uri := "https://" + net.JoinHostPort(s.VppAddr(), s.Ports.Port1)
	o := vpp.Vppctl("http cli server http3-enabled listener add uri " + uri)
	Log(o)
	AssertEmpty(strings.TrimSpace(o))

	Log(vpp.Vppctl("show session verbose 2"))

	// The compound listener advertises its own port without an explicit Alt-Svc port.
	for _, protoMajor := range []int{1, 2} {
		client := NewHttpClient(defaultHttpTimeout, protoMajor == 2)
		defer client.CloseIdleConnections()
		resp, err := client.Get(uri + "/show/version")
		AssertNil(err, fmt.Sprint(err))
		defer resp.Body.Close()
		Log(DumpHttpResp(resp, false))

		AssertHttpStatus(resp, http.StatusOK)
		AssertEqual(protoMajor, resp.ProtoMajor)
		AssertHttpHeaderWithValue(resp, "Alt-Svc", fmt.Sprintf(`h3=":%s"`, s.Ports.Port1))
	}

	// Verify that HTTP/3 is reachable on the advertised UDP port.
	args := fmt.Sprintf("-k --max-time 10 --noproxy '*' --http3-only %s/show/version", uri)
	_, log := RunCurlContainer(s.Containers.Curl, args)
	AssertContains(log, "HTTP/3 200")
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

// Withhold ACKs and the solicited RESET_STREAM until STOP_SENDING is retransmitted.
// This also keeps the response unacknowledged while request cancellation completes.
type http3EarlyPacketConn struct {
	net.PacketConn
	mu      sync.Mutex
	retry   bool
	stops   []quic.StreamErrorCode
	dropped int
	changed chan struct{}
}

type http3EarlyRecorder struct{ conn *http3EarlyPacketConn }

func (c *http3EarlyPacketConn) AddProducer() qlogwriter.Recorder {
	return http3EarlyRecorder{conn: c}
}

func (c *http3EarlyPacketConn) SupportsSchemas(string) bool { return true }
func (r http3EarlyRecorder) Close() error                   { return nil }

func (r http3EarlyRecorder) RecordEvent(event qlogwriter.Event) {
	packet, ok := event.(qlog.PacketReceived)
	if !ok {
		return
	}
	c := r.conn
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, frame := range packet.Frames {
		if stop, ok := frame.Frame.(*qlog.StopSendingFrame); ok && stop.StreamID == 0 {
			c.stops = append(c.stops, quic.StreamErrorCode(stop.ErrorCode))
			select {
			case c.changed <- struct{}{}:
			default:
			}
		}
	}
}

func (c *http3EarlyPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	drop := c.retry && len(c.stops) == 1
	if drop {
		c.dropped++
	}
	c.mu.Unlock()
	if drop {
		return len(p), nil
	}
	return c.PacketConn.WriteTo(p, addr)
}

func http3EarlyHeaders(fields []qpack.HeaderField) []byte {
	var headers bytes.Buffer
	encoder := qpack.NewEncoder(&headers)
	if len(fields) == 0 {
		headers.Write([]byte{0x00, 0x00})
	}
	for _, field := range fields {
		AssertNil(encoder.WriteField(field))
	}
	frame := quicvarint.Append(nil, 0x01)
	frame = quicvarint.Append(frame, uint64(headers.Len()))
	return append(frame, headers.Bytes()...)
}

func http3ReadEarlyResponse(stream *quic.Stream, status string) []byte {
	reader := quicvarint.NewReader(stream)
	frameType, err := quicvarint.Read(reader)
	AssertNil(err)
	AssertEqual(uint64(0x01), frameType)
	length, err := quicvarint.Read(reader)
	AssertNil(err)
	AssertEqual(true, length < 4096)
	headers := make([]byte, int(length))
	_, err = io.ReadFull(stream, headers)
	AssertNil(err)
	decode := qpack.NewDecoder().Decode(headers)
	actual := ""
	for {
		field, err := decode()
		if err == io.EOF {
			break
		}
		AssertNil(err)
		if field.Name == ":status" {
			actual = field.Value
		}
	}
	AssertEqual(status, actual)
	body, err := io.ReadAll(stream)
	AssertNil(err, "response must finish with FIN, without RESET_STREAM")
	return body
}

func http3EarlyResponseTest(s *Http3Suite, mode string, complete bool, retry bool) {
	vpp := s.Containers.Vpp.VppInstance
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Port1)
	Log(vpp.Vppctl("http tps fifo-size 8k no-zc h3 uri https://" + address))
	cleanup := quicCleanupCheck(5*time.Second, vpp)
	socket, err := net.ListenPacket("udp4", net.JoinHostPort(s.HostAddr(), "0"))
	AssertNil(err)
	defer socket.Close()
	packets := &http3EarlyPacketConn{PacketConn: socket, retry: retry, changed: make(chan struct{}, 1)}
	transport := quic.Transport{Conn: packets}
	defer transport.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	remote, err := net.ResolveUDPAddr("udp4", address)
	AssertNil(err)
	conn, err := transport.Dial(ctx, remote,
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}},
		&quic.Config{DisablePathMTUDiscovery: true,
			InitialStreamReceiveWindow: 4096, MaxStreamReceiveWindow: 4096,
			Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return packets }})
	AssertNil(err)
	defer conn.CloseWithError(0, "")
	control, err := conn.OpenUniStream()
	AssertNil(err)
	_, err = control.Write([]byte{0x00, 0x04, 0x00})
	AssertNil(err)
	stream, err := conn.OpenStream()
	AssertNil(err)
	deadline, _ := ctx.Deadline()
	AssertNil(stream.SetDeadline(deadline))
	fields := []qpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: address}, {Name: ":path", Value: "/test_file_64"}}
	healthyRequest := http3EarlyHeaders(fields)
	status := "431"
	if mode == "501" {
		status = "501"
		fields[0].Value = "CONNECT"
		fields = append(fields, qpack.HeaderField{Name: ":protocol", Value: "unsupported"})
	} else if mode == "method" || mode == "scheme" {
		if mode == "scheme" {
			status = "421"
			fields[1].Value = "web+demo"
		} else {
			status = "501"
			fields[0].Value = "X-EXTENSION"
		}
		if !complete {
			fields = append(fields, qpack.HeaderField{Name: "content-length", Value: "2097152"})
		}
	} else if mode == "decoded" {
		fields = append(fields, qpack.HeaderField{Name: "x-test", Value: strings.Repeat("A", 8192)})
	} else if mode == "application" {
		status = "200"
		fields[3].Value = "/test_file_1M"
		fields = append(fields, qpack.HeaderField{Name: "content-length", Value: "2097152"})
	}
	request := http3EarlyHeaders(fields)
	if mode == "encoded" {
		request = quicvarint.Append(nil, 0x01)
		request = quicvarint.Append(request, 512<<10+1)
	} else if mode == "application" || ((mode == "method" || mode == "scheme") && !complete) {
		request = quicvarint.Append(request, 0x00)
		request = quicvarint.Append(request, 2<<20)
	}
	_, err = stream.Write(request)
	AssertNil(err)
	if complete {
		AssertNil(stream.Close())
	} else {
		finished := make(chan error, 1)
		go func() {
			// The upload exceeds the transport receive window and must be interrupted.
			_, err := stream.Write(make([]byte, 2<<20))
			finished <- err
		}()
		var writeErr error
		select {
		case writeErr = <-finished:
		case <-ctx.Done():
			AssertNil(ctx.Err(), "upload was not cancelled")
		}
		AssertMatchError(writeErr, &quic.StreamError{StreamID: stream.StreamID(),
			ErrorCode: quic.StreamErrorCode(http3.ErrCodeNoError), Remote: true})
	}
	// Exercise another stream before reading the early response.
	healthy, err := conn.OpenStream()
	AssertNil(err)
	AssertNil(healthy.SetDeadline(deadline))
	_, err = healthy.Write(healthyRequest)
	AssertNil(err)
	AssertNil(healthy.Close())
	body := http3ReadEarlyResponse(stream, status)
	if mode == "application" {
		// The response cannot fit in the peer's receive window before we start reading.
		// Verify all DATA bytes survive the request's solicited RESET_STREAM.
		reader := quicvarint.NewReader(bytes.NewReader(body))
		var received int64
		for {
			frameType, err := quicvarint.Read(reader)
			if err == io.EOF {
				break
			}
			AssertNil(err)
			AssertEqual(uint64(0x00), frameType)
			length, err := quicvarint.Read(reader)
			AssertNil(err)
			n, err := io.CopyN(io.Discard, reader, int64(length))
			AssertNil(err)
			received += n
		}
		AssertEqual(int64(1<<20), received)
	} else {
		AssertEmpty(body)
	}
	AssertNotEmpty(http3ReadEarlyResponse(healthy, "200"))
	if retry {
		for {
			packets.mu.Lock()
			done := len(packets.stops) >= 2
			packets.mu.Unlock()
			if done {
				break
			}
			select {
			case <-packets.changed:
			case <-ctx.Done():
				AssertNil(ctx.Err(), "STOP_SENDING was not retransmitted")
			}
		}
	}
	packets.mu.Lock()
	stops := append([]quic.StreamErrorCode(nil), packets.stops...)
	dropped := packets.dropped
	packets.mu.Unlock()
	for _, code := range stops {
		AssertEqual(quic.StreamErrorCode(http3.ErrCodeNoError), code)
	}
	if retry {
		AssertNotEqual(0, dropped, "expected lost ACK / RESET_STREAM packets")
	}
	AssertNil(context.Cause(conn.Context()))
	AssertContains(vpp.Vppctl("show http stats"), "2 responses sent")
	AssertNil(conn.CloseWithError(0, ""))
	cleanup()
}

func Http3Early431UploadTest(s *Http3Suite) {
	http3EarlyResponseTest(s, "encoded", false, true)
}

func Http3Early431DecodedUploadTest(s *Http3Suite) {
	http3EarlyResponseTest(s, "decoded", false, false)
}

func Http3Early501UploadTest(s *Http3Suite) {
	http3EarlyResponseTest(s, "501", false, false)
}

func Http3Early501CompletedRequestTest(s *Http3Suite) {
	http3EarlyResponseTest(s, "501", true, false)
}

func Http3EarlyApplicationUploadTest(s *Http3Suite) {
	http3EarlyResponseTest(s, "application", false, false)
}

func Http3EarlyUnsupportedMethodUploadTest(s *Http3Suite) {
	http3EarlyResponseTest(s, "method", false, true)
}

func Http3EarlyUnsupportedMethodCompletedTest(s *Http3Suite) {
	http3EarlyResponseTest(s, "method", true, false)
}

func Http3EarlyUnsupportedSchemeUploadTest(s *Http3Suite) {
	http3EarlyResponseTest(s, "scheme", false, true)
}

func Http3EarlyUnsupportedSchemeCompletedTest(s *Http3Suite) {
	http3EarlyResponseTest(s, "scheme", true, false)
}

func Http3UnsupportedMethodTest(s *Http3Suite) {
	vpp := s.Containers.Vpp.VppInstance
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Port1)
	Log(vpp.Vppctl("http tps no-zc h3 uri https://" + address))
	conn := H3ClientConnect(address)
	defer conn.CloseWithError(0, "")
	control, err := conn.OpenUniStream()
	AssertNil(err)
	_, err = control.Write([]byte{0x00, 0x04, 0x00})
	AssertNil(err)
	for _, method := range []string{"X-EXTENSION", "HEAD", "DELETE", "PATCH", "OPTIONS", "CONNECT-UDP", "get", "!#$%&'*+-.^_`|~0123456789"} {
		By("valid unsupported method " + method)
		stream, err := conn.OpenStream()
		AssertNil(err)
		AssertNil(stream.SetDeadline(time.Now().Add(3 * time.Second)))
		_, err = stream.Write(http3EarlyHeaders([]qpack.HeaderField{
			{Name: ":method", Value: method}, {Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: address}, {Name: ":path", Value: "/test_file_64"},
			{Name: "content-length", Value: "0"},
		}))
		AssertNil(err)
		AssertNil(stream.Close())
		AssertEmpty(http3ReadEarlyResponse(stream, "501"))
		AssertNil(context.Cause(conn.Context()))
	}
}

func Http3MalformedMethodTest(s *Http3Suite) {
	vpp := s.Containers.Vpp.VppInstance
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Port1)
	Log(vpp.Vppctl("http tps no-zc h3 uri https://" + address))
	conn := H3ClientConnect(address)
	defer conn.CloseWithError(0, "")
	control, err := conn.OpenUniStream()
	AssertNil(err)
	_, err = control.Write([]byte{0x00, 0x04, 0x00})
	AssertNil(err)
	base := []qpack.HeaderField{{Name: ":method", Value: "X-EXTENSION"},
		{Name: ":scheme", Value: "https"}, {Name: ":authority", Value: address},
		{Name: ":path", Value: "/test_file_64"}}
	type malformedRequest struct {
		name   string
		fields []qpack.HeaderField
	}
	var tests []malformedRequest
	for _, method := range []string{"", "BAD METHOD", " GET", "GET ", "G\tET", "G\rET", "G\nET", "G\x00ET", "G\x7fET", "G\x80ET", "G/ET", "G:ET", "G(ET"} {
		fields := append([]qpack.HeaderField(nil), base...)
		fields[0].Value = method
		tests = append(tests, malformedRequest{name: fmt.Sprintf("invalid method %q", method), fields: fields})
	}
	for i, field := range base {
		fields := append([]qpack.HeaderField(nil), base[:i]...)
		fields = append(fields, base[i+1:]...)
		tests = append(tests, malformedRequest{name: "missing " + field.Name, fields: fields})
	}
	for _, field := range []qpack.HeaderField{
		{Name: ":method", Value: "GET"}, {Name: ":protocol", Value: "websocket"},
		{Name: ":status", Value: "200"}, {Name: "connection", Value: "close"},
		{Name: "content-length", Value: "invalid"}, {Name: "content-length", Value: "18446744073709551616"},
		{Name: "Uppercase", Value: "invalid"},
		{Name: "", Value: "invalid"},
	} {
		fields := append([]qpack.HeaderField(nil), base...)
		fields = append(fields, field)
		tests = append(tests, malformedRequest{name: "invalid field " + field.Name, fields: fields})
	}
	fields := append([]qpack.HeaderField(nil), base[1:]...)
	fields = append(fields, qpack.HeaderField{Name: "x-test", Value: "value"}, base[0])
	tests = append(tests, malformedRequest{name: "method after regular field", fields: fields})
	for _, authority := range []string{"", "a", "missing-port"} {
		fields := append([]qpack.HeaderField(nil), base...)
		fields[0].Value = "CONNECT-UDP"
		fields[2].Value = authority
		tests = append(tests, malformedRequest{name: "disabled CONNECT-UDP with invalid authority", fields: fields})
	}
	for _, test := range tests {
		By(test.name)
		stream, err := conn.OpenStream()
		AssertNil(err)
		AssertNil(stream.SetDeadline(time.Now().Add(3 * time.Second)))
		_, err = stream.Write(http3EarlyHeaders(test.fields))
		AssertNil(err)
		healthy, err := conn.OpenStream()
		AssertNil(err)
		AssertNil(healthy.SetDeadline(time.Now().Add(3 * time.Second)))
		fields := append([]qpack.HeaderField(nil), base...)
		fields[0].Value = "GET"
		_, err = healthy.Write(http3EarlyHeaders(fields))
		AssertNil(err)
		AssertNil(healthy.Close())
		_, err = stream.Read([]byte{0})
		AssertMatchError(err, &quic.StreamError{StreamID: stream.StreamID(),
			ErrorCode: quic.StreamErrorCode(http3.ErrCodeMessageError), Remote: true})
		AssertNotEmpty(http3ReadEarlyResponse(healthy, "200"))
		AssertNil(context.Cause(conn.Context()), "malformed request must only reset its stream")
	}
}

func Http3EmptyAuthorityTest(s *Http3Suite) {
	vpp := s.Containers.Vpp.VppInstance
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Port1)
	Log(vpp.Vppctl("http tps no-zc h3 uri https://" + address))
	conn := H3ClientConnect(address)
	defer conn.CloseWithError(0, "")
	control, err := conn.OpenUniStream()
	AssertNil(err)
	_, err = control.Write([]byte{0x00, 0x04, 0x00})
	AssertNil(err)
	for _, method := range []string{"GET", "POST", "PUT", "X-EXTENSION", "CONNECT", "CONNECT-UDP", "extended CONNECT"} {
		fields := []qpack.HeaderField{{Name: ":method", Value: method}}
		if method != "CONNECT" {
			fields = append(fields, qpack.HeaderField{Name: ":scheme", Value: "https"},
				qpack.HeaderField{Name: ":path", Value: "/test_file_64"})
		}
		if method == "extended CONNECT" {
			fields[0].Value = "CONNECT"
			fields = append(fields, qpack.HeaderField{Name: ":protocol", Value: "unsupported"})
		}
		for _, authority := range []struct {
			name  string
			bytes []byte
		}{{"indexed", []byte{0xc0}}, {"literal", []byte{0x50, 0x00}}, {"Huffman", []byte{0x50, 0x80}}} {
			By(method + " with " + authority.name + " empty authority")
			var headers bytes.Buffer
			encoder := qpack.NewEncoder(&headers)
			for _, field := range fields {
				AssertNil(encoder.WriteField(field))
			}
			headers.Write(authority.bytes)
			frame := quicvarint.Append([]byte{0x01}, uint64(headers.Len()))
			frame = append(frame, headers.Bytes()...)
			stream, err := conn.OpenStream()
			AssertNil(err)
			AssertNil(stream.SetDeadline(time.Now().Add(3 * time.Second)))
			_, err = stream.Write(frame)
			AssertNil(err)

			healthy, err := conn.OpenStream()
			AssertNil(err)
			AssertNil(healthy.SetDeadline(time.Now().Add(3 * time.Second)))
			_, err = healthy.Write(http3EarlyHeaders([]qpack.HeaderField{
				{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"},
				{Name: ":authority", Value: address}, {Name: ":path", Value: "/test_file_64"},
				{Name: "cookie", Value: ""}, {Name: "user-agent", Value: ""},
			}))
			AssertNil(err)
			AssertNil(healthy.Close())
			_, err = stream.Read([]byte{0})
			AssertMatchError(err, &quic.StreamError{StreamID: stream.StreamID(),
				ErrorCode: quic.StreamErrorCode(http3.ErrCodeMessageError), Remote: true})
			AssertNotEmpty(http3ReadEarlyResponse(healthy, "200"))
			AssertNil(context.Cause(conn.Context()), "empty authority must only reset its stream")
		}
	}
}

func Http3SupportedMethodsTest(s *Http3Suite) {
	vpp := s.Containers.Vpp.VppInstance
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Port1)
	Log(vpp.Vppctl("http cli server http3-enabled listener add uri https://" + address))
	transport := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer transport.Close()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	for _, method := range []string{"GET", "POST", "PUT"} {
		request, err := http.NewRequest(method, "https://"+address+"/echo", strings.NewReader("method body"))
		AssertNil(err)
		response, err := client.Do(request)
		AssertNil(err)
		AssertHttpStatus(response, http.StatusOK)
		body, err := io.ReadAll(response.Body)
		AssertNil(err)
		AssertNil(response.Body.Close())
		AssertEqual("method body", string(body))
	}
	request, err := http.NewRequest("PUT", "https://"+address+"/show/version", strings.NewReader("method body"))
	AssertNil(err)
	response, err := client.Do(request)
	AssertNil(err)
	defer response.Body.Close()
	AssertHttpStatus(response, http.StatusMethodNotAllowed)
	AssertHttpHeaderWithValue(response, "Allow", "GET")
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

func Http3ServerHeadersFrameTooLargeTest(s *Http3Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	Log(vpp.Vppctl("http tps no-zc h3 uri https://" + serverAddress))

	conn := H3ClientConnect(serverAddress)
	defer conn.CloseWithError(0, "")
	control, err := conn.OpenUniStream()
	AssertNil(err)
	_, err = control.Write([]byte{0x00, 0x04, 0x00})
	AssertNil(err)

	for _, length := range []uint64{512<<10 + 1, 1<<32 + 1, 1<<62 - 1} {
		for _, payloadLen := range []int{0, 1} {
			By(fmt.Sprintf("rejecting request HEADERS length %d with %d payload bytes", length, payloadLen))
			stream, err := conn.OpenStream()
			AssertNil(err)
			AssertNil(stream.SetDeadline(time.Now().Add(3 * time.Second)))
			frame := quicvarint.Append(nil, 0x01)
			frame = quicvarint.Append(frame, length)
			frame = append(frame, make([]byte, payloadLen)...)
			// Keep the send side open: rejection must not depend on the rest of the payload or FIN.
			_, err = stream.Write(frame)
			AssertNil(err)

			reader := quicvarint.NewReader(stream)
			frameType, err := quicvarint.Read(reader)
			AssertNil(err, "expected an immediate HTTP error response")
			AssertEqual(uint64(0x01), frameType)
			responseLen, err := quicvarint.Read(reader)
			AssertNil(err)
			AssertEqual(true, responseLen < 4096, "error response must be small")
			response := make([]byte, int(responseLen))
			_, err = io.ReadFull(stream, response)
			AssertNil(err)
			decode := qpack.NewDecoder().Decode(response)
			status := ""
			for {
				field, err := decode()
				if err == io.EOF {
					break
				}
				AssertNil(err)
				if field.Name == ":status" {
					status = field.Value
				}
			}
			AssertEqual("431", status)
			_, err = stream.Read([]byte{0})
			AssertEqual(io.EOF, err, "error response must end with FIN")
			AssertNil(context.Cause(conn.Context()), "oversized request must not close the connection")
			stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		}
	}
}

func Http3ClientHeadersFrameTooLargeTest(s *Http3Suite) {
	cert, err := tls.LoadX509KeyPair("resources/cert/localhost.crt", "resources/cert/localhost.key")
	AssertNil(err)
	serverAddress := s.HostAddr() + ":" + s.Ports.Port1
	listener, err := quic.ListenAddr(serverAddress,
		&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}, nil)
	AssertNil(err)
	defer listener.Close()

	for _, length := range []uint64{512<<10 + 1, 1<<32 + 1, 1<<62 - 1} {
		for _, payloadLen := range []int{0, 1} {
			By(fmt.Sprintf("rejecting response HEADERS length %d with %d payload bytes", length, payloadLen))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				conn, err := listener.Accept(ctx)
				AssertNil(err)
				defer conn.CloseWithError(0, "")
				control, err := conn.OpenUniStream()
				AssertNil(err)
				_, err = control.Write([]byte{0x00, 0x04, 0x00})
				AssertNil(err)
				stream, err := conn.AcceptStream(ctx)
				AssertNil(err)
				deadline, _ := ctx.Deadline()
				AssertNil(stream.SetDeadline(deadline))
				reader := quicvarint.NewReader(stream)
				frameType, err := quicvarint.Read(reader)
				AssertNil(err)
				AssertEqual(uint64(0x01), frameType)
				requestLen, err := quicvarint.Read(reader)
				AssertNil(err)
				_, err = io.CopyN(io.Discard, stream, int64(requestLen))
				AssertNil(err)

				frame := quicvarint.Append(nil, 0x01)
				frame = quicvarint.Append(frame, length)
				frame = append(frame, make([]byte, payloadLen)...)
				_, err = stream.Write(frame)
				AssertNil(err)
				select {
				case <-conn.Context().Done():
					expectedErr := quic.ApplicationError{
						ErrorCode: quic.ApplicationErrorCode(http3.ErrCodeExcessiveLoad),
						Remote:    true,
					}
					AssertMatchError(context.Cause(conn.Context()), &expectedErr)
				case <-ctx.Done():
					Fail("client did not reject oversized response HEADERS")
				}
			}()

			o := s.Containers.Vpp.VppInstance.Vppctl("http client http3 timeout 5 uri https://" + serverAddress + "/")
			Log(o)
			AssertContains(o, "transport closed")
			<-done
		}
	}
}

func Http3ClientOversizedBodyTest(s *Http3Suite) {
	cert, err := tls.LoadX509KeyPair("resources/cert/localhost.crt", "resources/cert/localhost.key")
	AssertNil(err)
	serverAddress := s.HostAddr() + ":" + s.Ports.Port1
	listener, err := quic.ListenAddr(serverAddress,
		&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}},
		&quic.Config{KeepAlivePeriod: 100 * time.Millisecond})
	AssertNil(err)
	defer listener.Close()

	for _, bodies := range [][][]byte{{[]byte("abcde")}, {[]byte("ab"), []byte("cde")}} {
		By(fmt.Sprintf("oversized response in %d DATA frames", len(bodies)))
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		release := make(chan struct{})
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(done)
			conn, err := listener.Accept(ctx)
			AssertNil(err)
			defer conn.CloseWithError(0, "")
			control, err := conn.OpenUniStream()
			AssertNil(err)
			_, err = control.Write([]byte{0x00, 0x04, 0x00})
			AssertNil(err)
			stream, err := conn.AcceptStream(ctx)
			AssertNil(err)
			deadline, _ := ctx.Deadline()
			AssertNil(stream.SetDeadline(deadline))
			reader := quicvarint.NewReader(stream)
			frameType, err := quicvarint.Read(reader)
			AssertNil(err)
			AssertEqual(uint64(0x01), frameType)
			requestLen, err := quicvarint.Read(reader)
			AssertNil(err)
			_, err = io.CopyN(io.Discard, stream, int64(requestLen))
			AssertNil(err)

			var headers bytes.Buffer
			encoder := qpack.NewEncoder(&headers)
			AssertNil(encoder.WriteField(qpack.HeaderField{Name: ":status", Value: "200"}))
			AssertNil(encoder.WriteField(qpack.HeaderField{Name: "content-length", Value: "4"}))
			AssertNil(encoder.Close())
			response := http3FinFrame(0x01, headers.Bytes())
			for _, body := range bodies {
				response = append(response, http3FinFrame(0x00, body)...)
			}
			_, err = stream.Write(response)
			AssertNil(err)

			// Keep the connection open until the CLI returns: closing it here
			// would notify the parent request and hide a missing stream reset.
			select {
			case <-release:
			case <-ctx.Done():
				Fail("client did not finish after the oversized response")
			}
		}()

		output := s.Containers.Vpp.VppInstance.Vppctl("http client http3 timeout 3 uri https://" + serverAddress + "/")
		close(release)
		<-done
		Log(output)
		AssertContains(output, "transport closed")
		AssertNotContains(output, "timeout")
	}
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

// http3ResetPacketConn creates a packet-number gap before the invalid request.
// Subsequent client packets are suppressed so they cannot flush stranded reset.
type http3ResetPacketConn struct {
	net.PacketConn
	mu              sync.Mutex
	sent            []qlog.PacketSent
	serverPending   map[qlog.PacketNumber]bool
	settingsPackets map[qlog.PacketNumber]bool
	settingsAcked   bool
	handshakeDone   bool
	armed           bool
	primerDropped   bool
	requestSent     bool
	requestPacket   qlog.PacketNumber
	requestAcked    bool
	changed         chan struct{}
}

type http3ResetRecorder struct{ conn *http3ResetPacketConn }

func (c *http3ResetPacketConn) AddProducer() qlogwriter.Recorder {
	return http3ResetRecorder{conn: c}
}

func (c *http3ResetPacketConn) SupportsSchemas(string) bool { return true }
func (r http3ResetRecorder) Close() error                   { return nil }

func (c *http3ResetPacketConn) notify() {
	select {
	case c.changed <- struct{}{}:
	default:
	}
}

func (r http3ResetRecorder) RecordEvent(event qlogwriter.Event) {
	c := r.conn
	c.mu.Lock()
	defer c.mu.Unlock()
	switch packet := event.(type) {
	case qlog.PacketSent:
		c.sent = append(c.sent, packet)
		if packet.Header.PacketType == qlog.PacketType1RTT {
			for _, frame := range packet.Frames {
				if stream, ok := frame.Frame.(*qlog.StreamFrame); ok {
					if stream.StreamID == 2 && stream.Offset == 0 {
						c.settingsPackets[packet.Header.PacketNumber] = true
					}
				}
			}
		}
	case qlog.PacketReceived:
		if packet.Header.PacketType != qlog.PacketType1RTT {
			return
		}
		for _, frame := range packet.Frames {
			if ack, ok := frame.Frame.(*qlog.AckFrame); ok {
				if c.requestSent && ack.AcksPacket(c.requestPacket) {
					c.requestAcked = true
				}
				for pn := range c.settingsPackets {
					if ack.AcksPacket(pn) {
						c.settingsAcked = true
					}
				}
			} else {
				if _, ok := frame.Frame.(*qlog.HandshakeDoneFrame); ok {
					c.handshakeDone = true
				}
				c.serverPending[packet.Header.PacketNumber] = true
			}
		}
	}
	c.notify()
}

func (c *http3ResetPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	length, count := 0, 0
	request, primer := false, false
	var requestPacket qlog.PacketNumber
	// qlog emits one event per QUIC packet before handing its datagram to WriteTo
	for length < len(p) && count < len(c.sent) {
		packet := c.sent[count]
		length += packet.Raw.Length
		count++
		if packet.Header.PacketType != qlog.PacketType1RTT {
			continue
		}
		for _, frame := range packet.Frames {
			switch f := frame.Frame.(type) {
			case *qlog.StreamFrame:
				if f.StreamID == 0 {
					request = true
					requestPacket = packet.Header.PacketNumber
				}
				primer = primer || (f.StreamID == 2 && f.Offset+f.Length > 3)
			case *qlog.AckFrame:
				if !c.armed {
					for pn := range c.serverPending {
						if f.AcksPacket(pn) {
							delete(c.serverPending, pn)
						}
					}
				}
			}
		}
	}
	if length != len(p) {
		return 0, fmt.Errorf("QUIC packet trace length %d does not match datagram length %d", length, len(p))
	}
	c.sent = c.sent[count:]
	if c.armed && (!request || c.requestSent) {
		c.primerDropped = c.primerDropped || primer
		c.notify()
		return len(p), nil
	}
	if request {
		c.requestSent = true
		c.requestPacket = requestPacket
	}
	n, err := c.PacketConn.WriteTo(p, addr)
	c.notify()
	return n, err
}

func (c *http3ResetPacketConn) wait(ctx context.Context, ready func() bool) error {
	for {
		c.mu.Lock()
		done := ready()
		c.mu.Unlock()
		if done {
			return nil
		}
		select {
		case <-c.changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func http3SenInvalidReqExpectStreamError(s *Http3Suite, p []byte, expectedErrorCode http3.ErrCode) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	Log(vpp.Vppctl("http tps no-zc h3 uri https://" + serverAddress))

	socket, err := net.ListenPacket("udp4", s.HostAddr()+":0")
	AssertNil(err)
	defer socket.Close()
	packets := &http3ResetPacketConn{
		PacketConn:      socket,
		serverPending:   make(map[qlog.PacketNumber]bool),
		settingsPackets: make(map[qlog.PacketNumber]bool),
		changed:         make(chan struct{}, 1),
	}
	transport := quic.Transport{Conn: packets}
	defer transport.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	address, err := net.ResolveUDPAddr("udp4", serverAddress)
	AssertNil(err)
	conn, err := transport.Dial(ctx, address,
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}, SessionTicketsDisabled: true},
		&quic.Config{
			DisablePathMTUDiscovery: true,
			Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
				return packets
			},
		})
	AssertNil(err)
	defer conn.CloseWithError(0, "")
	control, err := conn.OpenUniStream()
	AssertNil(err)
	// open control stream and send empty SETTINGS frame
	_, err = control.Write([]byte{0x00, 0x04, 0x00})
	AssertNil(err)
	serverControl, err := conn.AcceptUniStream(ctx)
	AssertNil(err)
	deadline, _ := ctx.Deadline()
	AssertNil(serverControl.SetReadDeadline(deadline))
	reader := quicvarint.NewReader(serverControl)
	streamType, err := quicvarint.Read(reader)
	AssertNil(err)
	AssertEqual(uint64(0x00), streamType)
	frameType, err := quicvarint.Read(reader)
	AssertNil(err)
	AssertEqual(uint64(0x04), frameType)
	length, err := quicvarint.Read(reader)
	AssertNil(err)
	_, err = io.CopyN(io.Discard, serverControl, int64(length))
	AssertNil(err)

	// drain handshake and SETTINGS before introducing the packet gap
	AssertNil(packets.wait(ctx, func() bool {
		return packets.handshakeDone && packets.settingsAcked && len(packets.serverPending) == 0
	}), "handshake and SETTINGS must be acknowledged")
	packets.mu.Lock()
	packets.armed = true
	packets.mu.Unlock()
	// empty unknown control frame
	_, err = control.Write([]byte{0x21, 0x00})
	AssertNil(err)
	AssertNil(packets.wait(ctx, func() bool { return packets.primerDropped }), "expected packet gap before request")
	stream, err := conn.OpenStream()
	AssertNil(err)
	AssertNil(stream.SetDeadline(deadline))
	_, err = stream.Write(p)
	AssertNil(err)
	AssertNil(packets.wait(ctx, func() bool { return packets.requestAcked }), "request must be acknowledged")
	_, err = stream.Read([]byte{0})
	AssertNotNil(err, "expected stream reset")
	Log(err)
	expectedErr := quic.StreamError{
		StreamID:  stream.StreamID(),
		ErrorCode: quic.StreamErrorCode(expectedErrorCode),
		Remote:    true,
	}
	AssertMatchError(err, &expectedErr, "expected error code "+expectedErrorCode.String())
	select {
	case <-stream.Context().Done():
		AssertMatchError(context.Cause(stream.Context()), &expectedErr, "expected STOP_SENDING")
	case <-ctx.Done():
		Fail("expected STOP_SENDING")
	}
	AssertNil(context.Cause(conn.Context()), "stream reset must not close the connection")
}

func Http3ClientRequestIncompleteTest(s *Http3Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	Log(vpp.Vppctl("http tps no-zc h3 uri https://" + serverAddress))

	conn := H3ClientConnect(serverAddress)
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStream()
	AssertNil(err)
	// End the request with FIN before sending its headers.
	AssertNil(stream.Close())
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

func http3FinFrame(frameType uint64, payload []byte) []byte {
	frame := quicvarint.Append(nil, frameType)
	frame = quicvarint.Append(frame, uint64(len(payload)))
	return append(frame, payload...)
}

func http3FinHeaders(method, path, contentLength string) []byte {
	var headers bytes.Buffer
	encoder := qpack.NewEncoder(&headers)
	for _, field := range []qpack.HeaderField{
		{Name: ":method", Value: method},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "localhost"},
		{Name: ":path", Value: path},
	} {
		AssertNil(encoder.WriteField(field))
	}
	if contentLength != "" {
		AssertNil(encoder.WriteField(qpack.HeaderField{Name: "content-length", Value: contentLength}))
	}
	AssertNil(encoder.Close())
	return http3FinFrame(0x01, headers.Bytes())
}

func http3FinReadResponse(stream *quic.Stream, bodyLength int) {
	response, err := io.ReadAll(stream)
	AssertNil(err, "expected a complete response and FIN")
	reader := bytes.NewReader(response)
	status := ""
	var body []byte
	for reader.Len() != 0 {
		frameType, err := quicvarint.Read(reader)
		AssertNil(err)
		length, err := quicvarint.Read(reader)
		AssertNil(err)
		AssertEqual(true, length <= uint64(reader.Len()))
		payload := make([]byte, int(length))
		_, err = io.ReadFull(reader, payload)
		AssertNil(err)
		switch frameType {
		case 0x01:
			decode := qpack.NewDecoder().Decode(payload)
			for {
				field, err := decode()
				if err == io.EOF {
					break
				}
				AssertNil(err)
				if field.Name == ":status" {
					status = field.Value
				}
			}
		case 0x00:
			body = append(body, payload...)
		}
	}
	AssertEqual("200", status)
	AssertEqual(bodyLength, len(body))
}

func Http3RequestFinCompleteTest(s *Http3Suite) {
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	Log(s.Containers.Vpp.VppInstance.Vppctl("http tps no-zc h3 uri https://" + serverAddress))
	get := http3FinHeaders(http.MethodGet, "/test_file_64", "")
	post := http3FinHeaders(http.MethodPost, "/test_file_4", "4")
	for _, tc := range []struct {
		name       string
		request    []byte
		bodyLength int
	}{
		{"headers", get, 64},
		{"zero content length", http3FinHeaders(http.MethodGet, "/test_file_64", "0"), 64},
		{"empty DATA after body", append(append(bytes.Clone(post), http3FinFrame(0x00, []byte("abcd"))...), http3FinFrame(0x00, nil)...), 0},
		{"complete DATA", append(bytes.Clone(post), http3FinFrame(0x00, []byte("abcd"))...), 0},
		{"multiple DATA frames", append(append(bytes.Clone(post), http3FinFrame(0x00, []byte("ab"))...), http3FinFrame(0x00, []byte("cd"))...), 0},
		{"empty DATA", append(append(bytes.Clone(post), http3FinFrame(0x00, nil)...), http3FinFrame(0x00, []byte("abcd"))...), 0},
		{"unknown frames", append(append(http3FinFrame(0x21, []byte("padding")), get...), http3FinFrame(0x21, nil)...), 64},
	} {
		By(tc.name)
		conn := H3ClientConnect(serverAddress)
		stream, err := conn.OpenStream()
		AssertNil(err)
		AssertNil(stream.SetDeadline(time.Now().Add(3 * time.Second)))
		_, err = stream.Write(tc.request)
		AssertNil(err)
		AssertNil(stream.Close())
		http3FinReadResponse(stream, tc.bodyLength)
		AssertNil(conn.CloseWithError(0, ""))
	}
	http3TestSessionCleanupServer(s)
}

func Http3RequestFinErrorsTest(s *Http3Suite) {
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	Log(s.Containers.Vpp.VppInstance.Vppctl("http tps no-zc h3 uri https://" + serverAddress))
	get := http3FinHeaders(http.MethodGet, "/test_file_64", "")
	post := http3FinHeaders(http.MethodPost, "/test_file_4", "5")
	for _, tc := range []struct {
		name       string
		request    []byte
		code       http3.ErrCode
		connection bool
	}{
		{"no headers", nil, http3.ErrCodeRequestIncomplete, false},
		{"frame boundary before headers", http3FinFrame(0x21, []byte("padding")), http3.ErrCodeRequestIncomplete, false},
		{"partial frame type", []byte{0x40}, http3.ErrCodeFrameError, true},
		{"missing frame length", []byte{0x01}, http3.ErrCodeFrameError, true},
		{"partial frame length", []byte{0x01, 0x40}, http3.ErrCodeFrameError, true},
		{"missing HEADERS payload", []byte{0x01, 0x03}, http3.ErrCodeFrameError, true},
		{"truncated HEADERS", get[:len(get)-1], http3.ErrCodeFrameError, true},
		{"truncated DATA", append(bytes.Clone(post), 0x00, 0x05, 'a'), http3.ErrCodeFrameError, true},
		{"truncated unknown frame", []byte{0x21, 0x03, 'a'}, http3.ErrCodeFrameError, true},
		{"truncated trailing unknown frame", append(bytes.Clone(post), 0x21, 0x03, 'a'), http3.ErrCodeFrameError, true},
		{"truncated frame after body", append(append(bytes.Clone(post), http3FinFrame(0x00, []byte("abcde"))...), 0x21, 0x03, 'a'), http3.ErrCodeFrameError, true},
		{"partial trailing frame header", append(bytes.Clone(post), 0x40), http3.ErrCodeFrameError, true},
		{"missing body", post, http3.ErrCodeMessageError, false},
		{"short body", append(bytes.Clone(post), http3FinFrame(0x00, []byte("abcd"))...), http3.ErrCodeMessageError, false},
		{"long body", append(bytes.Clone(post), http3FinFrame(0x00, []byte("abcdef"))...), http3.ErrCodeMessageError, false},
		{"extra DATA frame", append(append(bytes.Clone(post), http3FinFrame(0x00, []byte("abcde"))...), http3FinFrame(0x00, []byte("f"))...), http3.ErrCodeMessageError, false},
		{"prior stream error", http3FinFrame(0x01, []byte{0, 0, 0xd7, 0xc1}), http3.ErrCodeMessageError, false},
		{"prior connection error", http3FinFrame(0x00, []byte("a")), http3.ErrCodeFrameUnexpected, true},
	} {
		By(fmt.Sprintf("%s: %s", tc.name, tc.code))
		conn := H3ClientConnect(serverAddress)
		// Leave another request waiting for its last header byte. Stream errors
		// must allow it to finish; framing errors must terminate it too.
		healthy, err := conn.OpenStream()
		AssertNil(err)
		AssertNil(healthy.SetDeadline(time.Now().Add(3 * time.Second)))
		_, err = healthy.Write(get[:len(get)-1])
		AssertNil(err)
		stream, err := conn.OpenStream()
		AssertNil(err)
		AssertNil(stream.SetDeadline(time.Now().Add(3 * time.Second)))
		if len(tc.request) != 0 {
			_, err = stream.Write(tc.request)
			AssertNil(err)
		}
		AssertNil(stream.Close())
		_, err = stream.Read([]byte{0})
		if tc.connection {
			expected := quic.ApplicationError{ErrorCode: quic.ApplicationErrorCode(tc.code), Remote: true}
			AssertMatchError(err, &expected)
			_, err = healthy.Read([]byte{0})
			AssertMatchError(err, &expected)
		} else {
			expected := quic.StreamError{StreamID: stream.StreamID(), ErrorCode: quic.StreamErrorCode(tc.code), Remote: true}
			AssertMatchError(err, &expected)
			AssertNil(context.Cause(conn.Context()), "stream error must not close the connection")
			_, err = healthy.Write(get[len(get)-1:])
			AssertNil(err)
			AssertNil(healthy.Close())
			http3FinReadResponse(healthy, 64)
		}
		AssertNil(conn.CloseWithError(0, ""))
	}
	http3TestSessionCleanupServer(s)
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
	http3SenInvalidReqExpectStreamError(
		s,
		[]byte{
			0x01, 0x0B, 0x00, 0x00, 0xD4, 0xD7, 0xC1, 0x50,
			0x01, 0x61, 0x54, 0x01, 0x34, 0x00, 0x05, 0x78,
			0x78, 0x78, 0x78, 0x78,
		},
		http3.ErrCodeMessageError)
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
		0x01, 0x13, 0x00, 0x00, 0xD4, 0xD7, 0x51, 0x07,
		0x2F, 0x75, 0x70, 0x6C, 0x6F, 0x61, 0x64, 0x50,
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
		ErrorCode: quic.StreamErrorCode(http3.ErrCodeMessageError),
		Remote:    true,
	}
	AssertMatchError(err, &expectedErr, "expected error code "+http3.ErrCodeMessageError.String())
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

type http3TraceFunc func(qlogwriter.Event)

func (f http3TraceFunc) AddProducer() qlogwriter.Recorder { return f }
func (f http3TraceFunc) SupportsSchemas(string) bool      { return true }
func (f http3TraceFunc) RecordEvent(e qlogwriter.Event)   { f(e) }
func (f http3TraceFunc) Close() error                     { return nil }

func Http3UnknownFrameOnReqStreamTest(s *Http3Suite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	uri := "https://" + serverAddress
	Log(vpp.Vppctl("http tps no-zc h3 uri " + uri))

	for _, tc := range []struct {
		length     uint64
		payloadLen int
	}{
		{16, 16},
		{1, 0},
		{1 << 32, 2},
		{1<<32 + 1, 2},
		{0x001fffff00000000, 2},
	} {
		By(fmt.Sprintf("discarding an unknown frame of length %d with %d payload bytes received", tc.length, tc.payloadLen))
		frame := quicvarint.Append(nil, 0x21)
		frame = quicvarint.Append(frame, tc.length)
		frame = append(frame, make([]byte, tc.payloadLen)...)

		acked := make(chan struct{})
		var mu sync.Mutex
		var ackOnce sync.Once
		packets := make(map[qlog.PacketNumber]bool)
		trace := http3TraceFunc(func(event qlogwriter.Event) {
			mu.Lock()
			defer mu.Unlock()
			switch packet := event.(type) {
			case qlog.PacketSent:
				for _, frameEvent := range packet.Frames {
					// The raw request stream is the first bidirectional stream.
					if f, ok := frameEvent.Frame.(*qlog.StreamFrame); ok && f.StreamID == 0 &&
						f.Offset+f.Length == int64(len(frame)) {
						packets[packet.Header.PacketNumber] = true
					}
				}
			case qlog.PacketReceived:
				if packet.Header.PacketType != qlog.PacketType1RTT {
					return
				}
				for _, frameEvent := range packet.Frames {
					if ack, ok := frameEvent.Frame.(*qlog.AckFrame); ok {
						for pn := range packets {
							if ack.AcksPacket(pn) {
								ackOnce.Do(func() { close(acked) })
							}
						}
					}
				}
			}
		})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := quic.DialAddr(ctx, serverAddress,
			&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}, SessionTicketsDisabled: true},
			&quic.Config{Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return trace }})
		AssertNil(err)
		defer conn.CloseWithError(0, "")
		h3c := (&http3.Transport{}).NewClientConn(conn)
		stream, err := conn.OpenStream()
		AssertNil(err)
		deadline, _ := ctx.Deadline()
		AssertNil(stream.SetWriteDeadline(deadline))

		// Keep the send side open and withhold any remaining frame payload.
		_, err = stream.Write(frame)
		AssertNil(err)
		select {
		case <-acked:
		case <-ctx.Done():
			Fail("server did not acknowledge the unknown-frame data")
		}

		responseStream, err := h3c.OpenRequestStream(ctx)
		AssertNil(err)
		AssertNil(responseStream.SetDeadline(time.Now().Add(3 * time.Second)))
		req, err := http.NewRequest(http.MethodGet, uri+"/test_file_64", nil)
		AssertNil(err)
		AssertNil(responseStream.SendRequestHeader(req))
		AssertNil(responseStream.Close())
		resp, err := responseStream.ReadResponse()
		AssertNil(err, "server must remain responsive while discarding a large unknown frame")
		AssertHttpStatus(resp, http.StatusOK)
		body, err := io.ReadAll(resp.Body)
		AssertNil(err)
		AssertEqual(64, len(body))
		AssertNil(resp.Body.Close())
		AssertNil(context.Cause(stream.Context()), "unknown frame must not reset the request stream")
	}
}

func Http3GoawayInvalidLengthTest(s *Http3Suite) {
	http3SendCtrlExpectConnError(
		s,
		[]byte{
			0x04, 0x00, 0x07, 0x09,
			0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		http3.ErrCodeFrameError)
}

func Http3GoawayEmptyTest(s *Http3Suite) {
	http3SendCtrlExpectConnError(s, []byte{0x04, 0x00, 0x07, 0x00}, http3.ErrCodeFrameError)
}

func Http3GoawayTruncatedIdTest(s *Http3Suite) {
	http3SendCtrlExpectConnError(s, []byte{0x04, 0x00, 0x07, 0x01, 0x40}, http3.ErrCodeFrameError)
}

func Http3GoawayExtraBytesTest(s *Http3Suite) {
	http3SendCtrlExpectConnError(s, []byte{0x04, 0x00, 0x07, 0x02, 0x00, 0x00}, http3.ErrCodeFrameError)
}

func Http3PushControlFrameErrorsTest(s *Http3Suite) {
	address := s.VppAddr() + ":" + s.Ports.Port1
	Log(s.Containers.Vpp.VppInstance.Vppctl("http tps no-zc h3 uri https://" + address))
	type testCase struct {
		name    string
		frames  []byte
		code    http3.ErrCode
		request bool
	}
	var cases []testCase
	for _, frameType := range []uint64{0x03, 0x0d} {
		for _, payload := range [][]byte{nil, {0x40}, {0x80, 0x00, 0x00}, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, {0x00, 0x00}, make([]byte, 9)} {
			cases = append(cases, testCase{
				name:   fmt.Sprintf("malformed frame 0x%x payload %x", frameType, payload),
				frames: http3FinFrame(frameType, payload), code: http3.ErrCodeFrameError,
			})
		}
		cases = append(cases, testCase{
			name:   fmt.Sprintf("frame 0x%x on request stream", frameType),
			frames: http3FinFrame(frameType, []byte{0}), code: http3.ErrCodeFrameUnexpected, request: true,
		})
	}
	for _, id := range []uint64{0, 63, 64, 16384, 1 << 32, 1<<62 - 1} {
		cases = append(cases, testCase{
			name:   fmt.Sprintf("cancel unpromised push %d", id),
			frames: http3FinFrame(0x03, quicvarint.Append(nil, id)), code: http3.ErrCodeIDError,
		})
	}
	for _, limit := range []uint64{1, 1 << 32, 1<<62 - 1} {
		cases = append(cases, testCase{
			name: fmt.Sprintf("decreasing MAX_PUSH_ID from %d", limit),
			frames: append(http3FinFrame(0x0d, quicvarint.Append(nil, limit)),
				http3FinFrame(0x0d, quicvarint.Append(nil, limit-1))...), code: http3.ErrCodeIDError,
		})
	}
	cases = append(cases, testCase{
		name:   "cancel unpromised push after MAX_PUSH_ID",
		frames: append(http3FinFrame(0x0d, []byte{0}), http3FinFrame(0x03, []byte{0})...), code: http3.ErrCodeIDError,
	})
	for _, tc := range cases {
		By(tc.name)
		conn := H3ClientConnect(address)
		defer conn.CloseWithError(0, "")
		control, err := conn.OpenUniStream()
		AssertNil(err)
		if tc.request {
			_, err = control.Write([]byte{0x00, 0x04, 0x00})
			AssertNil(err)
			stream, err := conn.OpenStream()
			AssertNil(err)
			_, err = stream.Write(tc.frames)
			AssertNil(err)
		} else {
			_, err = control.Write(append([]byte{0x00, 0x04, 0x00}, tc.frames...))
			AssertNil(err)
		}
		select {
		case <-conn.Context().Done():
			expected := quic.ApplicationError{ErrorCode: quic.ApplicationErrorCode(tc.code), Remote: true}
			AssertMatchError(context.Cause(conn.Context()), &expected)
		case <-time.After(3 * time.Second):
			Fail("push control frame did not produce the expected connection error")
		}
		AssertNil(conn.CloseWithError(0, ""))
	}
	http3TestSessionCleanupServer(s)
}

func Http3MaxPushIdTest(s *Http3Suite) {
	address := s.VppAddr() + ":" + s.Ports.Port1
	Log(s.Containers.Vpp.VppInstance.Vppctl("http tps no-zc h3 uri https://" + address))
	// A new connection starts without a push limit, independently of previous connections.
	for range 2 {
		conn := H3ClientConnect(address)
		defer conn.CloseWithError(0, "")
		control, err := conn.OpenUniStream()
		AssertNil(err)
		_, err = control.Write([]byte{0x00, 0x04, 0x00})
		AssertNil(err)
		for _, id := range []uint64{0, 0, 63, 64, 16383, 16384, 1 << 30, 1 << 32, 1<<62 - 1} {
			for _, length := range []int{1, 2, 4, 8} {
				if length < quicvarint.Len(id) {
					continue
				}
				By(fmt.Sprintf("MAX_PUSH_ID %d encoded in %d bytes", id, length))
				_, err = control.Write(http3FinFrame(0x0d, quicvarint.AppendWithLen(nil, id, length)))
				AssertNil(err)
				http3StreamTypeCheckRequest(conn)
			}
		}
		AssertNil(conn.CloseWithError(0, ""))
	}
	http3TestSessionCleanupServer(s)
}

func Http3ClientPushControlFramesTest(s *Http3Suite) {
	cert, err := tls.LoadX509KeyPair("resources/cert/localhost.crt", "resources/cert/localhost.key")
	AssertNil(err)
	address := s.HostAddr() + ":" + s.Ports.Port1
	listener, err := quic.ListenAddr(address,
		&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}, nil)
	AssertNil(err)
	defer listener.Close()
	for _, tc := range []struct {
		name  string
		frame []byte
		code  http3.ErrCode
	}{
		{"MAX_PUSH_ID", http3FinFrame(0x0d, []byte{0}), http3.ErrCodeFrameUnexpected},
		{"empty MAX_PUSH_ID", http3FinFrame(0x0d, nil), http3.ErrCodeFrameUnexpected},
		{"ungranted CANCEL_PUSH", http3FinFrame(0x03, []byte{0}), http3.ErrCodeIDError},
		{"empty CANCEL_PUSH", http3FinFrame(0x03, nil), http3.ErrCodeFrameError},
		{"truncated CANCEL_PUSH", http3FinFrame(0x03, []byte{0x40}), http3.ErrCodeFrameError},
		{"CANCEL_PUSH with extra bytes", http3FinFrame(0x03, []byte{0, 0}), http3.ErrCodeFrameError},
	} {
		By(tc.name)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(done)
			conn, err := listener.Accept(ctx)
			AssertNil(err)
			defer conn.CloseWithError(0, "")
			stream, err := conn.AcceptStream(ctx)
			AssertNil(err)
			deadline, _ := ctx.Deadline()
			AssertNil(stream.SetReadDeadline(deadline))
			reader := quicvarint.NewReader(stream)
			frameType, err := quicvarint.Read(reader)
			AssertNil(err)
			AssertEqual(uint64(0x01), frameType)
			length, err := quicvarint.Read(reader)
			AssertNil(err)
			_, err = io.CopyN(io.Discard, stream, int64(length))
			AssertNil(err)
			control, err := conn.OpenUniStream()
			AssertNil(err)
			_, err = control.Write(append([]byte{0x00, 0x04, 0x00}, tc.frame...))
			AssertNil(err)
			select {
			case <-conn.Context().Done():
				expected := quic.ApplicationError{ErrorCode: quic.ApplicationErrorCode(tc.code), Remote: true}
				AssertMatchError(context.Cause(conn.Context()), &expected)
			case <-ctx.Done():
				Fail("client did not reject push control frame")
			}
		}()
		o := s.Containers.Vpp.VppInstance.Vppctl("http client http3 timeout 5 uri https://" + address + "/")
		Log(o)
		<-done
		AssertContains(o, "transport closed")
	}
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

func http3StreamTypeCheckRequest(conn *quic.Conn) {
	stream, err := conn.OpenStream()
	AssertNil(err)
	AssertNil(stream.SetDeadline(time.Now().Add(3 * time.Second)))
	_, err = stream.Write(http3FinHeaders(http.MethodGet, "/test_file_64", ""))
	AssertNil(err)
	AssertNil(stream.Close())
	http3FinReadResponse(stream, 64)
}

func Http3FragmentedStreamTypeTest(s *Http3Suite) {
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	Log(s.Containers.Vpp.VppInstance.Vppctl("http tps no-zc h3 uri https://" + serverAddress))
	for _, streamType := range []uint64{0x00, 0x02, 0x03, 0x1234} {
		for _, length := range []int{2, 4, 8} {
			By(fmt.Sprintf("stream type 0x%x encoded in %d bytes", streamType, length))
			conn := H3ClientConnect(serverAddress)
			defer conn.CloseWithError(0, "")
			stream, err := conn.OpenUniStream()
			AssertNil(err)
			encoded := quicvarint.AppendWithLen(nil, streamType, length)
			for i := range encoded {
				_, err = stream.Write(encoded[i : i+1])
				AssertNil(err)
				if i == len(encoded)-1 && streamType == 0x00 {
					_, err = stream.Write([]byte{0x04, 0x00})
					AssertNil(err)
				}
				// Complete a request before sending the next byte, so each
				// incomplete prefix reaches VPP separately.
				http3StreamTypeCheckRequest(conn)
			}
			if streamType != 0x1234 {
				duplicate, err := conn.OpenUniStream()
				AssertNil(err)
				_, err = duplicate.Write(quicvarint.Append(nil, streamType))
				AssertNil(err)
				select {
				case <-conn.Context().Done():
					expected := quic.ApplicationError{ErrorCode: quic.ApplicationErrorCode(http3.ErrCodeStreamCreationError), Remote: true}
					AssertMatchError(context.Cause(conn.Context()), &expected)
				case <-time.After(3 * time.Second):
					Fail("completed stream type was not registered")
				}
			}
			AssertNil(conn.CloseWithError(0, ""))
		}
	}
	http3TestSessionCleanupServer(s)
}

func Http3IncompleteStreamTypeCloseTest(s *Http3Suite) {
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	Log(s.Containers.Vpp.VppInstance.Vppctl("http tps no-zc h3 uri https://" + serverAddress))
	for _, prefix := range [][]byte{nil, {0x40}, {0x80, 0x00, 0x00}, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, {0x21}} {
		for _, reset := range []bool{false, true} {
			By(fmt.Sprintf("closing stream type prefix %x, reset=%t", prefix, reset))
			conn := H3ClientConnect(serverAddress)
			defer conn.CloseWithError(0, "")
			control, err := conn.OpenUniStream()
			AssertNil(err)
			_, err = control.Write([]byte{0x00, 0x04, 0x00})
			AssertNil(err)
			stream, err := conn.OpenUniStream()
			AssertNil(err)
			if len(prefix) != 0 {
				_, err = stream.Write(prefix)
				AssertNil(err)
				http3StreamTypeCheckRequest(conn)
			}
			if reset {
				stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
			} else {
				AssertNil(stream.Close())
			}
			http3StreamTypeCheckRequest(conn)
			AssertNil(context.Cause(conn.Context()), "closing a noncritical stream must not close the connection")
			AssertNil(conn.CloseWithError(0, ""))
		}
	}
	http3TestSessionCleanupServer(s)
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

func Http3ServerMemLeakTest(s *Http3Suite) {
	s.SkipUnlessLeakCheck()

	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr() + ":" + s.Ports.Port1
	vpp.Vppctl("http cli server http3-enabled uri https://" + serverAddress)
	target := fmt.Sprintf("https://%s/show/version", serverAddress)

	/* no goVPP less noise */
	vpp.Disconnect()

	/* warmup requests (FIB, pools) */
	args := fmt.Sprintf("-k --max-time 10 --noproxy '*' --http3-only -z %s %s %s %s", target, target, target, target)
	_, log := RunCurlContainer(s.Containers.Curl, args)
	AssertContains(log, "HTTP/3 200")
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

func Http3ClientMemLeakTest(s *Http3Suite) {
	s.SkipUnlessLeakCheck()

	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.HostAddr() + ":" + s.Ports.Port1

	s.StartNginx()

	uri := "https://" + serverAddress + "/64B"

	/* no goVPP less noise */
	vpp.Disconnect()

	/* warmup requests (FIB, pools) */
	cmd := fmt.Sprintf("http client verbose http3 uri %s", uri)
	o := vpp.Vppctl(cmd)
	AssertContains(o, "HTTP/3 200 OK")

	/* let's give it some time to clean up sessions, so pool elements can be reused and we have less noise */
	time.Sleep(time.Second * 15)

	vpp.EnableMemoryTrace()
	traces1, err := vpp.GetMemoryTrace()
	AssertNil(err, fmt.Sprint(err))

	o = vpp.Vppctl(cmd)
	AssertContains(o, "HTTP/3 200 OK")

	/* let's give it some time to clean up sessions */
	time.Sleep(time.Second * 15)

	traces2, err := vpp.GetMemoryTrace()
	Log(vpp.Vppctl("show http"))
	Log(vpp.Vppctl("show quic"))
	Log(vpp.Vppctl("show quic crypto context"))
	Log(vpp.Vppctl("show session verbose 2"))
	AssertNil(err, fmt.Sprint(err))
	vpp.MemLeakCheck(traces1, traces2)
}

func Http3PseudoHeadersTest(s *Http3Suite) {
	vpp := s.Containers.Vpp.VppInstance
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Port1)
	Log(vpp.Vppctl("http tps uri https://" + address + " h3 no-zc"))
	conn := H3ClientConnect(address)
	defer conn.CloseWithError(0, "")
	control, err := conn.OpenUniStream()
	AssertNil(err)
	_, err = control.Write([]byte{0, 4, 0})
	AssertNil(err)
	encode := func(fields []hpack.HeaderField) []byte {
		out := []qpack.HeaderField{}
		for _, f := range fields {
			out = append(out, qpack.HeaderField{Name: f.Name, Value: f.Value})
		}
		return http3EarlyHeaders(out)
	}
	healthyFields := []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: address}, {Name: ":path", Value: "/test_file_64"}}
	for _, tc := range pseudoHeaderCases(address) {
		By(tc.name)
		stream, err := conn.OpenStream()
		AssertNil(err)
		AssertNil(stream.SetDeadline(time.Now().Add(3 * time.Second)))
		_, err = stream.Write(encode(tc.fields))
		AssertNil(err)
		if tc.status != 0 {
			AssertNil(stream.Close())
		}
		healthy, err := conn.OpenStream()
		AssertNil(err)
		AssertNil(healthy.SetDeadline(time.Now().Add(3 * time.Second)))
		_, err = healthy.Write(encode(healthyFields))
		AssertNil(err)
		AssertNil(healthy.Close())
		if tc.status == 0 {
			_, err = stream.Read([]byte{0})
			AssertMatchError(err, &quic.StreamError{StreamID: stream.StreamID(), ErrorCode: quic.StreamErrorCode(http3.ErrCodeMessageError), Remote: true})
		} else {
			http3ReadEarlyResponse(stream, strconv.Itoa(tc.status))
		}
		AssertNotEmpty(http3ReadEarlyResponse(healthy, "200"))
		AssertNil(context.Cause(conn.Context()))
	}
}

func Http3ResponsePseudoHeadersTest(s *Http3Suite) {
	vpp := s.Containers.Vpp.VppInstance
	cert, err := tls.LoadX509KeyPair("resources/cert/localhost.crt", "resources/cert/localhost.key")
	AssertNil(err)
	listener, err := quic.ListenAddr(net.JoinHostPort(s.HostAddr(), s.Ports.Port1), &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}, nil)
	AssertNil(err)
	defer listener.Close()
	for _, tc := range pseudoResponseCases() {
		By(tc.name)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(done)
			conn, err := listener.Accept(ctx)
			AssertNil(err)
			defer conn.CloseWithError(0, "")
			control, err := conn.OpenUniStream()
			AssertNil(err)
			_, err = control.Write([]byte{0, 4, 0})
			AssertNil(err)
			stream, err := conn.AcceptStream(ctx)
			AssertNil(err)
			deadline, _ := ctx.Deadline()
			AssertNil(stream.SetDeadline(deadline))
			reader := quicvarint.NewReader(stream)
			frame, err := quicvarint.Read(reader)
			AssertNil(err)
			AssertEqual(uint64(1), frame)
			length, err := quicvarint.Read(reader)
			AssertNil(err)
			_, err = io.CopyN(io.Discard, stream, int64(length))
			AssertNil(err)
			fields := []qpack.HeaderField{}
			for _, f := range tc.fields {
				fields = append(fields, qpack.HeaderField{Name: f.Name, Value: f.Value})
			}
			_, err = stream.Write(http3EarlyHeaders(fields))
			AssertNil(err)
			select {
			case <-stream.Context().Done():
				AssertMatchError(context.Cause(stream.Context()), &quic.StreamError{StreamID: stream.StreamID(), ErrorCode: quic.StreamErrorCode(http3.ErrCodeMessageError), Remote: true})
			case <-ctx.Done():
				Fail("expected H3_MESSAGE_ERROR receive cancellation")
			}
		}()
		Log(vpp.Vppctl("http client http3 verbose timeout 1 uri https://" + listener.Addr().String() + "/"))
		<-done
		cancel()
	}
	AssertNotContains(vpp.Vppctl("show http stats"), "connections protocol error")
}
