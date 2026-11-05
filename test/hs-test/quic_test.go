package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/gomega"
	"github.com/quic-go/quic-go"
)

func init() {
	RegisterQuicTests(QuicAlpnMatchTest, QuicClientHelloRetryTest, QuicAlpnOverlapMatchTest,
		QuicAlpnServerPriorityMatchTest, QuicAlpnMismatchTest,
		QuicAlpnEmptyServerListTest, QuicAlpnEmptyClientListTest, QuicBuiltinVperfZeroCopyTest,
		QuicBuiltinVperfBidirectionalZeroCopyTest, QuicBuiltinVperfTest, QuicBuiltinVperfBidirectionalTest,
		QuicReorderTest, QuicCrlRejectThenAllowTest, QuicPeerCertCloseTest)
	RegisterQuicMWTests(QuicCpsMWTest, QuicEngineObjectCountMigrationMWTest)
	RegisterNoTopoTests(QuicFailedHandshakeTest, QuicCryptoContextTest, QuicRxDatagramSizeTest,
		QuicEngineObjectCountTest, QuicConnectFailureTest, QuicStreamCloseTest, QuicStreamResetCloseTest)
	RegisterNoTopoMWTests(QuicEngineObjectCountMWTest, QuicAcceptTimeoutMWTest, QuicConnectFailureMWTest,
		QuicHandshakeTimeoutMWTest, QuicIdleTimeoutMWTest)
}

func QuicEngineObjectCountMWTest(s *NoTopoSuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	QuicEngineObjectCountTest(s)
}

func quicEngineObjectCounts(vpp *VppInstance) []uint64 {
	return quicParseEngineObjectCounts(vpp.Vppctl("show quic"))
}

func quicParseEngineObjectCounts(o string) []uint64 {
	pattern := regexp.MustCompile(`(?m)^(?:quicly connections|quicly streams):\s+(\d+)\r?$`)
	matches := pattern.FindAllStringSubmatch(o, -1)
	AssertEqual(2, len(matches), "missing engine object counts: "+o)
	result := make([]uint64, len(matches))
	for i, match := range matches {
		var err error
		result[i], err = strconv.ParseUint(match[1], 10, 64)
		AssertNil(err)
	}
	return result
}

func quicActiveTimerCounts(vpp *VppInstance) []uint64 {
	return quicParseActiveTimerCounts(vpp.Vppctl("show quic verbose"))
}

func quicParseActiveTimerCounts(o string) []uint64 {
	pattern := regexp.MustCompile(`(?m)^  active timers: ACCEPT (\d+) TX (\d+)\r?$`)
	matches := pattern.FindAllStringSubmatch(o, -1)
	AssertNotEmpty(matches, "missing active timer counts: "+o)
	AssertEqual(strings.Count(o, "connections without engine:"), len(matches),
		"expected timer counts for every thread: "+o)
	result := []uint64{0, 0}
	for _, match := range matches {
		for i := range result {
			count, err := strconv.ParseUint(match[i+1], 10, 64)
			AssertNil(err)
			result[i] += count
		}
	}
	return result
}

type quicCleanupCounts struct {
	ContextsPerThread []uint64
	EngineConnections uint64
	EngineStreams     uint64
	AcceptTimers      uint64
	TxTimers          uint64
}

func quicReadCleanupCounts(o string) quicCleanupCounts {
	objects := quicParseEngineObjectCounts(o)
	timers := quicParseActiveTimerCounts(o)
	pattern := regexp.MustCompile(`(?m)^Thread (\d+): ctx pool (\d+)/\d+\r?$`)
	pools := pattern.FindAllStringSubmatch(o, -1)
	AssertNotEmpty(pools, "missing context pool counts: "+o)
	AssertEqual(len(pools), strings.Count(o, "active timers:"), "missing per-thread counts: "+o)
	counts := quicCleanupCounts{
		ContextsPerThread: make([]uint64, len(pools)),
		EngineConnections: objects[0],
		EngineStreams:     objects[1],
		AcceptTimers:      timers[0],
		TxTimers:          timers[1],
	}
	for i, pool := range pools {
		AssertEqual(strconv.Itoa(i), pool[1], "unexpected context pool thread: "+o)
		var err error
		counts.ContextsPerThread[i], err = strconv.ParseUint(pool[2], 10, 64)
		AssertNil(err)
	}
	return counts
}

func quicCleanupCheck(timeout time.Duration, vpps ...*VppInstance) func() {
	baselines := make([]quicCleanupCounts, len(vpps))
	for i, vpp := range vpps {
		baselines[i] = quicReadCleanupCounts(vpp.Vppctl("show quic verbose"))
	}
	return func() {
		for i, vpp := range vpps {
			var output string
			EventuallyWithOffset(1, func() quicCleanupCounts {
				output = vpp.Vppctl("show quic verbose")
				return quicReadCleanupCounts(output)
			}).WithTimeout(timeout).WithPolling(100*time.Millisecond).
				Should(Equal(baselines[i]), func() string {
					return vpp.Container.Name + " QUIC resources did not return to baseline:\n" + output
				})
		}
	}
}

func QuicEngineObjectCountMigrationMWTest(s *QuicSuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	clientVpp := s.Containers.ClientVpp.VppInstance
	serverVpp := s.Containers.ServerVpp.VppInstance
	// Connects start on worker 0. Receive on worker 1 to force UDP/QUIC
	// migration, so engine objects are freed on a different thread.
	for queue := range 2 {
		AssertEmpty(clientVpp.Vppctl("set interface rx-placement " + s.Interfaces.Client.VppName() +
			" queue " + strconv.Itoa(queue) + " worker 1"))
	}
	uri := "quic://" + net.JoinHostPort(s.Interfaces.Server.Ip4AddressString(), s.Ports.Port1)
	AssertContains(serverVpp.Vppctl("test tls server uri "+uri), "server started")
	checkCleanup := quicCleanupCheck(5*time.Second, clientVpp, serverVpp)
	for range 2 {
		o := clientVpp.Vppctl("test tls client uri " + uri)
		Log(o)
		AssertContains(o, "TLS version: 1.3")
		checkCleanup()
		for _, vpp := range []*VppInstance{clientVpp, serverVpp} {
			Log(vpp.Vppctl("show quic"))
		}
	}
}

func QuicEngineObjectCountTest(s *NoTopoSuite) {
	vpp := s.Containers.Vpp.VppInstance
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	Log(vpp.Vppctl("test tls server alpn-proto1 3 uri quic://" + address))
	checkCleanup := quicCleanupCheck(5*time.Second, vpp)
	counts := func() []uint64 {
		return quicEngineObjectCounts(vpp)
	}
	baseline := counts()
	AssertEqual([]uint64{0, 0}, baseline, "listeners must not create engine connection objects")
	o := vpp.Vppctl("show quic")
	AssertNotContains(o, "VPP Context Details")
	AssertNotContains(o, "Smoothed RTT")
	AssertNotContains(o, "active timers:")
	verbose := func() string { return vpp.Vppctl("show quic verbose") }
	o = verbose()
	AssertContains(o, "Thread 0: connections 0 streams 0 listeners 1 reserved 1")
	AssertNotContains(o, "conn state ")
	AssertContains(o, "Smoothed RTT")
	timerCounts := func() []uint64 { return quicActiveTimerCounts(vpp) }
	AssertEqual([]uint64{0, 0}, timerCounts(), "listeners must not create timers")
	sessionDetails := func() string { return vpp.Vppctl("show session verbose 2") }
	AssertNotContains(sessionDetails(), " timers: ACCEPT ")
	waitCounts := func(expected []uint64) {
		Eventually(counts, 5*time.Second, 100*time.Millisecond).Should(Equal(expected))
	}
	streamStatsPattern := regexp.MustCompile(`(?s)---------- Streams ----------.*?---------- Packets ----------`)

	for range 2 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := quic.DialAddr(ctx, address,
			&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}},
			&quic.Config{Versions: []quic.Version{quic.Version1}})
		cancel()
		AssertNil(err)
		defer conn.CloseWithError(0, "test complete")
		waitCounts([]uint64{1, 0})
		Eventually(timerCounts, 5*time.Second, 100*time.Millisecond).Should(Equal([]uint64{0, 1}))
		Eventually(sessionDetails, 5*time.Second, 100*time.Millisecond).
			Should(ContainSubstring(" timers: ACCEPT inactive TX active"))
		AssertNotContains(vpp.Vppctl("show session verbose"), " timers: ACCEPT ")
		Eventually(verbose, 5*time.Second, 100*time.Millisecond).Should(And(
			MatchRegexp(`Thread \d+: connections 1 streams 0 listeners \d+ reserved 1`),
			ContainSubstring("conn state READY: 1"),
		))
		connectionContexts := quicReadCleanupCounts(verbose()).ContextsPerThread

		stream, err := conn.OpenStream()
		AssertNil(err)
		_, err = stream.Write([]byte("count this stream"))
		AssertNil(err)
		waitCounts([]uint64{1, 1})
		AssertEqual(1, strings.Count(sessionDetails(), " timers: ACCEPT "),
			"only the connection should show timers, not its stream or listeners")
		Eventually(verbose, 5*time.Second, 100*time.Millisecond).
			Should(MatchRegexp(`Thread \d+: connections 1 streams 1 listeners \d+ reserved 1`))
		Log(vpp.Vppctl("clear errors"))
		waitCounts([]uint64{1, 1})

		stream.CancelRead(1)
		stream.CancelWrite(1)
		waitCounts([]uint64{1, 0})
		AssertNil(context.Cause(conn.Context()), "stream reset must leave connection alive")
		Eventually(func() []uint64 {
			return quicReadCleanupCounts(verbose()).ContextsPerThread
		}, 5*time.Second, 100*time.Millisecond).Should(Equal(connectionContexts),
			"stream reset must release its VPP context")
		Log(vpp.Vppctl("clear errors"))

		// Closing a connection must also destroy any remaining streams.
		stream, err = conn.OpenStream()
		AssertNil(err)
		_, err = stream.Write([]byte("close with this stream still open"))
		AssertNil(err)
		waitCounts([]uint64{1, 1})
		AssertNil(conn.CloseWithError(0, "test complete"))
		checkCleanup()
		Eventually(verbose, 5*time.Second, 100*time.Millisecond).Should(And(
			Not(ContainSubstring("conn state ")),
			Not(MatchRegexp(`(?m)^Thread \d+: connections \d+ streams [1-9]`)),
		), "verbose context counts must return to the listener baseline")
		Eventually(func() string {
			return streamStatsPattern.FindString(vpp.Vppctl("show quic"))
		}, 5*time.Second, 100*time.Millisecond).Should(And(
			MatchRegexp(`(?m)^Accepted:\s+1\r?$`),
			MatchRegexp(`(?m)^Opened:\s+0\r?$`),
			MatchRegexp(`(?m)^Closed:\s+1\r?$`),
		), "peer-opened stream must increment accepted and closed counters")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, address,
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"no-match"}},
		&quic.Config{Versions: []quic.Version{quic.Version1}})
	if conn != nil {
		defer conn.CloseWithError(0, "test complete")
	}
	AssertNotNil(err, "ALPN mismatch must fail the handshake")
	checkCleanup()
	Log(vpp.Vppctl("show quic"))
}

func QuicStreamCloseTest(s *NoTopoSuite) {
	vpp := s.Containers.Vpp.VppInstance
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	AssertContains(vpp.Vppctl("test tls server echo rx-fifo-size 1m alpn-proto1 3 uri quic://"+address), "server started")
	checkCleanup := quicCleanupCheck(5*time.Second, vpp)
	listenerSessions := vpp.Vppctl("show session")
	counts := func() []uint64 { return quicEngineObjectCounts(vpp) }
	waitCounts := func(streams uint64) {
		Eventually(counts, 5*time.Second, 50*time.Millisecond).Should(Equal([]uint64{1, streams}))
	}
	for _, test := range []string{
		"bidi FIN", "bidi buffered FIN", "bidi buffered FIN parent close",
		"bidi RESET_STREAM", "bidi STOP_SENDING", "uni FIN", "uni RESET_STREAM",
	} {
		func() {
			Log("QUIC stream close case: %s", test)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := quic.DialAddr(ctx, address,
				&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}},
				&quic.Config{Versions: []quic.Version{quic.Version1},
					InitialStreamReceiveWindow: 1024, MaxStreamReceiveWindow: 1024})
			AssertNil(err)
			defer conn.CloseWithError(0, "test complete")
			roundTrip := func() {
				stream, err := conn.OpenStream()
				AssertNil(err)
				AssertNil(stream.SetDeadline(time.Now().Add(5 * time.Second)))
				_, err = stream.Write([]byte("stream cleanup probe"))
				AssertNil(err)
				AssertNil(stream.Close())
				response, err := io.ReadAll(stream)
				AssertNil(err)
				AssertEqual("stream cleanup probe", string(response))
				waitCounts(0)
			}
			// Complete a stream before taking the connection-only baseline.
			roundTrip()
			parentContexts := quicReadCleanupCounts(vpp.Vppctl("show quic verbose")).ContextsPerThread
			parentSessions := vpp.Vppctl("show session")
			frameStats := func() string { return vpp.Vppctl("show session verbose 2") }
			switch test {
			case "bidi FIN":
				roundTrip()
			case "bidi buffered FIN", "bidi buffered FIN parent close":
				stream, err := conn.OpenStream()
				AssertNil(err)
				AssertNil(stream.SetDeadline(time.Now().Add(5 * time.Second)))
				// Exceed the server's 8 KiB TX FIFO and withhold reads so
				// that FIN arrives while some input is still waiting to echo.
				payload := bytes.Repeat([]byte("buffered echo"), 1024)
				_, err = stream.Write(payload)
				AssertNil(err)
				AssertNil(stream.Close())
				Eventually(func() string { return vpp.Vppctl("show session verbose") },
					5*time.Second, 50*time.Millisecond).
					Should(MatchRegexp(`(?m)\[Q\] stream .*CLOSING\s+[1-9][0-9]*\s+[1-9][0-9]*\s*\r?$`))
				if test == "bidi buffered FIN parent close" {
					AssertNil(conn.CloseWithError(0, "close with buffered echo"))
					checkCleanup()
					Eventually(func() string { return vpp.Vppctl("show session") },
						5*time.Second, 100*time.Millisecond).Should(Equal(listenerSessions))
					return
				}
				response, err := io.ReadAll(stream)
				AssertNil(err)
				Expect(response).To(Equal(payload), "half-close must echo all buffered input")
			case "bidi RESET_STREAM":
				stream, err := conn.OpenStream()
				AssertNil(err)
				AssertNil(stream.SetDeadline(time.Now().Add(5 * time.Second)))
				_, err = stream.Write([]byte("reset this stream"))
				AssertNil(err)
				waitCounts(1)
				stream.CancelWrite(0x41)
				_, err = io.ReadAll(stream)
				if err != nil {
					Expect(err).To(BeAssignableToTypeOf(&quic.StreamError{}))
				}
				Eventually(frameStats, 5*time.Second, 100*time.Millisecond).
					Should(MatchRegexp(`reset-stream [1-9][0-9]* stop-sending 0`))
			case "bidi STOP_SENDING":
				stream, err := conn.OpenStream()
				AssertNil(err)
				AssertNil(stream.SetWriteDeadline(time.Now().Add(5 * time.Second)))
				written := make(chan error, 1)
				go func() {
					_, err := stream.Write(bytes.Repeat([]byte("x"), 128<<10))
					written <- err
				}()
				// The peer's 1 KiB receive window leaves VPP's echo TX FIFO
				// nonempty. Exercise STOP_SENDING with unsent application data.
				Eventually(func() string { return vpp.Vppctl("show session verbose") },
					5*time.Second, 100*time.Millisecond).
					Should(MatchRegexp(`(?m)\[Q\] stream .*ESTABLISHED\s+[0-9]+\s+[1-9][0-9]*\s*\r?$`))
				stream.CancelRead(0x42)
				Eventually(frameStats, 5*time.Second, 100*time.Millisecond).
					Should(MatchRegexp(`reset-stream 0 stop-sending [1-9][0-9]*`))
				// Abort the flow-controlled writer only after STOP_SENDING
				// arrived, then check cleanup with both directions terminated.
				stream.CancelWrite(0x42)
				Eventually(written, 5*time.Second).Should(Receive(&err))
				if err != nil {
					Expect(err).To(BeAssignableToTypeOf(&quic.StreamError{}))
				}
			default:
				stream, err := conn.OpenUniStream()
				AssertNil(err)
				_, err = stream.Write([]byte("unidirectional cleanup"))
				AssertNil(err)
				waitCounts(1)
				if test == "uni FIN" {
					AssertNil(stream.Close())
				} else {
					stream.CancelWrite(0x43)
					Eventually(frameStats, 5*time.Second, 100*time.Millisecond).
						Should(MatchRegexp(`reset-stream [1-9][0-9]* stop-sending 0`))
				}
			}
			waitCounts(0)
			Eventually(func() []uint64 {
				return quicReadCleanupCounts(vpp.Vppctl("show quic verbose")).ContextsPerThread
			}, 5*time.Second, 100*time.Millisecond).Should(Equal(parentContexts), "stream context must be released while parent remains open")
			Eventually(func() string { return vpp.Vppctl("show session") },
				5*time.Second, 100*time.Millisecond).Should(Equal(parentSessions))
			AssertNil(context.Cause(conn.Context()), "stream closure must preserve the parent connection")
			roundTrip()
			AssertNil(conn.CloseWithError(0, "test complete"))
			checkCleanup()
			Eventually(func() string { return vpp.Vppctl("show session") },
				5*time.Second, 100*time.Millisecond).Should(Equal(listenerSessions))
		}()
	}
}

func QuicStreamResetCloseTest(s *NoTopoSuite) {
	vpp := s.Containers.Vpp.VppInstance
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	AssertContains(vpp.Vppctl("test tls server alpn-proto1 3 uri quic://"+address), "server started")
	checkCleanup := quicCleanupCheck(5*time.Second, vpp)
	sessions := vpp.Vppctl("show session")
	for range 2 {
		for _, unidirectional := range []bool{false, true} {
			func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				conn, err := quic.DialAddr(ctx, address,
					&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, nil)
				AssertNil(err)
				defer conn.CloseWithError(0, "test complete")
				var stream interface {
					Write([]byte) (int, error)
					CancelWrite(quic.StreamErrorCode)
				}
				if unidirectional {
					stream, err = conn.OpenUniStream()
				} else {
					stream, err = conn.OpenStream()
				}
				AssertNil(err)
				_, err = stream.Write([]byte("reset and immediately close parent"))
				AssertNil(err)
				Eventually(func() []uint64 { return quicEngineObjectCounts(vpp) },
					5*time.Second, 50*time.Millisecond).Should(Equal([]uint64{1, 1}))
				stream.CancelWrite(0x44)
				AssertNil(conn.CloseWithError(0, "close races with stream reset"))
				checkCleanup()
				Eventually(func() string { return vpp.Vppctl("show session") },
					5*time.Second, 100*time.Millisecond).Should(Equal(sessions))
			}()
		}
	}
}

func QuicPeerCertCloseTest(s *QuicSuite) {
	uri := "quic://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	a := s.CreateTlsCrlTestArtifacts("quic-peer-cert", s.Interfaces.Server.Ip4AddressString(),
		s.Containers.ServerVpp, s.Containers.ClientVpp)
	tlsPeerCertClose(s.Containers.ServerVpp.VppInstance, s.Containers.ClientVpp.VppInstance, uri, a)
}

func QuicCrlRejectThenAllowTest(s *QuicSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	a := s.CreateTlsCrlTestArtifacts("quic", s.Interfaces.Server.Ip4AddressString(),
		s.Containers.ServerVpp, s.Containers.ClientVpp)

	Log(serverVpp.Vppctl("test tls server cert " + a.ServerCert + " key " + a.ServerKey + " uri quic://" + serverAddress))
	checkCleanup := quicCleanupCheck(5*time.Second, clientVpp, serverVpp)

	uri := "quic://" + serverAddress
	o := clientVpp.Vppctl("test tls client verify peer ca-cert " + a.CaCert + " crl " + a.Crl + " uri " + uri)
	Log(o)
	AssertContains(o, "connect error failed tls handshake")
	checkCleanup()

	o = serverVpp.Vppctl("show test tls server")
	Log(o)
	AssertContains(o, "accepted connections 0")

	o = clientVpp.Vppctl("test tls client verify peer ca-cert " + a.CaCert + " uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	AssertNotContains(o, "failed tls handshake")

	o = serverVpp.Vppctl("show test tls server")
	Log(o)
	AssertContains(o, "accepted connections 1")
	checkCleanup()
}

func QuicAlpnMatchTest(s *QuicSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("test tls server alpn-proto1 3 uri quic://" + serverAddress))
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("show session verbose 2"))
	checkCleanup := quicCleanupCheck(5*time.Second, s.Containers.ClientVpp.VppInstance,
		s.Containers.ServerVpp.VppInstance)

	uri := "quic://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test tls client alpn-proto1 3 uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	// selected based on 1:1 match
	AssertContains(o, "ALPN selected: h3")
	checkCleanup()
}

func QuicClientHelloRetryTest(s *QuicSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(serverVpp.Vppctl("test tls server uri quic://" + serverAddress))
	checkCleanup := quicCleanupCheck(5*time.Second, clientVpp, serverVpp)

	o := clientVpp.Vppctl("test tls client uri quic://" + serverAddress)
	Log(o)
	AssertContains(o, "TLS version: 1.3")
	group := regexp.MustCompile(`Key agreement: ([^\r\n]+)`).FindStringSubmatch(o)
	AssertEqual(2, len(group), "Expected the client's initial key-share group")
	checkCleanup()

	serverGroup := "P-256"
	if strings.TrimSpace(group[1]) == "secp256r1" {
		serverGroup = "X25519"
	}
	Log("Initial client key share: " + strings.TrimSpace(group[1]) + "; server requires: " + serverGroup)
	o = serverVpp.Vppctl("app crypto add tls-profile app test_tls_server groups " + serverGroup)
	Log(o)
	AssertContains(o, "profile 0")

	serverAddress2 := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port2
	o = serverVpp.Vppctl("test tls server alpn-proto1 3 profile-index 0 uri quic://" + serverAddress2)
	Log(o)
	AssertNotContains(o, "failed")
	AssertNotContains(o, "error")
	checkCleanup = quicCleanupCheck(5*time.Second, clientVpp, serverVpp)

	o = clientVpp.Vppctl("test tls client alpn-proto1 2 alpn-proto2 3 uri quic://" + serverAddress2)
	Log(o)
	AssertNotContains(o, "connect error")
	AssertNotContains(o, "timeout")
	AssertContains(o, "ALPN selected: h3")
	AssertContains(o, "TLS version: 1.3")

	o = serverVpp.Vppctl("show test tls server")
	Log(o)
	AssertContains(o, "accepted connections 2")
	checkCleanup()
}

func QuicAlpnOverlapMatchTest(s *QuicSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("test tls server alpn-proto1 3 alpn-proto2 1 uri quic://" + serverAddress))
	checkCleanup := quicCleanupCheck(5*time.Second, s.Containers.ClientVpp.VppInstance,
		s.Containers.ServerVpp.VppInstance)

	uri := "quic://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test tls client alpn-proto1 2 alpn-proto2 3 uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	// selected based on overlap
	AssertContains(o, "ALPN selected: h3")
	checkCleanup()
}

func QuicAlpnServerPriorityMatchTest(s *QuicSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("test tls server alpn-proto1 3 alpn-proto2 1 uri quic://" + serverAddress))
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("show session verbose 2"))
	checkCleanup := quicCleanupCheck(5*time.Second, s.Containers.ClientVpp.VppInstance,
		s.Containers.ServerVpp.VppInstance)

	uri := "quic://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test tls client alpn-proto1 1 alpn-proto2 3 uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	// selected based on server priority
	AssertContains(o, "ALPN selected: h3")
	checkCleanup()
}

func QuicAlpnMismatchTest(s *QuicSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(serverVpp.Vppctl("test tls server alpn-proto1 2 alpn-proto2 1 uri quic://" + serverAddress))
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("show session verbose 2"))
	checkCleanup := quicCleanupCheck(5*time.Second, clientVpp, serverVpp)

	uri := "quic://" + serverAddress
	o := clientVpp.Vppctl("test tls client alpn-proto1 3 alpn-proto2 4 uri " + uri)
	Log(o)
	AssertNotContains(o, "timeout")
	AssertNotContains(o, "ALPN selected")
	// connection refused on mismatch
	AssertContains(o, "connect error failed tls handshake")
	checkCleanup()
	// The server retains its UDP/QUIC listeners and the client has no sessions.
	o = serverVpp.Vppctl("show session verbose 2")
	Log(o)
	AssertContains(o, "active sessions 2", "server sessions not cleaned up")
	o = serverVpp.Vppctl("show test tls server")
	Log(o)
	AssertContains(o, "accepted connections 0")
	// no session on client
	o = clientVpp.Vppctl("show session verbose 2")
	Log(o)
	AssertContains(o, "no sessions")
}

func QuicAlpnEmptyServerListTest(s *QuicSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("test tls server uri quic://" + serverAddress))
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("show session verbose 2"))
	checkCleanup := quicCleanupCheck(5*time.Second, s.Containers.ClientVpp.VppInstance,
		s.Containers.ServerVpp.VppInstance)

	uri := "quic://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test tls client alpn-proto1 3 alpn-proto2 2 uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	// no alpn negotiation
	AssertContains(o, "ALPN selected: none")
	checkCleanup()
}

func QuicAlpnEmptyClientListTest(s *QuicSuite) {
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("test tls server alpn-proto1 3 alpn-proto2 1 uri quic://" + serverAddress))
	Log(s.Containers.ServerVpp.VppInstance.Vppctl("show session verbose 2"))
	checkCleanup := quicCleanupCheck(5*time.Second, s.Containers.ClientVpp.VppInstance,
		s.Containers.ServerVpp.VppInstance)

	uri := "quic://" + serverAddress
	o := s.Containers.ClientVpp.VppInstance.Vppctl("test tls client uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	// no alpn negotiation
	AssertContains(o, "ALPN selected: none")
	checkCleanup()
}

func QuicFailedHandshakeTest(s *NoTopoSuite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.Interfaces.Tap.Ip4AddressString() + ":" + s.Ports.Http
	Log(vpp.Vppctl("test tls server uri quic://" + serverAddress))
	checkCleanup := quicCleanupCheck(5*time.Second, vpp)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := quic.DialAddr(
		ctx,
		serverAddress,
		&tls.Config{InsecureSkipVerify: true, SessionTicketsDisabled: true},
		// set QUIC version 2 because we want failed accept
		&quic.Config{Versions: []quic.Version{quic.Version2}},
	)
	Log(err)
	// connect should fail (context deadline exceeded)
	AssertNotNil(err, "connect should failed")
	checkCleanup()
	// expect only two sessions (UDP and QUIC listener)
	o := vpp.Vppctl("show session verbose")
	Log(o)
	AssertContains(o, "active sessions 2", "expected only listeners")
}

func QuicConnectFailureMWTest(s *NoTopoSuite) {
	s.CpusPerVppContainer = 2
	s.SetupTest()
	QuicConnectFailureTest(s)
}

func QuicConnectFailureTest(s *NoTopoSuite) {
	vpp := s.Containers.Vpp.VppInstance
	AssertEmpty(vpp.Vppctl("ip route add 192.0.2.1/32 via drop"))
	baseline := quicReadCleanupCounts(vpp.Vppctl("show quic verbose"))
	AssertEqual(uint64(0), baseline.EngineConnections)
	AssertEqual(uint64(0), baseline.EngineStreams)
	AssertEqual(uint64(0), baseline.AcceptTimers)
	AssertEqual(uint64(0), baseline.TxTimers)
	sessions := vpp.Vppctl("show session")
	cryptoContexts := vpp.Vppctl("show quic crypto context")

	// drop route make src address selection fail before connection is created
	for range 3 {
		o := vpp.Vppctl("test tls client uri quic://192.0.2.1/443")
		Log(o)
		AssertContains(o, "connect error no resolving interface")
		AssertNotContains(o, "timeout")
		AssertEqual(sessions, vpp.Vppctl("show session"), "failed connect must not leave sessions")
		AssertEqual(baseline, quicReadCleanupCounts(vpp.Vppctl("show quic verbose")),
			"synchronous connect failure must immediately release all QUIC resources")
		AssertEqual(cryptoContexts, vpp.Vppctl("show quic crypto context"),
			"failed connect must release the detached application's crypto context")
	}
}

func QuicAcceptTimeoutMWTest(s *NoTopoSuite) {
	const oversizedPacketSize = 1281 // QUIC_MAX_PACKET_SIZE + 1
	var quicConfig Stanza
	quicConfig.NewStanza("quic").Append("conn-timeout 3000").Close()
	s.CpusPerVppContainer = 2
	s.SetupTest(quicConfig)
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	AssertContains(vpp.Vppctl("test tls server uri quic://"+serverAddress), "server started")
	baseline := quicReadCleanupCounts(vpp.Vppctl("show quic verbose"))
	AssertEqual(2, len(baseline.ContextsPerThread), "expected main thread and one worker")
	AssertEqual(uint64(0), baseline.EngineConnections)
	AssertEqual(uint64(0), baseline.EngineStreams)
	AssertEqual(uint64(0), baseline.AcceptTimers)
	AssertEqual(uint64(0), baseline.TxTimers)
	checkCleanup := quicCleanupCheck(8*time.Second, vpp)
	sessions := vpp.Vppctl("show session")

	remoteAddr, err := net.ResolveUDPAddr("udp4", serverAddress)
	AssertNil(err)
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(s.HostAddr())})
	AssertNil(err)
	defer socket.Close()

	pending := baseline
	pending.ContextsPerThread = append([]uint64(nil), baseline.ContextsPerThread...)
	pending.ContextsPerThread[1]++
	pending.AcceptTimers++
	for range 2 {
		n, err := socket.WriteToUDP(make([]byte, oversizedPacketSize), remoteAddr)
		AssertNil(err)
		AssertEqual(oversizedPacketSize, n)
		var output string
		Eventually(func() quicCleanupCounts {
			output = vpp.Vppctl("show quic verbose")
			return quicReadCleanupCounts(output)
		}, time.Second, 50*time.Millisecond).Should(Equal(pending),
			"expected one pending context and ACCEPT timer on the worker, without engine objects")
		AssertContains(output, "connections without engine: 1")
		AssertContains(output, "conn state OPENED: 1")

		checkCleanup()
		Eventually(func() string {
			return vpp.Vppctl("show session")
		}, time.Second, 100*time.Millisecond).Should(Equal(sessions),
			"expired UDP session must be removed while listeners remain")
	}
	AssertContains(vpp.Vppctl("show test tls server"), "accepted connections 0")
}

func quicTimeoutSetup(s *NoTopoSuite) *VppInstance {
	var quicConfig Stanza
	quicConfig.NewStanza("quic").Append("conn-timeout 3000").Close()
	s.CpusPerVppContainer = 2
	s.SetupTest(quicConfig)
	return s.Containers.Vpp.VppInstance
}

func QuicHandshakeTimeoutMWTest(s *NoTopoSuite) {
	vpp := quicTimeoutSetup(s)
	// Keep the destination port bound throughout the test. A silent UDP peer
	// must not turn the QUIC timeout into an ICMP port-unreachable failure.
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(s.HostAddr())})
	AssertNil(err)
	defer sink.Close()
	uri := "quic://" + sink.LocalAddr().String()
	baseline := quicReadCleanupCounts(vpp.Vppctl("show quic verbose"))
	AssertEqual(2, len(baseline.ContextsPerThread))
	AssertEqual(uint64(0), baseline.EngineConnections)
	AssertEqual(uint64(0), baseline.EngineStreams)
	checkCleanup := quicCleanupCheck(8*time.Second, vpp)
	sessions := vpp.Vppctl("show session")
	cryptoContexts := vpp.Vppctl("show quic crypto context")

	pending := baseline
	pending.ContextsPerThread = append([]uint64(nil), baseline.ContextsPerThread...)
	pending.ContextsPerThread[1]++
	pending.EngineConnections++
	pending.TxTimers++
	for range 2 {
		result := make(chan string, 1)
		go func() { result <- vpp.Vppctl("test tls client uri " + uri) }()
		var output string
		Eventually(func() quicCleanupCounts {
			output = vpp.Vppctl("show quic verbose")
			return quicReadCleanupCounts(output)
		}, 2*time.Second, 50*time.Millisecond).Should(Equal(pending),
			"expected a worker-owned engine connection and TX timer before handshake expiry")
		AssertContains(output, "conn state HANDSHAKE: 1")
		AssertNil(sink.SetReadDeadline(time.Now().Add(2 * time.Second)))
		packet := make([]byte, 2048)
		n, _, err := sink.ReadFromUDP(packet)
		AssertNil(err)
		Expect(n).To(BeNumerically(">=", 1200), "the silent peer must receive a QUIC Initial")

		Eventually(result, 12*time.Second).Should(Receive(&output))
		Log(output)
		AssertContains(output, "connect error failed tls handshake")
		AssertNotContains(output, "timeout", "the TLS test application's watchdog must not expire")
		checkCleanup()
		Eventually(func() string { return vpp.Vppctl("show session") },
			2*time.Second, 100*time.Millisecond).Should(Equal(sessions))
		AssertEqual(cryptoContexts, vpp.Vppctl("show quic crypto context"),
			"handshake timeout must release the client's crypto context")
	}
}

// Keep the socket alive while making the peer disappear in both directions.
// This suppresses QUIC close packets as well as ordinary traffic.
type quicDropPacketConn struct {
	net.PacketConn
	drop atomic.Bool
}

func (c *quicDropPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil || !c.drop.Load() {
			return n, addr, err
		}
	}
}

func (c *quicDropPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.drop.Load() {
		return len(p), nil
	}
	return c.PacketConn.WriteTo(p, addr)
}

func QuicIdleTimeoutMWTest(s *NoTopoSuite) {
	vpp := quicTimeoutSetup(s)
	address := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	remoteAddr, err := net.ResolveUDPAddr("udp4", address)
	AssertNil(err)
	AssertContains(vpp.Vppctl("test tls server alpn-proto1 3 uri quic://"+address), "server started")
	baseline := quicReadCleanupCounts(vpp.Vppctl("show quic verbose"))
	AssertEqual(2, len(baseline.ContextsPerThread))
	checkCleanup := quicCleanupCheck(8*time.Second, vpp)
	sessions := vpp.Vppctl("show session")
	cryptoContexts := vpp.Vppctl("show quic crypto context")
	live := baseline
	live.ContextsPerThread = append([]uint64(nil), baseline.ContextsPerThread...)
	live.ContextsPerThread[1] += 2 // connection and stream
	live.EngineConnections++
	live.EngineStreams++
	live.TxTimers++

	const payload = "keep this stream open until the connection times out"
	for cycle, drop := range []bool{false, true} {
		func() {
			socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(s.HostAddr())})
			AssertNil(err)
			defer socket.Close()
			peer := &quicDropPacketConn{PacketConn: socket}
			transport := &quic.Transport{Conn: peer}
			defer transport.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := transport.Dial(ctx, remoteAddr,
				&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}},
				&quic.Config{Versions: []quic.Version{quic.Version1},
					HandshakeIdleTimeout: 10 * time.Second, MaxIdleTimeout: 30 * time.Second,
					KeepAlivePeriod: 0})
			AssertNil(err)
			defer conn.CloseWithError(0, "test complete")
			stream, err := conn.OpenStream()
			AssertNil(err)
			_, err = stream.Write([]byte(payload))
			AssertNil(err)
			Eventually(func() string { return vpp.Vppctl("show test tls server") },
				2*time.Second, 100*time.Millisecond).
				Should(MatchRegexp(`(?m)^received bytes ` + strconv.Itoa((cycle+1)*len(payload)) + `\r?$`))
			var output string
			Eventually(func() quicCleanupCounts {
				output = vpp.Vppctl("show quic verbose")
				return quicReadCleanupCounts(output)
			}, 2*time.Second, 50*time.Millisecond).Should(Equal(live),
				"expected a live worker-owned connection, open stream and TX timer")
			AssertContains(output, "conn state READY: 1")
			AssertNil(context.Cause(conn.Context()), "peer must remain connected until the timeout scenario starts")
			Log("waiting for QUIC idle timeout, silently dropping peer packets: %t", drop)
			peer.drop.Store(drop)

			// Neither the stream nor its parent is closed by the test until all
			// VPP resources have returned to baseline through timer expiry.
			checkCleanup()
			Eventually(conn.Context().Done(), 8*time.Second).Should(BeClosed())
			Expect(context.Cause(conn.Context())).To(BeAssignableToTypeOf(&quic.IdleTimeoutError{}))
			Eventually(func() string { return vpp.Vppctl("show session") },
				2*time.Second, 100*time.Millisecond).Should(Equal(sessions))
			AssertEqual(cryptoContexts, vpp.Vppctl("show quic crypto context"),
				"idle timeout must retain only the listener's crypto context reference")
		}()
	}
}

func QuicRxDatagramSizeTest(s *NoTopoSuite) {
	const maxPacketSize = 1280 // QUIC_MAX_PACKET_SIZE in quic/quic.h.
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := net.JoinHostPort(s.VppAddr(), s.Ports.Http)
	o := vpp.Vppctl("test tls server alpn-proto1 3 uri quic://" + serverAddress)
	Log(o)
	AssertContains(o, "server started")
	checkCleanup := quicCleanupCheck(5*time.Second, vpp)

	counterPattern := regexp.MustCompile(`(?m)^\s*(\d+)\s+quic-input\s+quic RX datagrams too large\s+error\s*$`)
	oversizedDatagrams := func() int {
		total := 0
		for _, match := range counterPattern.FindAllStringSubmatch(vpp.Vppctl("show errors"), -1) {
			count, err := strconv.Atoi(match[1])
			AssertNil(err)
			total += count
		}
		return total
	}
	AssertEqual(0, oversizedDatagrams())

	remoteAddr, err := net.ResolveUDPAddr("udp4", serverAddress)
	AssertNil(err)
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(s.HostAddr())})
	AssertNil(err)
	defer socket.Close()

	// Stay within the IP MTU to exercise the QUIC guard without fragmentation.
	oversizedSizes := []int{maxPacketSize + 1, 1472, maxPacketSize + 1}
	for _, size := range oversizedSizes {
		n, err := socket.WriteToUDP(make([]byte, size), remoteAddr)
		AssertNil(err)
		AssertEqual(size, n)
	}
	Eventually(oversizedDatagrams, 5*time.Second, 100*time.Millisecond).
		Should(Equal(len(oversizedSizes)), "oversized UDP datagrams were not counted")
	o = vpp.Vppctl("show quic verbose")
	AssertContains(o, "connections without engine: 1")
	AssertContains(o, "conn state OPENED: 1")
	AssertContains(o, "active timers: ACCEPT 1 TX 0")

	// Reuse the same UDP flow to verify the rejected datagrams were consumed and
	// a valid Initial datagram exactly at the size limit is still accepted.
	transport := quic.Transport{Conn: socket}
	defer transport.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := transport.Dial(ctx, remoteAddr,
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}, SessionTicketsDisabled: true},
		&quic.Config{
			Versions:                []quic.Version{quic.Version1},
			InitialPacketSize:       maxPacketSize,
			DisablePathMTUDiscovery: true,
		})
	AssertNil(err)
	defer conn.CloseWithError(0, "test complete")
	Eventually(func() string {
		return vpp.Vppctl("show test tls server")
	}, 5*time.Second, 100*time.Millisecond).Should(ContainSubstring("accepted connections 1"))
	AssertEqual(len(oversizedSizes), oversizedDatagrams())
	Log(vpp.Vppctl("show errors"))
	AssertNil(conn.CloseWithError(0, "test complete"))
	checkCleanup()
}

func QuicCryptoContextTest(s *NoTopoSuite) {
	vpp := s.Containers.Vpp.VppInstance
	Log(vpp.Vppctl("show quic"))
	serverAddress := s.Interfaces.Tap.Ip4AddressString() + ":" + s.Ports.Http
	Log(vpp.Vppctl("test tls server uri quic://" + serverAddress))
	o := vpp.Vppctl("show quic crypto context")
	Log(o)
	AssertContains(o, "[0][test_tls_server n_sub: 1, ckpair: 1]")
	AssertNotContains(o, "[verify: ")
	AssertNotContains(o, "[tls_profile: ")

	// add second listener which should use same quic crypto context
	serverAddress2 := s.Interfaces.Tap.Ip4AddressString() + ":" + s.Ports.NginxServer
	Log(vpp.Vppctl("test tls server use-last-ckpair uri quic://" + serverAddress2))
	o = vpp.Vppctl("show quic crypto context")
	Log(o)
	AssertContains(o, "[0][test_tls_server n_sub: 2, ckpair: 1]")

	// add third listener with alpn proto set which should use new quic crypto context
	serverAddress3 := s.Interfaces.Tap.Ip4AddressString() + ":" + s.Ports.CutThru
	Log(vpp.Vppctl("test tls server use-last-ckpair alpn-proto1 3 uri quic://" + serverAddress3))
	o = vpp.Vppctl("show quic crypto context")
	Log(o)
	AssertContains(o, "[0][test_tls_server n_sub: 2, ckpair: 1]")
	AssertContains(o, "[1][test_tls_server n_sub: 1, ckpair: 1]")

	// add fourth listener with tls profile which should use new quic crypto context
	o = vpp.Vppctl("app crypto add tls-profile app test_tls_server " +
		"ciphersuites TLS_AES_256_GCM_SHA384")
	Log(o)
	AssertNotContains(o, "error")
	AssertContains(o, "profile 0")
	serverAddress4 := s.Interfaces.Tap.Ip4AddressString() + ":" + s.Ports.NginxServerSsl
	Log(vpp.Vppctl("test tls server profile-index 0 uri quic://" + serverAddress4))
	o = vpp.Vppctl("show quic crypto context")
	Log(o)
	AssertContains(o, "[0][test_tls_server n_sub: 2, ckpair: 1]")
	AssertContains(o, "[1][test_tls_server n_sub: 1, ckpair: 1]")
	AssertContains(o, "[2][test_tls_server n_sub: 1, ckpair: 2][tls_profile: 0]")
	checkCleanup := quicCleanupCheck(5*time.Second, vpp)

	// start anonther app which should use it own quic crypto context
	serverAddress5 := s.Interfaces.Tap.Ip4AddressString() + ":" + s.Ports.NginxHttp3
	Log(vpp.Vppctl("vperf server fifo-size 8k uri quic://" + serverAddress5))
	o = vpp.Vppctl("show quic crypto context")
	Log(o)
	AssertContains(o, "[3][vperf_srv_builtin n_sub: 1")

	// remove app to test cleanup
	Log(vpp.Vppctl("vperf server stop"))
	checkCleanup()
	o = vpp.Vppctl("show quic crypto context")
	Log(o)
	AssertNotContains(o, "[3][vperf_srv_builtin n_sub: 1")
	AssertContains(o, "[0][test_tls_server n_sub: 2, ckpair: 1]")
	AssertContains(o, "[1][test_tls_server n_sub: 1, ckpair: 1]")
	AssertContains(o, "[2][test_tls_server n_sub: 1, ckpair: 2][tls_profile: 0]")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(
		ctx,
		serverAddress3,
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}, SessionTicketsDisabled: true},
		&quic.Config{},
	)
	AssertNil(err)
	defer conn.CloseWithError(0, "test complete")
	o = vpp.Vppctl("show session proto quic state ready verbose 2")
	Log(o)
	AssertContains(o, "1 sessions matched filter")
	AssertContains(o, "alpn-selected: h3")
	AssertContains(o, "crctx: 1")
	AssertNil(conn.CloseWithError(0, "test complete"))
	checkCleanup()
}

func quicBuiltinVperf(s *QuicSuite, uni bool) {
	expr := `(\d+\.\d)-(\d+.\d)\s+(\d+\.\d+)[KMG]\s+0\s+\d+\.\d+[KMG]b/s\s+(\d?\.\d+)ms`
	if uni {
		expr = `(\d+\.\d)-(\d+.\d)\s+(\d+\.\d+)[KMG]\s+(\d+\.\d+)[KMG]\s+\d+\.\d+[KMG]b/s\s+(\d?\.\d+)ms`
	}
	regex := regexp.MustCompile(expr)
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	Log(serverVpp.Vppctl("vperf server " +
		" uri quic://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1))
	checkCleanup := quicCleanupCheck(5*time.Second, clientVpp, serverVpp)

	cmd := "vperf client run-time 30 report-interval "
	if uni {
		cmd += "echo-bytes "
	}
	cmd += "uri quic://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1

	o := clientVpp.Vppctl(cmd)
	Log(o)
	if regex.MatchString(o) {
		matches := regex.FindAllStringSubmatch(o, -1)
		// check if all intervals have non-zero TX bytes
		AssertEqual(30, len(matches))
	} else {
		AssertEmpty("invalid vperf client output")
	}
	checkCleanup()
}

func QuicBuiltinVperfZeroCopyTest(s *QuicSuite) {
	quicBuiltinVperf(s, false)
}

func QuicBuiltinVperfBidirectionalZeroCopyTest(s *QuicSuite) {
	quicBuiltinVperf(s, true)
}

func QuicBuiltinVperfTest(s *QuicSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	Log(serverVpp.Vppctl("vperf server " +
		" uri quic://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1))
	checkCleanup := quicCleanupCheck(5*time.Second, clientVpp, serverVpp)

	cmd := "vperf client test-bytes bytes 8388601 "
	cmd += "uri quic://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1

	o := clientVpp.Vppctl(cmd)
	Log(o)
	AssertNotContains(o, "failed")
	checkCleanup()
}

func QuicBuiltinVperfBidirectionalTest(s *QuicSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	Log(serverVpp.Vppctl("vperf server " +
		" uri quic://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1))
	checkCleanup := quicCleanupCheck(5*time.Second, clientVpp, serverVpp)

	cmd := "vperf client echo-bytes test-bytes bytes 8388608 "
	cmd += "uri quic://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1

	o := clientVpp.Vppctl(cmd)
	Log(o)
	AssertNotContains(o, "failed")
	checkCleanup()
}

func QuicCpsMWTest(s *QuicSuite) {
	var memoryConfig Stanza
	memoryConfig.NewStanza("memory").Append("main-heap-size 2G").Close()
	var quicConfig Stanza
	quicConfig.NewStanza("quic").Append("fifo-size 4k").Append("first-segment-size 134217728").Close()
	s.CpusPerVppContainer = 2
	s.SetupTest(memoryConfig, quicConfig)

	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	Log(serverVpp.Vppctl("vperf server fifo-size 4k" +
		" uri quic://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1))
	checkCleanup := quicCleanupCheck(35*time.Second, clientVpp, serverVpp)

	// syn-timeout must be less than quic connection timeout (30 seconds)
	o := clientVpp.Vppctl("vperf client nclients 10000 bytes 64 syn-timeout 27 fifo-size 4k" +
		" uri quic://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)
	Log(o)
	checkCleanup()
	Log(serverVpp.Vppctl("show quic"))
	Log(clientVpp.Vppctl("show quic"))
	Log(serverVpp.Vppctl("show quic crypto context"))
	Log(clientVpp.Vppctl("show quic crypto context"))
	Log(serverVpp.Vppctl("show error"))
	Log(clientVpp.Vppctl("show error"))
}

func QuicReorderTest(s *QuicSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance
	clientVpp.Vppctl("set nsim poll-main-thread delay 0.1 ms bandwidth 10 gbps packet-size 1460 packets-per-drop 100 packets-per-reorder 5")
	clientVpp.Vppctl("nsim output-feature enable-disable " + s.Interfaces.Client.VppName())
	Log(clientVpp.Vppctl("show nsim"))

	serverVpp.Vppctl("set nsim poll-main-thread delay 0.1 ms bandwidth 10 gbps packet-size 1460 packets-per-drop 100 packets-per-reorder 5")
	serverVpp.Vppctl("nsim output-feature enable-disable " + s.Interfaces.Server.VppName())
	Log(serverVpp.Vppctl("show nsim"))

	quicBuiltinVperf(s, true)
	Log(serverVpp.Vppctl("show session verbose 2"))
	Log(clientVpp.Vppctl("show session verbose 2"))
	Log(serverVpp.Vppctl("show error"))
	Log(clientVpp.Vppctl("show error"))
}
