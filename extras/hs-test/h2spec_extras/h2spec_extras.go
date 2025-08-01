package h2spec_extras

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/summerwind/h2spec/config"
	"github.com/summerwind/h2spec/spec"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

var key = "extras"

func NewTestGroup(section string, name string) *spec.TestGroup {
	return &spec.TestGroup{
		Key:     key,
		Section: section,
		Name:    name,
	}
}

func Spec() *spec.TestGroup {
	tg := &spec.TestGroup{
		Key:  key,
		Name: "extras for HTTP/2 server",
	}

	tg.AddTestGroup(FlowControl())
	tg.AddTestGroup(ConnectMethod())
	tg.AddTestGroup(ExtendedConnectMethod())
	tg.AddTestGroup(PingAnomaly())

	return tg
}

func VerifyWindowUpdate(conn *spec.Conn, streamID, expectedIncrement uint32) error {
	actual, passed := conn.WaitEventByType(spec.EventWindowUpdateFrame)
	actualStr := actual.String()
	switch event := actual.(type) {
	case spec.WindowUpdateFrameEvent:
		actualStr = fmt.Sprintf("WINDOW_UPDATE Frame (stream_id:%d, increment:%d)", event.StreamID, event.Increment)
		passed = (event.StreamID == streamID) && (event.Increment == expectedIncrement)
	default:
		passed = false
	}

	if !passed {
		expected := []string{
			fmt.Sprintf("WINDOW_UPDATE Frame (stream_id:%d, increment:%d)", streamID, expectedIncrement),
		}

		return &spec.TestError{
			Expected: expected,
			Actual:   actualStr,
		}
	}
	return nil
}

func VerifyTunnelClosed(conn *spec.Conn) error {
	var streamClosed = false
	var lastEvent spec.Event
	for !conn.Closed {
		ev := conn.WaitEvent()
		lastEvent = ev
		switch event := ev.(type) {
		case spec.DataFrameEvent:
			if event.StreamEnded() {
				streamClosed = true
				goto done
			}
		case spec.TimeoutEvent:
			goto done
		}
	}
done:
	if !streamClosed {
		return &spec.TestError{
			Expected: []string{spec.ExpectedStreamClosed},
			Actual:   lastEvent.String(),
		}
	}
	return nil
}

func FlowControl() *spec.TestGroup {
	tg := NewTestGroup("1", "Flow control")
	tg.AddTestCase(&spec.TestCase{
		Desc:        "Sends a WINDOW_UPDATE frame on connection",
		Requirement: "The endpoint MUST NOT send a flow-controlled frame with a length that exceeds the space available.",
		Run: func(c *config.Config, conn *spec.Conn) error {
			var streamID uint32 = 1

			// turn off automatic connection window update
			conn.WindowUpdate = false

			err := conn.Handshake()
			if err != nil {
				return err
			}

			headers := spec.CommonHeaders(c)
			headers[2].Value = "/4kB"

			// consume most of the connection window
			for i := 0; i <= 14; i++ {
				hp := http2.HeadersFrameParam{
					StreamID:      streamID,
					EndStream:     true,
					EndHeaders:    true,
					BlockFragment: conn.EncodeHeaders(headers),
				}
				conn.WriteHeaders(hp)
				streamID += 2
				err := spec.VerifyEventType(conn, spec.EventDataFrame)
				if err != nil {
					return err
				}
			}

			hp := http2.HeadersFrameParam{
				StreamID:      streamID,
				EndStream:     true,
				EndHeaders:    true,
				BlockFragment: conn.EncodeHeaders(headers),
			}
			conn.WriteHeaders(hp)
			// verify reception of DATA frame
			err = spec.VerifyEventType(conn, spec.EventDataFrame)
			if err != nil {
				return err
			}

			// increment connection window
			conn.WriteWindowUpdate(0, 65535)

			// wait for DATA frame with rest of the content
			actual, passed := conn.WaitEventByType(spec.EventDataFrame)
			switch event := actual.(type) {
			case spec.DataFrameEvent:
				passed = event.Header().Length == 1
			default:
				passed = false
			}

			if !passed {
				expected := []string{
					fmt.Sprintf("DATA Frame (length:1, flags:0x00, stream_id:%d)", streamID),
				}

				return &spec.TestError{
					Expected: expected,
					Actual:   actual.String(),
				}
			}

			return nil
		},
	})

	tg.AddTestCase(&spec.TestCase{
		Desc:        "Receive a WINDOW_UPDATE frame on stream",
		Requirement: "The receiver of a frame sends a WINDOW_UPDATE frame as it consumes data and frees up space in flow-control windows.",
		Run: func(c *config.Config, conn *spec.Conn) error {
			var streamID uint32 = 1

			err := conn.Handshake()
			if err != nil {
				return err
			}

			headers := spec.CommonHeaders(c)
			headers[0].Value = "POST"
			headers = append(headers, spec.HeaderField("content-length", "12"))
			hp := http2.HeadersFrameParam{
				StreamID:      streamID,
				EndStream:     false,
				EndHeaders:    true,
				BlockFragment: conn.EncodeHeaders(headers),
			}
			conn.WriteHeaders(hp)
			// we send window update on stream when app read data from rx fifo, so send DATA frame and wait for WINDOW_UPDATE frame
			// first increment is bigger because half of the fifo size was reserved for headers
			conn.WriteData(streamID, false, []byte("AAAA"))
			err = VerifyWindowUpdate(conn, streamID, 4+conn.Settings[http2.SettingMaxHeaderListSize])
			if err != nil {
				return err
			}
			// test it again
			conn.WriteData(streamID, false, []byte("BBBBB"))
			err = VerifyWindowUpdate(conn, streamID, 5)
			if err != nil {
				return err
			}
			// we don't send stream window update if stream is half-closed, so HEADERS frame should be received
			conn.WriteData(streamID, true, []byte("CCC"))
			return spec.VerifyHeadersFrame(conn, streamID)
		},
	})
	return tg
}

func ConnectHeaders(c *config.Config) []hpack.HeaderField {

	return []hpack.HeaderField{
		spec.HeaderField(":method", "CONNECT"),
		spec.HeaderField(":authority", c.Path),
	}
}

func readTcpTunnel(conn *spec.Conn, streamID uint32) ([]byte, error) {
	actual, passed := conn.WaitEventByType(spec.EventDataFrame)
	switch event := actual.(type) {
	case spec.DataFrameEvent:
		passed = event.Header().StreamID == streamID
	default:
		passed = false
	}
	if !passed {
		return nil, &spec.TestError{
			Expected: []string{spec.EventDataFrame.String()},
			Actual:   actual.String(),
		}
	}
	df, _ := actual.(spec.DataFrameEvent)
	return df.Data(), nil
}

func ConnectMethod() *spec.TestGroup {
	tg := NewTestGroup("2", "CONNECT method")

	tg.AddTestCase(&spec.TestCase{
		Desc:        "Tunnel closed by target",
		Requirement: "A proxy that receives a TCP segment with the FIN bit set sends a DATA frame with the END_STREAM flag set.",
		Run: func(c *config.Config, conn *spec.Conn) error {
			var streamID uint32 = 1

			err := conn.Handshake()
			if err != nil {
				return err
			}

			headers := ConnectHeaders(c)
			hp := http2.HeadersFrameParam{
				StreamID:      streamID,
				EndStream:     false,
				EndHeaders:    true,
				BlockFragment: conn.EncodeHeaders(headers),
			}
			conn.WriteHeaders(hp)
			err = spec.VerifyHeadersFrame(conn, streamID)
			if err != nil {
				return err
			}

			// send http/1.0 so target will close connection when send response
			conn.WriteData(streamID, false, []byte("GET /index.html HTTP/1.0\r\n\r\n"))

			// wait for DATA frame with END_STREAM flag set
			err = VerifyTunnelClosed(conn)
			if err != nil {
				return err
			}

			// client is expected to send DATA frame with the END_STREAM flag set
			conn.WriteData(streamID, true, []byte(""))

			return nil
		},
	})

	tg.AddTestCase(&spec.TestCase{
		Desc:        "Tunnel closed by client (with attached data)",
		Requirement: "A proxy that receives a DATA frame with the END_STREAM flag set sends the attached data with the FIN bit set on the last TCP segment.",
		Run: func(c *config.Config, conn *spec.Conn) error {
			var streamID uint32 = 1

			err := conn.Handshake()
			if err != nil {
				return err
			}

			headers := ConnectHeaders(c)
			hp := http2.HeadersFrameParam{
				StreamID:      streamID,
				EndStream:     false,
				EndHeaders:    true,
				BlockFragment: conn.EncodeHeaders(headers),
			}
			conn.WriteHeaders(hp)
			err = spec.VerifyHeadersFrame(conn, streamID)
			if err != nil {
				return err
			}

			// close tunnel
			conn.WriteData(streamID, true, []byte("HEAD /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"))

			// wait for DATA frame with END_STREAM flag set
			err = VerifyTunnelClosed(conn)
			if err != nil {
				return err
			}

			return nil
		},
	})

	tg.AddTestCase(&spec.TestCase{
		Desc:        "Tunnel closed by client (empty DATA frame)",
		Requirement: "The final DATA frame could be empty.",
		Run: func(c *config.Config, conn *spec.Conn) error {
			var streamID uint32 = 1

			err := conn.Handshake()
			if err != nil {
				return err
			}

			headers := ConnectHeaders(c)
			hp := http2.HeadersFrameParam{
				StreamID:      streamID,
				EndStream:     false,
				EndHeaders:    true,
				BlockFragment: conn.EncodeHeaders(headers),
			}
			conn.WriteHeaders(hp)
			err = spec.VerifyHeadersFrame(conn, streamID)
			if err != nil {
				return err
			}

			conn.WriteData(streamID, false, []byte("HEAD /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"))

			// verify reception of response DATA frame
			err = spec.VerifyEventType(conn, spec.EventDataFrame)
			if err != nil {
				return err
			}

			// close tunnel
			conn.WriteData(streamID, true, []byte(""))

			// wait for DATA frame with END_STREAM flag set
			err = VerifyTunnelClosed(conn)
			if err != nil {
				return err
			}

			return nil
		},
	})

	tg.AddTestCase(&spec.TestCase{
		Desc:        "Multiple tunnels",
		Requirement: "In HTTP/2, the CONNECT method establishes a tunnel over a single HTTP/2 stream to a remote host, rather than converting the entire connection to a tunnel.",
		Run: func(c *config.Config, conn *spec.Conn) error {
			var streamID uint32 = 1

			err := conn.Handshake()
			if err != nil {
				return err
			}

			maxStreams, ok := conn.Settings[http2.SettingMaxConcurrentStreams]
			if !ok {
				return spec.ErrSkipped
			}

			for i := 0; i < int(maxStreams); i++ {
				headers := ConnectHeaders(c)
				hp := http2.HeadersFrameParam{
					StreamID:      streamID,
					EndStream:     false,
					EndHeaders:    true,
					BlockFragment: conn.EncodeHeaders(headers),
				}
				conn.WriteHeaders(hp)
				err = spec.VerifyHeadersFrame(conn, streamID)
				if err != nil {
					return err
				}

				streamID += 2
			}

			streamID = 1
			for i := 0; i < int(maxStreams); i++ {
				conn.WriteData(streamID, false, []byte("HEAD /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"))
				streamID += 2
			}

			var receivedResp []uint32
			for i := 0; i < int(maxStreams); i++ {
				actual, passed := conn.WaitEventByType(spec.EventDataFrame)
				switch event := actual.(type) {
				case spec.DataFrameEvent:
					passed = !slices.Contains(receivedResp, event.StreamID)
				default:
					passed = false
				}
				if !passed {
					expected := []string{
						"Receive one response per stream (tunnel)",
					}

					return &spec.TestError{
						Expected: expected,
						Actual:   actual.String(),
					}
				}
			}

			return nil
		},
	})

	tg.AddTestCase(&spec.TestCase{
		Desc:        "The \":scheme\" and \":path\" pseudo-header fields MUST be omitted.",
		Requirement: "A CONNECT request that does not conform to these restrictions is malformed.",
		Run: func(c *config.Config, conn *spec.Conn) error {
			var streamID uint32 = 1

			err := conn.Handshake()
			if err != nil {
				return err
			}

			headers := ConnectHeaders(c)
			headers = append(headers, spec.HeaderField(":scheme", "https"))
			headers = append(headers, spec.HeaderField(":path", "/"))
			hp := http2.HeadersFrameParam{
				StreamID:      streamID,
				EndStream:     false,
				EndHeaders:    true,
				BlockFragment: conn.EncodeHeaders(headers),
			}
			conn.WriteHeaders(hp)

			return spec.VerifyStreamError(conn, http2.ErrCodeProtocol)
		},
	})
	return tg
}

func ExtendedConnectMethod() *spec.TestGroup {
	tg := NewTestGroup("3", "Extended CONNECT method")

	tg.AddTestCase(&spec.TestCase{
		Desc:        "SETTINGS_ENABLE_CONNECT_PROTOCOL parameter with value 1 received.",
		Requirement: "Using a SETTINGS parameter to opt into an otherwise incompatible protocol change is a use of \"Extending HTTP/2\" defined by Section 5.5 of RFC9113.",
		Run: func(c *config.Config, conn *spec.Conn) error {

			err := conn.Handshake()
			if err != nil {
				return err
			}

			enabled, ok := conn.Settings[http2.SettingEnableConnectProtocol]
			if !ok {
				return &spec.TestError{
					Expected: []string{"SETTINGS_ENABLE_CONNECT_PROTOCOL received"},
					Actual:   "SETTINGS_ENABLE_CONNECT_PROTOCOL not received",
				}
			}
			if enabled != uint32(1) {
				return &spec.TestError{
					Expected: []string{"SETTINGS_ENABLE_CONNECT_PROTOCOL parameter with value 1 received"},
					Actual:   "SETTINGS_ENABLE_CONNECT_PROTOCOL parameter with value " + strconv.Itoa(int(enabled)) + " received",
				}
			}

			return nil
		},
	})

	tg.AddTestCase(&spec.TestCase{
		Desc:        "The \":scheme\" and \":path\" pseudo-header fields MUST be included.",
		Requirement: "A CONNECT request bearing the \":protocol\" pseudo-header that does not conform is malformed.",
		Run: func(c *config.Config, conn *spec.Conn) error {
			var streamID uint32 = 1

			err := conn.Handshake()
			if err != nil {
				return err
			}

			headers := ConnectHeaders(c)
			headers = append(headers, spec.HeaderField(":protocol", "connect-udp"))
			hp := http2.HeadersFrameParam{
				StreamID:      streamID,
				EndStream:     false,
				EndHeaders:    true,
				BlockFragment: conn.EncodeHeaders(headers),
			}
			conn.WriteHeaders(hp)

			return spec.VerifyStreamError(conn, http2.ErrCodeProtocol)
		},
	})

	tg.AddTestGroup(ConnectUdp())

	return tg
}

func ConnectUdpHeaders(c *config.Config) []hpack.HeaderField {

	headers := spec.CommonHeaders(c)
	headers[0].Value = "CONNECT"
	headers = append(headers, spec.HeaderField(":protocol", "connect-udp"))
	headers = append(headers, spec.HeaderField("capsule-protocol", "?1"))
	return headers
}

func writeCapsule(conn *spec.Conn, streamID uint32, endStream bool, payload []byte) error {
	b := make([]byte, 0)
	b = quicvarint.Append(b, 0)
	b = append(b, payload...)
	var capsule bytes.Buffer
	err := http3.WriteCapsule(&capsule, 0, b)
	if err != nil {
		return err
	}

	return conn.WriteData(streamID, endStream, capsule.Bytes())
}

func readCapsule(conn *spec.Conn, streamID uint32) ([]byte, error) {
	actual, passed := conn.WaitEventByType(spec.EventDataFrame)
	switch event := actual.(type) {
	case spec.DataFrameEvent:
		passed = event.Header().StreamID == streamID
	default:
		passed = false
	}
	if !passed {
		return nil, &spec.TestError{
			Expected: []string{spec.EventDataFrame.String()},
			Actual:   actual.String(),
		}
	}
	df, _ := actual.(spec.DataFrameEvent)
	r := bytes.NewReader(df.Data())
	capsuleType, payloadReader, err := http3.ParseCapsule(r)
	if err != nil {
		return nil, err
	}
	if capsuleType != 0 {
		return nil, errors.New("capsule type should be 0")
	}
	b := make([]byte, 1024)
	n, err := payloadReader.Read(b)
	if err != nil {
		return nil, err
	}
	if n < 3 {
		return nil, errors.New("response payload too short")
	}
	if b[0] != 0 {
		return nil, errors.New("context id should be 0")
	}
	return b[1:n], nil
}

func ConnectUdp() *spec.TestGroup {
	tg := NewTestGroup("3.1", "Proxying UDP in HTTP")

	tg.AddTestCase(&spec.TestCase{
		Desc:        "Tunneling UDP over HTTP/2",
		Requirement: "To initiate a UDP tunnel associated with a single HTTP stream, a client issues a request containing the \"connect-udp\" upgrade token. The target of the tunnel is indicated by the client to the UDP proxy via the \"target_host\" and \"target_port\" variables of the URI Template",
		Run: func(c *config.Config, conn *spec.Conn) error {
			var streamID uint32 = 1

			err := conn.Handshake()
			if err != nil {
				return err
			}

			headers := ConnectUdpHeaders(c)
			hp := http2.HeadersFrameParam{
				StreamID:      streamID,
				EndStream:     false,
				EndHeaders:    true,
				BlockFragment: conn.EncodeHeaders(headers),
			}
			conn.WriteHeaders(hp)
			// verify response headers
			actual, passed := conn.WaitEventByType(spec.EventHeadersFrame)
			switch event := actual.(type) {
			case spec.HeadersFrameEvent:
				passed = event.Header().StreamID == streamID
			default:
				passed = false
			}
			if !passed {
				expected := []string{
					fmt.Sprintf("DATA Frame (length:1, flags:0x00, stream_id:%d)", streamID),
				}

				return &spec.TestError{
					Expected: expected,
					Actual:   actual.String(),
				}
			}
			hf, _ := actual.(spec.HeadersFrameEvent)
			respHeaders := make([]hpack.HeaderField, 0, 256)
			decoder := hpack.NewDecoder(4096, func(f hpack.HeaderField) { respHeaders = append(respHeaders, f) })
			_, err = decoder.Write(hf.HeaderBlockFragment())
			if err != nil {
				return err
			}
			if !slices.Contains(respHeaders, spec.HeaderField("capsule-protocol", "?1")) {
				hs := ""
				for _, h := range respHeaders {
					hs += h.String() + "\n"
				}
				return &spec.TestError{
					Expected: []string{"\"capsule-protocol: ?1\" header received"},
					Actual:   hs,
				}
			}
			if !slices.Contains(respHeaders, spec.HeaderField(":status", "200")) {
				hs := ""
				for _, h := range respHeaders {
					hs += h.String() + "\n"
				}
				return &spec.TestError{
					Expected: []string{"\":status: 200\" header received"},
					Actual:   hs,
				}
			}
			for _, h := range respHeaders {
				if h.Name == "content-length" {
					return &spec.TestError{
						Expected: []string{"\"content-length\" header must not be used"},
						Actual:   h.String(),
					}
				}
			}

			// send and receive data over tunnel
			data := []byte("hello")
			err = writeCapsule(conn, streamID, false, data)
			if err != nil {
				return err
			}
			resp, err := readCapsule(conn, streamID)
			if err != nil {
				return err
			}
			if !bytes.Equal(data, resp) {
				return &spec.TestError{
					Expected: []string{"capsule payload: " + string(data)},
					Actual:   "capsule payload:" + string(resp),
				}
			}
			// try again
			err = writeCapsule(conn, streamID, false, data)
			if err != nil {
				return err
			}
			resp, err = readCapsule(conn, streamID)
			if err != nil {
				return err
			}
			if !bytes.Equal(data, resp) {
				return &spec.TestError{
					Expected: []string{"capsule payload: " + string(data)},
					Actual:   "capsule payload:" + string(resp),
				}
			}
			return nil
		},
	})

	tg.AddTestCase(&spec.TestCase{
		Desc:        "Multiple tunnels",
		Requirement: "In HTTP/2, the data stream of a given HTTP request consists of all bytes sent in DATA frames with the corresponding stream ID.",
		Run: func(c *config.Config, conn *spec.Conn) error {
			var streamID uint32 = 1

			err := conn.Handshake()
			if err != nil {
				return err
			}

			maxStreams, ok := conn.Settings[http2.SettingMaxConcurrentStreams]
			if !ok {
				return spec.ErrSkipped
			}

			for i := 0; i < int(maxStreams); i++ {
				headers := ConnectUdpHeaders(c)
				hp := http2.HeadersFrameParam{
					StreamID:      streamID,
					EndStream:     false,
					EndHeaders:    true,
					BlockFragment: conn.EncodeHeaders(headers),
				}
				conn.WriteHeaders(hp)
				err = spec.VerifyHeadersFrame(conn, streamID)
				if err != nil {
					return err
				}

				streamID += 2
			}

			streamID = 1
			data := []byte("hello")
			for i := 0; i < int(maxStreams); i++ {
				err = writeCapsule(conn, streamID, false, data)
				if err != nil {
					return err
				}
			}

			for i := 0; i < int(maxStreams); i++ {
				resp, err := readCapsule(conn, streamID)
				if err != nil {
					return err
				}
				if !bytes.Equal(data, resp) {
					return &spec.TestError{
						Expected: []string{"capsule payload: " + string(data)},
						Actual:   "capsule payload:" + string(resp),
					}
				}
			}

			return nil
		},
	})

	tg.AddTestCase(&spec.TestCase{
		Desc:        "Tunnel closed by client (with attached data)",
		Requirement: "A proxy that receives a DATA frame with the END_STREAM flag set sends the attached data and close UDP connection.",
		Run: func(c *config.Config, conn *spec.Conn) error {
			var streamID uint32 = 1

			err := conn.Handshake()
			if err != nil {
				return err
			}

			headers := ConnectUdpHeaders(c)
			hp := http2.HeadersFrameParam{
				StreamID:      streamID,
				EndStream:     false,
				EndHeaders:    true,
				BlockFragment: conn.EncodeHeaders(headers),
			}
			conn.WriteHeaders(hp)
			err = spec.VerifyHeadersFrame(conn, streamID)
			if err != nil {
				return err
			}

			// close tunnel
			data := []byte("hello")
			err = writeCapsule(conn, streamID, true, data)
			if err != nil {
				return err
			}

			// wait for DATA frame with END_STREAM flag set
			err = VerifyTunnelClosed(conn)
			if err != nil {
				return err
			}

			return nil
		},
	})

	tg.AddTestCase(&spec.TestCase{
		Desc:        "Tunnel closed by client (empty DATA frame)",
		Requirement: "The final DATA frame could be empty.",
		Run: func(c *config.Config, conn *spec.Conn) error {
			var streamID uint32 = 1

			err := conn.Handshake()
			if err != nil {
				return err
			}

			headers := ConnectUdpHeaders(c)
			hp := http2.HeadersFrameParam{
				StreamID:      streamID,
				EndStream:     false,
				EndHeaders:    true,
				BlockFragment: conn.EncodeHeaders(headers),
			}
			conn.WriteHeaders(hp)
			err = spec.VerifyHeadersFrame(conn, streamID)
			if err != nil {
				return err
			}

			// send and receive data over tunnel
			data := []byte("hello")
			err = writeCapsule(conn, streamID, false, data)
			if err != nil {
				return err
			}
			resp, err := readCapsule(conn, streamID)
			if err != nil {
				return err
			}
			if !bytes.Equal(data, resp) {
				return &spec.TestError{
					Expected: []string{"capsule payload: " + string(data)},
					Actual:   "capsule payload:" + string(resp),
				}
			}

			// close tunnel
			conn.WriteData(streamID, true, []byte(""))

			// wait for DATA frame with END_STREAM flag set
			err = VerifyTunnelClosed(conn)
			if err != nil {
				return err
			}

			return nil
		},
	})

	tg.AddTestCase(&spec.TestCase{
		Desc:        "CONNECT and CONNECT-UDP on single connection",
		Requirement: "One stream establish TCP tunnel and second UDP tunnel.",
		Run: func(c *config.Config, conn *spec.Conn) error {
			err := conn.Handshake()
			if err != nil {
				return err
			}

			var udpTunnelStreamID uint32 = 1
			var tcpTunnelStreamID uint32 = 3

			headers := ConnectUdpHeaders(c)
			hp := http2.HeadersFrameParam{
				StreamID:      udpTunnelStreamID,
				EndStream:     false,
				EndHeaders:    true,
				BlockFragment: conn.EncodeHeaders(headers),
			}
			conn.WriteHeaders(hp)
			err = spec.VerifyHeadersFrame(conn, udpTunnelStreamID)
			if err != nil {
				return err
			}

			pathSplit := strings.Split(c.Path, "/")
			path := fmt.Sprintf("%s:%s", pathSplit[4], pathSplit[5])
			headers = []hpack.HeaderField{
				spec.HeaderField(":method", "CONNECT"),
				spec.HeaderField(":authority", path),
			}
			hp = http2.HeadersFrameParam{
				StreamID:      tcpTunnelStreamID,
				EndStream:     false,
				EndHeaders:    true,
				BlockFragment: conn.EncodeHeaders(headers),
			}
			conn.WriteHeaders(hp)
			err = spec.VerifyHeadersFrame(conn, tcpTunnelStreamID)
			if err != nil {
				return err
			}

			// send and receive data over UDP tunnel
			udpData := []byte("hello UDP")
			err = writeCapsule(conn, udpTunnelStreamID, false, udpData)
			if err != nil {
				return err
			}
			udpResp, err := readCapsule(conn, udpTunnelStreamID)
			if err != nil {
				return err
			}
			if !bytes.Equal(udpData, udpResp) {
				return &spec.TestError{
					Expected: []string{"capsule payload: " + string(udpData)},
					Actual:   "capsule payload:" + string(udpResp),
				}
			}

			// send and receive data over TCP tunnel
			tcpData := []byte("hello TCP")
			conn.WriteData(tcpTunnelStreamID, false, tcpData)
			tcpResp, err := readTcpTunnel(conn, tcpTunnelStreamID)
			if !bytes.Equal(tcpData, tcpResp) {
				return &spec.TestError{
					Expected: []string{"payload: " + string(tcpData)},
					Actual:   "payload:" + string(tcpResp),
				}
			}

			// send and receive data over TCP tunnel
			conn.WriteData(tcpTunnelStreamID, false, tcpData)
			tcpResp, err = readTcpTunnel(conn, tcpTunnelStreamID)
			if !bytes.Equal(tcpData, tcpResp) {
				return &spec.TestError{
					Expected: []string{"payload: " + string(tcpData)},
					Actual:   "payload:" + string(tcpResp),
				}
			}

			// send and receive data over UDP tunnel
			err = writeCapsule(conn, udpTunnelStreamID, false, udpData)
			if err != nil {
				return err
			}
			udpResp, err = readCapsule(conn, udpTunnelStreamID)
			if err != nil {
				return err
			}
			if !bytes.Equal(udpData, udpResp) {
				return &spec.TestError{
					Expected: []string{"capsule payload: " + string(udpData)},
					Actual:   "capsule payload:" + string(udpResp),
				}
			}

			return nil
		},
	})

	return tg
}

func PingAnomaly() *spec.TestGroup {
	tg := NewTestGroup("4", "Data Leakage")
	tg.AddTestCase(&spec.TestCase{
		Desc:        "1-byte extra",
		Requirement: "The endpoint MUST terminate the connection with a connection error of type PROTOCOL_ERROR.",
		Run: func(c *config.Config, conn *spec.Conn) error {
			err := conn.Handshake()
			if err != nil {
				return err
			}
			conn.Send([]byte("\x00\x00\x08\x06\x00\x00\x00\x00\x00\x00\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF"))
			return spec.VerifyConnectionError(conn, http2.ErrCodeProtocol)
		},
	})
	return tg
}
