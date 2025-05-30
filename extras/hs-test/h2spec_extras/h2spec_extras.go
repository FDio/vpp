package h2spec_extras

import (
	"fmt"
	"slices"

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
			conn.WriteData(streamID, false, []byte("AAAA"))
			err = VerifyWindowUpdate(conn, streamID, 4)
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
	return tg
}
