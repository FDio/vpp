package h2spec_extras

import (
	"fmt"

	"github.com/summerwind/h2spec/config"
	"github.com/summerwind/h2spec/spec"
	"golang.org/x/net/http2"
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

	return tg
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
		Requirement: "TODO",
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
			conn.WriteData(streamID, false, []byte("AAAA"))
			err = spec.VerifyEventType(conn, spec.EventWindowUpdateFrame)
			if err != nil {
				return err
			}
			conn.WriteData(streamID, false, []byte("BBBB"))
			err = spec.VerifyEventType(conn, spec.EventWindowUpdateFrame)
			if err != nil {
				return err
			}
			conn.WriteData(streamID, true, []byte("CCCC"))

			return spec.VerifyHeadersFrame(conn, streamID)
		},
	})
	return tg
}
