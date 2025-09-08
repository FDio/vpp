package hst

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

type CapsuleParseError struct {
	Err error
}

func (e *CapsuleParseError) Error() string {
	return e.Err.Error()
}

type ConnectUdpClient struct {
	log     bool
	suite   *HstSuite
	timeout time.Duration
	Conn    net.Conn
}

func (s *HstSuite) NewConnectUdpClient(timeout time.Duration, log bool) *ConnectUdpClient {
	client := &ConnectUdpClient{log: log, suite: s, timeout: timeout}
	return client
}

func writeConnectUdpReq(target string) []byte {
	var b bytes.Buffer

	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\n", target)
	u, _ := url.Parse(target)
	fmt.Fprintf(&b, "Host: %s\r\n", u.Host)
	fmt.Fprintf(&b, "User-Agent: hs-test\r\n")
	fmt.Fprintf(&b, "Connection: Upgrade\r\n")
	fmt.Fprintf(&b, "Upgrade: connect-udp\r\n")
	fmt.Fprintf(&b, "Capsule-Protocol: ?1\r\n")
	io.WriteString(&b, "\r\n")

	return b.Bytes()
}

func (c *ConnectUdpClient) Dial(proxyAddress, targetUri string) error {
	req := writeConnectUdpReq(targetUri)
	conn, err := net.DialTimeout("tcp", proxyAddress, c.timeout)
	if err != nil {
		return err
	}

	if c.log {
		c.suite.Log("* Connected to proxy")
	}

	conn.SetDeadline(time.Now().Add(c.timeout))
	_, err = conn.Write(req)
	if err != nil {
		return err
	}

	r := bufio.NewReader(conn)
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		return err
	}

	if c.log {
		c.suite.Log(DumpHttpResp(resp, true))
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return errors.New("request failed: " + resp.Status)
	}
	if resp.Header.Get("Connection") != "upgrade" || resp.Header.Get("Upgrade") != "connect-udp" || resp.Header.Get("Capsule-Protocol") != "?1" {
		conn.Close()
		return errors.New("invalid response")
	}

	if c.log {
		c.suite.Log("* CONNECT-UDP tunnel established")
	}
	c.Conn = conn
	return nil
}

func (c *ConnectUdpClient) Close() error {
	return c.Conn.Close()
}

func (c *ConnectUdpClient) WriteCapsule(capsuleType http3.CapsuleType, payload []byte) error {
	err := c.Conn.SetWriteDeadline(time.Now().Add(c.timeout))
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	err = http3.WriteCapsule(&buf, capsuleType, payload)
	if err != nil {
		return err
	}
	_, err = c.Conn.Write(buf.Bytes())
	if err != nil {
		return err
	}
	return nil
}

func (c *ConnectUdpClient) WriteDgramCapsule(payload []byte) error {
	b := make([]byte, 0)
	b = quicvarint.Append(b, 0)
	b = append(b, payload...)
	return c.WriteCapsule(0, b)
}

func (c *ConnectUdpClient) ReadDgramCapsule() ([]byte, error) {
	err := c.Conn.SetReadDeadline(time.Now().Add(c.timeout))
	if err != nil {
		return nil, err
	}
	r := bufio.NewReader(c.Conn)
	capsuleType, payloadReader, err := http3.ParseCapsule(r)
	if err != nil {
		return nil, err
	}
	if capsuleType != 0 {
		return nil, &CapsuleParseError{errors.New("capsule type should be 0")}
	}
	b := make([]byte, 1024)
	n, err := payloadReader.Read(b)
	if err != nil {
		return nil, err
	}
	if n < 3 {
		return nil, &CapsuleParseError{errors.New("response payload too short")}
	}
	if b[0] != 0 {
		return nil, &CapsuleParseError{errors.New("context id should be 0")}
	}
	return b[1:n], nil
}
