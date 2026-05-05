package hst

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	tcpharness "fd.io/hs-test/infra/tcpharness"
	. "github.com/onsi/ginkgo/v2"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

type HsiClientResult struct {
	Output string
	Err    error
}

func runInNetns(netNs string, fn func() (string, error)) (string, error) {
	if netNs == "" {
		return fn()
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	orig, err := netns.Get()
	if err != nil {
		return "", err
	}
	defer orig.Close()

	target, err := netns.GetFromName(netNs)
	if err != nil {
		return "", err
	}
	defer target.Close()

	if err := netns.Set(target); err != nil {
		return "", err
	}
	defer func() {
		if restoreErr := netns.Set(orig); restoreErr != nil {
			Log("failed to restore netns: %v", restoreErr)
		}
	}()

	return fn()
}

func udpNetwork(addr string) string {
	if strings.Contains(addr, ":") {
		return "udp6"
	}
	return "udp4"
}

func tcpNetwork(addr string) string {
	if strings.Contains(addr, ":") {
		return "tcp6"
	}
	return "tcp4"
}

func hsiNetAddr(addr string, port uint16) string {
	return net.JoinHostPort(addr, strconv.Itoa(int(port)))
}

func hsiUdpDial(addr string, port uint16) (*net.UDPConn, []byte, error) {
	raddr, err := net.ResolveUDPAddr(udpNetwork(addr), hsiNetAddr(addr, port))
	if err != nil {
		return nil, nil, err
	}
	conn, err := net.DialUDP(udpNetwork(addr), nil, raddr)
	if err != nil {
		return nil, nil, err
	}
	return conn, make([]byte, 2048), nil
}

func StartHsiUdpEchoClient(addr string, port uint16, netNs string, pause time.Duration,
	payloads ...string) <-chan HsiClientResult {
	finished := make(chan HsiClientResult, 1)
	go func() {
		defer GinkgoRecover()
		output, err := runInNetns(netNs, func() (string, error) {
			if len(payloads) == 0 {
				return "", fmt.Errorf("missing UDP echo payload")
			}

			conn, buf, err := hsiUdpDial(addr, port)
			if err != nil {
				return "", err
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				return "", err
			}

			for _, payload := range payloads[:len(payloads)-1] {
				if _, err := conn.Write([]byte(payload)); err != nil {
					return "", err
				}
				time.Sleep(pause)
			}

			want := []byte(payloads[len(payloads)-1])
			if _, err := conn.Write(want); err != nil {
				return "", err
			}

			var output strings.Builder
			for {
				n, err := conn.Read(buf)
				if err != nil {
					return output.String(), err
				}
				reply := append([]byte(nil), buf[:n]...)
				output.WriteString(string(reply))
				output.WriteByte('\n')
				if bytes.Equal(reply, want) {
					break
				}
			}
			return output.String(), nil
		})
		finished <- HsiClientResult{Output: output, Err: err}
	}()
	return finished
}

func SendHsiUdpDatagrams(addr string, port uint16, netNs string, pause time.Duration,
	payloads ...string) <-chan HsiClientResult {
	finished := make(chan HsiClientResult, 1)
	go func() {
		defer GinkgoRecover()
		output, err := runInNetns(netNs, func() (string, error) {
			conn, _, err := hsiUdpDial(addr, port)
			if err != nil {
				return "", err
			}
			defer conn.Close()

			for _, payload := range payloads {
				if _, err := conn.Write([]byte(payload)); err != nil {
					return "", err
				}
				if pause > 0 {
					time.Sleep(pause)
				}
			}
			return "", nil
		})
		finished <- HsiClientResult{Output: output, Err: err}
	}()
	return finished
}

func HsiTempSignalPaths() (string, string) {
	ready, err := os.CreateTemp("", "hsi-ready-*")
	AssertNil(err)
	readyPath := ready.Name()
	AssertNil(ready.Close())
	AssertNil(os.Remove(readyPath))

	signal, err := os.CreateTemp("", "hsi-signal-*")
	AssertNil(err)
	signalPath := signal.Name()
	AssertNil(signal.Close())
	AssertNil(os.Remove(signalPath))

	return readyPath, signalPath
}

func WaitForFile(path string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	AssertFail("timed out waiting for %s", path)
}

func waitForSignal(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s", path)
}

func readHsiHTTPResponse(reader *bufio.Reader) ([]byte, error) {
	var response bytes.Buffer
	contentLength := 0

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return response.Bytes(), err
		}
		response.WriteString(line)
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(trimmed), "content-length:") {
			fields := strings.SplitN(trimmed, ":", 2)
			if n, err := strconv.Atoi(strings.TrimSpace(fields[1])); err == nil {
				contentLength = n
			}
		}
		if trimmed == "" {
			break
		}
	}

	if contentLength == 0 {
		return response.Bytes(), nil
	}

	body := make([]byte, contentLength)
	if _, err := io.ReadFull(reader, body); err != nil {
		return response.Bytes(), err
	}
	response.Write(body)
	return response.Bytes(), nil
}

func writeReady(path string, port int) error {
	return os.WriteFile(path, []byte(strconv.Itoa(port)), 0644)
}

func hsiTcpClientConnect(addr string, port uint16) (*net.TCPConn, *bufio.Reader, error) {
	taddr, err := net.ResolveTCPAddr(tcpNetwork(addr), hsiNetAddr(addr, port))
	if err != nil {
		return nil, nil, err
	}
	conn, err := net.DialTCP(tcpNetwork(addr), nil, taddr)
	if err != nil {
		return nil, nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		conn.Close()
		return nil, nil, err
	}
	return conn, bufio.NewReader(conn), nil
}

func StartHsiTcpHalfCloseClient(addr string, port uint16, netNs, readyPath,
	signalPath string) <-chan HsiClientResult {
	finished := make(chan HsiClientResult, 1)
	go func() {
		defer GinkgoRecover()
		output, err := runInNetns(netNs, func() (string, error) {
			conn, reader, err := hsiTcpClientConnect(addr, port)
			if err != nil {
				return "", err
			}
			defer conn.Close()

			var output bytes.Buffer
			if _, err := conn.Write([]byte("GET /64B HTTP/1.1\r\nHost: hsi\r\nConnection: keep-alive\r\n\r\n")); err != nil {
				return output.String(), err
			}
			response, err := readHsiHTTPResponse(reader)
			if err != nil {
				return output.String(), err
			}
			output.Write(response)

			local := conn.LocalAddr().(*net.TCPAddr)
			if err := writeReady(readyPath, local.Port); err != nil {
				return output.String(), err
			}
			if err := waitForSignal(signalPath, 10*time.Second); err != nil {
				return output.String(), err
			}

			if _, err := conn.Write([]byte("GET /64B HTTP/1.1\r\nHost: hsi\r\nConnection: close\r\n\r\n")); err != nil {
				return output.String(), err
			}
			if err := conn.CloseWrite(); err != nil {
				return output.String(), err
			}
			for {
				buf := make([]byte, 4096)
				n, err := reader.Read(buf)
				if n > 0 {
					output.Write(buf[:n])
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					return output.String(), err
				}
			}
			if !bytes.Contains(output.Bytes(), []byte("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")) {
				return output.String(), fmt.Errorf("expected 64B response body")
			}
			return output.String(), nil
		})
		finished <- HsiClientResult{Output: output, Err: err}
	}()
	return finished
}

func StartHsiTcpFinReplayClient(addr string, port uint16, netNs, ifName, readyPath,
	signalPath string, replayDelay time.Duration, replayCount int) <-chan HsiClientResult {
	finished := make(chan HsiClientResult, 1)
	go func() {
		defer GinkgoRecover()
		output, err := runInNetns(netNs, func() (string, error) {
			conn, reader, err := hsiTcpClientConnect(addr, port)
			if err != nil {
				return "", err
			}
			defer conn.Close()

			var output bytes.Buffer
			if _, err := conn.Write([]byte("GET /64B HTTP/1.1\r\nHost: hsi\r\nConnection: keep-alive\r\n\r\n")); err != nil {
				return output.String(), err
			}
			response, err := readHsiHTTPResponse(reader)
			if err != nil {
				return output.String(), err
			}
			output.Write(response)

			local := conn.LocalAddr().(*net.TCPAddr)
			if err := writeReady(readyPath, local.Port); err != nil {
				return output.String(), err
			}
			if err := waitForSignal(signalPath, 10*time.Second); err != nil {
				return output.String(), err
			}

			dst := net.ParseIP(addr)
			src := local.IP.To4()
			if src == nil || src.IsUnspecified() {
				src, err = tcpharness.IPv4AddrOnInterface(ifName)
				if err != nil {
					return output.String(), err
				}
			}
			fd, err := tcpharness.OpenIPv4PacketSocket(ifName)
			if err != nil {
				return output.String(), err
			}
			defer unix.Close(fd)

			done := make(chan struct{})
			finCh := make(chan []byte, 1)
			defer close(done)
			go tcpharness.CaptureIPv4TCPFin(fd, src, dst, uint16(local.Port), port, done, finCh)

			if _, err := conn.Write([]byte("GET /64B HTTP/1.1\r\nHost: hsi\r\nConnection: close\r\n\r\n")); err != nil {
				return output.String(), err
			}
			if err := conn.CloseWrite(); err != nil {
				return output.String(), err
			}

			select {
			case fin := <-finCh:
				time.Sleep(replayDelay)
				for i := 0; i < replayCount; i++ {
					if err := tcpharness.SendIPv4RawPacket(fin, dst); err != nil {
						return output.String(), err
					}
				}
			case <-time.After(2 * time.Second):
				return output.String(), fmt.Errorf("timed out capturing FIN")
			}

			for {
				buf := make([]byte, 4096)
				n, err := reader.Read(buf)
				if n > 0 {
					output.Write(buf[:n])
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					return output.String(), err
				}
			}
			if !bytes.Contains(output.Bytes(), []byte("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")) {
				return output.String(), fmt.Errorf("expected 64B response body")
			}
			return output.String(), nil
		})
		finished <- HsiClientResult{Output: output, Err: err}
	}()
	return finished
}

func StartHsiTcpInvalidRstClient(addr string, port uint16, netNs, readyPath,
	signalPath string) <-chan HsiClientResult {
	finished := make(chan HsiClientResult, 1)
	go func() {
		defer GinkgoRecover()
		output, err := runInNetns(netNs, func() (string, error) {
			conn, reader, err := hsiTcpClientConnect(addr, port)
			if err != nil {
				return "", err
			}
			defer conn.Close()

			var output bytes.Buffer
			if _, err := conn.Write([]byte("GET /64B HTTP/1.1\r\nHost: hsi\r\nConnection: keep-alive\r\n\r\n")); err != nil {
				return output.String(), err
			}
			response, err := readHsiHTTPResponse(reader)
			if err != nil {
				return output.String(), err
			}
			output.Write(response)

			local := conn.LocalAddr().(*net.TCPAddr)
			if err := writeReady(readyPath, local.Port); err != nil {
				return output.String(), err
			}
			if err := waitForSignal(signalPath, 10*time.Second); err != nil {
				return output.String(), err
			}

			dst := net.ParseIP(addr)
			for _, spec := range []struct {
				seq   uint32
				ack   uint32
				flags uint8
			}{
				{flags: 0x02 | 0x04},                  // SYN+RST
				{seq: 1, flags: 0x04},                 // out-of-window RST
				{ack: ^uint32(0), flags: 0x10 | 0x04}, // impossible ACK-bearing RST
			} {
				packet, err := tcpharness.BuildIPv4TCPControl(local.IP, dst, uint16(local.Port),
					port, spec.seq, spec.ack, spec.flags)
				if err != nil {
					return output.String(), err
				}
				if err := tcpharness.SendIPv4RawPacket(packet, dst); err != nil {
					return output.String(), err
				}
			}
			time.Sleep(200 * time.Millisecond)

			if _, err := conn.Write([]byte("GET /64B HTTP/1.1\r\nHost: hsi\r\nConnection: close\r\n\r\n")); err != nil {
				return output.String(), err
			}
			for {
				buf := make([]byte, 4096)
				n, err := reader.Read(buf)
				if n > 0 {
					output.Write(buf[:n])
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					return output.String(), err
				}
			}
			if !bytes.Contains(output.Bytes(), []byte("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")) {
				return output.String(), fmt.Errorf("expected 64B response body")
			}
			return output.String(), nil
		})
		finished <- HsiClientResult{Output: output, Err: err}
	}()
	return finished
}

func MakeProxyLiteUploadFile() string {
	uploadFile, err := os.CreateTemp("", "hsi-proxy-lite-upload-*")
	AssertNil(err)
	_, err = uploadFile.Write(bytes.Repeat([]byte("0123456789abcdef"), 64*1024))
	AssertNil(err)
	AssertNil(uploadFile.Close())
	return uploadFile.Name()
}
