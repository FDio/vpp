package hst

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/edwarnicke/exechelper"
	. "github.com/onsi/ginkgo/v2"
)

const networkTopologyDir string = "topo-network/"
const containerTopologyDir string = "topo-containers/"
const HttpCapsuleTypeDatagram = uint64(0)
const iperfLogFileName = "iperf.log"
const redisLogFileName = "redis-server.log"
const h2loadLogFileName = "h2load.tsv"

type Stanza struct {
	content string
	pad     int
}

type ActionResult struct {
	Err       error
	Desc      string
	ErrOutput string
	StdOutput string
}

type JsonResult struct {
	Code      int
	Desc      string
	ErrOutput string
	StdOutput string
}

func AssertFileSize(f1, f2 string) error {
	fi1, err := os.Stat(f1)
	if err != nil {
		return err
	}

	fi2, err1 := os.Stat(f2)
	if err1 != nil {
		return err1
	}

	if fi1.Size() != fi2.Size() {
		return fmt.Errorf("file sizes differ (%d vs %d)", fi1.Size(), fi2.Size())
	}
	return nil
}

func (c *Stanza) NewStanza(name string) *Stanza {
	c.Append("\n" + name + " {")
	c.pad += 2
	return c
}

func (c *Stanza) Append(name string) *Stanza {
	c.content += strings.Repeat(" ", c.pad)
	c.content += name + "\n"
	return c
}

func (c *Stanza) Close() *Stanza {
	c.content += "}\n"
	c.pad -= 2
	return c
}

func (s *Stanza) ToString() string {
	return s.content
}

func (s *Stanza) SaveToFile(fileName string) error {
	fo, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer fo.Close()

	_, err = io.Copy(fo, strings.NewReader(s.content))
	return err
}

// NewHttpClient creates [http.Client] with disabled proxy and redirects.
func NewHttpClient(timeout time.Duration, enableHTTP2 bool) *http.Client {
	transport := http.DefaultTransport
	transport.(*http.Transport).Proxy = nil
	transport.(*http.Transport).DisableKeepAlives = true
	transport.(*http.Transport).ForceAttemptHTTP2 = enableHTTP2
	transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	return client
}

func DumpHttpResp(resp *http.Response, body bool) string {
	dump, err := httputil.DumpResponse(resp, body)
	if err != nil {
		return ""
	}
	return string(dump)
}

func TcpSendReceive(address, data string) (string, error) {
	conn, err := net.DialTimeout("tcp", address, time.Second*30)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	err = conn.SetDeadline(time.Now().Add(time.Second * 30))
	if err != nil {
		return "", err
	}
	_, err = conn.Write([]byte(data))
	if err != nil {
		return "", err
	}
	reply := make([]byte, 1024)
	_, err = conn.Read(reply)
	if err != nil {
		return "", err
	}
	return string(reply), nil
}

func TcpSendAndClose(address, data string) error {
	conn, err := net.DialTimeout("tcp", address, time.Second*30)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(data))
	if err != nil {
		return err
	}

	return nil
}

/*
RunCurlContainer execute curl command with given args.
Container with name "curl" must be available.
Curl runs in verbose mode and progress meter switch off by default.
*/
func (s *HstSuite) RunCurlContainer(curlCont *Container, args string) (string, string) {
	cmd := fmt.Sprintf("curl -v -s %s", args)
	s.Log(cmd)
	curlCont.ExtraRunningArgs = cmd
	curlCont.Run()
	stdout, stderr := curlCont.GetOutput()
	s.Log(stderr)
	s.Log(stdout)
	return stdout, stderr
}

/*
CollectNginxLogs save access and error logs to the test execution directory.
Nginx logging need to be set following way:

  - error_log <default-work-dir>/{{.LogPrefix}}-error.log;
  - access_log <default-work-dir>/{{.LogPrefix}}-access.log;

where LogPrefix is set to nginxContainer.Name
*/
func (s *HstSuite) CollectNginxLogs(nginxContainer *Container) {
	targetDir := nginxContainer.Suite.getLogDirPath()
	source := nginxContainer.GetHostWorkDir() + "/" + nginxContainer.Name + "-"
	cmd := exec.Command("cp", "-t", targetDir, source+"error.log", source+"access.log")
	s.Log(cmd.String())
	err := cmd.Run()
	if err != nil {
		s.Log(fmt.Sprint(err))
	}
}

/*
CollectEnvoyLogs save access logs to the test execution directory.
Envoy access log path need to be set following way:
<default-work-dir>/{{.LogPrefix}}-access.log
where LogPrefix is set to envoyContainer.Name
*/
func (s *HstSuite) CollectEnvoyLogs(envoyContainer *Container) {
	targetDir := envoyContainer.Suite.getLogDirPath()
	source := envoyContainer.GetHostWorkDir() + "/" + envoyContainer.Name + "-"
	cmd := exec.Command("cp", "-t", targetDir, source+"access.log")
	s.Log(cmd.String())
	err := cmd.Run()
	if err != nil {
		s.Log(fmt.Sprint(err))
	}
}

func (s *HstSuite) IperfLogFileName(serverContainer *Container) string {
	return serverContainer.GetContainerWorkDir() + "/" + serverContainer.Name + "-" + iperfLogFileName
}

func (s *HstSuite) CollectIperfLogs(serverContainer *Container) {
	targetDir := serverContainer.Suite.getLogDirPath()
	source := serverContainer.GetHostWorkDir() + "/" + serverContainer.Name + "-" + iperfLogFileName
	cmd := exec.Command("cp", "-t", targetDir, source)
	s.Log(cmd.String())
	err := cmd.Run()
	if err != nil {
		s.Log(fmt.Sprint(err))
	}
}

func (s *HstSuite) RedisServerLogFileName(serverContainer *Container) string {
	return serverContainer.GetContainerWorkDir() + "/" + serverContainer.Name + "-" + redisLogFileName
}

func (s *HstSuite) CollectRedisServerLogs(serverContainer *Container) {
	targetDir := serverContainer.Suite.getLogDirPath()
	source := serverContainer.GetHostWorkDir() + "/" + serverContainer.Name + "-" + redisLogFileName
	cmd := exec.Command("cp", "-t", targetDir, source)
	s.Log(cmd.String())
	err := cmd.Run()
	if err != nil {
		s.Log(fmt.Sprint(err))
	}
}

func (s *HstSuite) H2loadLogFileName(h2loadContainer *Container) string {
	return h2loadContainer.GetContainerWorkDir() + "/" + h2loadContainer.Name + "-" + h2loadLogFileName
}

func (s *HstSuite) CollectH2loadLogs(h2loadContainer *Container) {
	targetDir := h2loadContainer.Suite.getLogDirPath()
	source := h2loadContainer.GetHostWorkDir() + "/" + h2loadContainer.Name + "-" + h2loadLogFileName
	cmd := exec.Command("cp", "-t", targetDir, source)
	s.Log(cmd.String())
	err := cmd.Run()
	if err != nil {
		s.Log(fmt.Sprint(err))
	}
}

func (s *HstSuite) StartHttpServer(running chan struct{}, done chan struct{}, addressPort, netNs string) {
	cmd := CommandInNetns([]string{"./http_server", addressPort, s.Ppid, s.ProcessIndex}, netNs)
	err := cmd.Start()
	s.Log(cmd)
	if err != nil {
		s.Log("Failed to start http server: " + fmt.Sprint(err))
		return
	}
	running <- struct{}{}
	<-done
	cmd.Process.Kill()
}

func (s *HstSuite) StartWget(finished chan error, server_ip, port, query, netNs string) {
	defer func() {
		finished <- errors.New("wget error")
	}()

	cmd := CommandInNetns([]string{"wget", "--timeout=10", "--no-proxy", "--tries=5", "-O", "/dev/null", server_ip + ":" + port + "/" + query},
		netNs)
	s.Log(cmd)
	o, err := cmd.CombinedOutput()
	s.Log(string(o))
	if err != nil {
		finished <- fmt.Errorf("wget error: '%v\n\n%s'", err, o)
		return
	} else if !strings.Contains(string(o), "200 OK") {
		finished <- fmt.Errorf("wget error: response not 200 OK")
		return
	}
	finished <- nil
}

func (s *HstSuite) StartCurl(finished chan error, uri, netNs, expectedRespCode string, timeout int, args []string) {
	defer func() {
		finished <- errors.New("curl error")
	}()

	c := []string{"curl", "-v", "-s", "-k", "--max-time", strconv.Itoa(timeout), "-o", "/dev/null", "--noproxy", "*"}
	c = append(c, args...)
	c = append(c, uri)
	cmd := CommandInNetns(c, netNs)
	s.Log(cmd)
	o, err := cmd.CombinedOutput()
	s.Log(string(o))
	if err != nil {
		finished <- fmt.Errorf("curl error: '%v\n\n%s'", err, o)
		return
	} else if !strings.Contains(string(o), expectedRespCode) {
		finished <- fmt.Errorf("curl error: response not %s", expectedRespCode)
		return
	}
	finished <- nil
}

func (s *HstSuite) StartIperfClient(finished chan error, clientAddress, serverAddress, serverPort, netNs string, args []string) {
	defer func() {
		finished <- errors.New("iperf client error")
	}()

	c := []string{"iperf3", "-c", serverAddress, "-B", clientAddress, "-J", "-l", "1460", "-b", "10g", "-p", serverPort}
	c = append(c, args...)
	cmd := CommandInNetns(c, netNs)
	s.Log(cmd)
	o, err := cmd.CombinedOutput()
	if err != nil {
		finished <- fmt.Errorf("iperf client error: '%v\n\n%s'", err, o)
		return
	}
	s.Log(o)
	finished <- nil
}

// Start a server app. 'processName' is used to check whether the app started correctly.
func (s *HstSuite) StartServerApp(c *Container, processName string, cmd string,
	running chan error, done chan struct{}) {

	s.Log("starting server")
	c.ExecServer(true, cmd)
	cmd2 := exec.Command("docker", "exec", c.Name, "pidof", processName)
	err := cmd2.Run()
	if err != nil {
		msg := fmt.Errorf("failed to start server app: %v", err)
		running <- msg
		<-done
		return
	}
	running <- nil
	<-done
}

func (s *HstSuite) StartClientApp(c *Container, cmd string,
	clnCh chan error, clnRes chan []byte) {
	defer func() {
		close(clnCh)
		close(clnRes)
	}()

	s.Log("starting client app, please wait")
	cmd2 := exec.Command("/bin/sh", "-c", "docker exec "+c.getEnvVarsAsCliOption()+" "+
		c.Name+" "+cmd)
	s.Log(cmd2)
	o, err := cmd2.CombinedOutput()

	if err != nil {
		s.Log(err)
		s.Log(string(o))
		clnRes <- nil
		clnCh <- fmt.Errorf("failed to start client app '%s'", err)
		s.AssertNil(err, fmt.Sprint(err))
	} else {
		clnRes <- o
	}
}

func (s *HstSuite) GetCoreProcessName(file string) (string, bool) {
	cmd := fmt.Sprintf("file -b %s", file)
	output, err := exechelper.Output(cmd)
	if err != nil {
		s.Log(fmt.Sprint(err))
		return "", false
	}
	outputStr := string(output)
	// ELF 64-bit LSB core file, x86-64, version 1 (SYSV), SVR4-style, from 'vpp -c /tmp/server/etc/vpp/startup.conf', real uid: 0, effective uid: 0, real gid: 0, effective gid: 0, execfn: '/usr/bin/vpp', platform: 'x86_64'
	if !strings.Contains(outputStr, "core file") {
		return "", false
	}
	soutputSplit := strings.Split(outputStr, ",")
	for _, tmp := range soutputSplit {
		if strings.Contains(tmp, "execfn:") {
			return strings.Trim(strings.Split(tmp, ": ")[1], "'"), true
		}
	}
	return "", false
}

func (s *HstSuite) StartTcpEchoServer(addr string, port int) *net.TCPListener {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP(addr), Port: port})
	s.AssertNil(err, fmt.Sprint(err))
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}
			go handleConn(conn)
		}
	}()
	s.Log("* started tcp echo server " + addr + ":" + strconv.Itoa(port))
	return listener
}

func (s *HstSuite) StartUdpEchoServer(addr string, port int) *net.UDPConn {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(addr), Port: port})
	s.AssertNil(err, fmt.Sprint(err))
	go func() {
		for {
			b := make([]byte, 1500)
			n, addr, err := conn.ReadFrom(b)
			if err != nil {
				return
			}
			if _, err := conn.WriteTo(b[:n], addr); err != nil {
				return
			}
		}
	}()
	s.Log("* started udp echo server " + addr + ":" + strconv.Itoa(port))
	return conn
}

// Parses transfer speed ("NBps full-duplex")
func (s *HstSuite) ParseEchoClientTransfer(stats string) (uint64, error) {
	pattern := regexp.MustCompile(`(?i)(\d+)\s+bytes/second\s+(?:half|full)-duplex`)
	match := pattern.FindStringSubmatch(stats)
	if len(match) == 0 {
		return 0, errors.New("throughput pattern not found")
	}
	uVal, err := strconv.ParseUint(match[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse numeric value '%s': %w", match[1], err)
	}
	return uVal, nil
}

// Logs to files by default, logs to stdout when VERBOSE=true with GinkgoWriter
// to keep console tidy
func (s *HstSuite) Log(log any, arg ...any) {
	var logStr string
	if len(arg) == 0 {
		logStr = fmt.Sprint(log)
	} else {
		logStr = fmt.Sprintf(fmt.Sprint(log), arg...)
	}
	logs := strings.SplitSeq(logStr, "\n")

	for line := range logs {
		s.Logger.Println(line)
	}
	if *IsVerbose {
		GinkgoWriter.Println(logStr)
	}
}

func GetTestFilename() string {
	_, filename, _, _ := runtime.Caller(2)
	return filepath.Base(filename)
}

var testCounter uint16
var startTime time.Time = time.Now()

func TestCounterFunc() {
	if ParallelTotal.Value.String() != "1" {
		return
	}
	testCounter++
	fmt.Printf("Test counter: %d/%d (%.2f%%)\n"+
		"Time elapsed: %.2fs\n",
		testCounter, TestsThatWillRun, float64(testCounter)/float64(TestsThatWillRun)*100, time.Since(startTime).Seconds())
}

// Helper functions
func convertToMB(value, unit string) float64 {
	val, _ := strconv.ParseFloat(value, 64)
	switch unit {
	case "K":
		return val / 1024
	case "M":
		return val
	case "G":
		return val * 1024
	default:
		return val
	}
}

func convertToMbps(value, unit string) float64 {
	val, _ := strconv.ParseFloat(value, 64)
	switch unit {
	case "K":
		return val / 1000
	case "M":
		return val
	case "G":
		return val * 1000
	default:
		return val
	}
}

// IperfResult contains the parsed performance metrics
type IperfResult struct {
	BitrateMbps   float64
	TransferredMB float64
	Jitter        float64 // UDP only
	PacketLoss    float64 // UDP only, percentage
	Protocol      string  // "TCP" or "UDP"
	Retransmits   int     // TCP only
}

// ParseIperfText parses iperf text output (default format)
func ParseIperfText(output string) (*IperfResult, error) {
	result := &IperfResult{}

	// Pattern for TCP summary: [SUM]  0.0-10.0 sec  1.10 GBytes   941 Mbits/sec   123  sender
	// Or: [  3]  0.0-10.0 sec  1.10 GBytes   941 Mbits/sec   123  sender
	tcpPattern := regexp.MustCompile(`\[[\s\w]+\]\s+([\d\.]+)-([\d\.]+)\s+sec\s+([\d\.]+)\s+([KMG])Bytes\s+([\d\.]+)\s+([KMG])bits/sec(?:\s+(\d+))?\s+(sender|receiver)`)

	// Pattern for UDP summary with packet loss
	// [  3]  0.0-10.0 sec  1.25 MBytes  1.05 Mbits/sec  0.123 ms  10/1000 (1%)
	udpPattern := regexp.MustCompile(`\[[\s\w]+\]\s+([\d\.]+)-([\d\.]+)\s+sec\s+([\d\.]+)\s+([KMG])Bytes\s+([\d\.]+)\s+([KMG])bits/sec\s+([\d\.]+)\s+ms\s+(\d+)/(\d+)\s+\(([\d\.]+)%\)`)

	// Simpler UDP pattern without jitter/loss (sometimes iperf shows this)
	udpSimplePattern := regexp.MustCompile(`\[[\s\w]+\]\s+([\d\.]+)-([\d\.]+)\s+sec\s+([\d\.]+)\s+([KMG])Bytes\s+([\d\.]+)\s+([KMG])bits/sec.*receiver`)

	scanner := bufio.NewScanner(strings.NewReader(output))
	lines := []string{}

	// Collect all lines
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	// Parse from the end (summary lines are at the bottom)
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]

		// Try UDP pattern with full stats first
		if matches := udpPattern.FindStringSubmatch(line); matches != nil {
			result.Protocol = "UDP"
			result.TransferredMB = convertToMB(matches[3], matches[4])
			result.BitrateMbps = convertToMbps(matches[5], matches[6])
			result.Jitter, _ = strconv.ParseFloat(matches[7], 64)
			result.PacketLoss, _ = strconv.ParseFloat(matches[10], 64)
			return result, nil
		}

		// Try simple UDP pattern
		if matches := udpSimplePattern.FindStringSubmatch(line); matches != nil {
			result.Protocol = "UDP"
			result.TransferredMB = convertToMB(matches[3], matches[4])
			result.BitrateMbps = convertToMbps(matches[5], matches[6])
			return result, nil
		}

		// Try TCP pattern (look for sender/receiver)
		if matches := tcpPattern.FindStringSubmatch(line); matches != nil {
			// Prefer "sender" line for client tests
			if matches[8] == "sender" || result.Protocol == "" {
				result.Protocol = "TCP"
				result.TransferredMB = convertToMB(matches[3], matches[4])
				result.BitrateMbps = convertToMbps(matches[5], matches[6])

				if len(matches) > 7 && matches[7] != "" {
					result.Retransmits, _ = strconv.Atoi(matches[7])
				}

				if matches[8] == "sender" {
					return result, nil
				}
			}
		}
	}

	if result.Protocol != "" {
		return result, nil
	}

	return nil, fmt.Errorf("failed to parse iperf output: no summary line found")
}

// Check if the error is an exec.ExitError caused by SIGKILL
func IsKilledError(err error) bool {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			return status.Signaled() && status.Signal() == syscall.SIGKILL
		}
	}
	return false
}
