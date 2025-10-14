package hst

import (
	"crypto/tls"
	"encoding/json"
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
		finished <- fmt.Errorf("curl error: response not " + expectedRespCode)
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
	result := s.ParseJsonIperfOutput(o)
	s.LogJsonIperfOutput(result)
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
	logs := strings.Split(logStr, "\n")

	for _, line := range logs {
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

type IPerfResult struct {
	Start struct {
		Timestamp struct {
			Time string `json:"time"`
		} `json:"timestamp"`
		Connected []struct {
			Socket     int    `json:"socket"`
			LocalHost  string `json:"local_host"`
			LocalPort  int    `json:"local_port"`
			RemoteHost string `json:"remote_host"`
			RemotePort int    `json:"remote_port"`
		} `json:"connected"`
		Version string `json:"version"`
		Details struct {
			Protocol string `json:"protocol"`
		} `json:"test_start"`
	} `json:"start"`
	End struct {
		TcpSent *struct {
			MbitsPerSecond float64 `json:"bits_per_second"`
			MBytes         float64 `json:"bytes"`
		} `json:"sum_sent,omitempty"`
		TcpReceived *struct {
			MbitsPerSecond float64 `json:"bits_per_second"`
			MBytes         float64 `json:"bytes"`
		} `json:"sum_received,omitempty"`
		Udp *struct {
			MbitsPerSecond float64 `json:"bits_per_second"`
			JitterMs       float64 `json:"jitter_ms,omitempty"`
			LostPackets    int     `json:"lost_packets,omitempty"`
			Packets        int     `json:"packets,omitempty"`
			LostPercent    float64 `json:"lost_percent,omitempty"`
			MBytes         float64 `json:"bytes"`
		} `json:"sum,omitempty"`
	} `json:"end"`
}

func (s *HstSuite) ParseJsonIperfOutput(jsonResult []byte) IPerfResult {
	var result IPerfResult

	// VCL/LDP debugging can pollute output so find the first occurrence of a curly brace to locate the start of JSON data
	jsonStart := -1
	jsonEnd := len(jsonResult)
	braceCount := 0
	for i := 0; i < len(jsonResult); i++ {
		if jsonResult[i] == '{' {
			if jsonStart == -1 {
				jsonStart = i
			}
			braceCount++
		} else if jsonResult[i] == '}' {
			braceCount--
			if braceCount == 0 {
				jsonEnd = i + 1
				break
			}
		}
	}
	jsonResult = jsonResult[jsonStart:jsonEnd]

	// remove iperf warning line if present
	if strings.Contains(string(jsonResult), "warning") {
		index := strings.Index(string(jsonResult), "\n")
		jsonResult = jsonResult[index+1:]
	}

	err := json.Unmarshal(jsonResult, &result)
	s.AssertNil(err)

	if result.Start.Details.Protocol == "TCP" {
		result.End.TcpSent.MbitsPerSecond = result.End.TcpSent.MbitsPerSecond / 1000000
		result.End.TcpSent.MBytes = result.End.TcpSent.MBytes / 1000000
		result.End.TcpReceived.MbitsPerSecond = result.End.TcpReceived.MbitsPerSecond / 1000000
		result.End.TcpReceived.MBytes = result.End.TcpReceived.MBytes / 1000000
	} else {
		result.End.Udp.MBytes = result.End.Udp.MBytes / 1000000
		result.End.Udp.MbitsPerSecond = result.End.Udp.MbitsPerSecond / 1000000
	}

	return result
}

func (s *HstSuite) LogJsonIperfOutput(result IPerfResult) {
	s.Log("\n*******************************************\n"+
		"%s\n"+
		"[%s] %s:%d connected to %s:%d\n"+
		"Started:  %s\n",
		result.Start.Version,
		result.Start.Details.Protocol,
		result.Start.Connected[0].LocalHost, result.Start.Connected[0].LocalPort,
		result.Start.Connected[0].RemoteHost, result.Start.Connected[0].RemotePort,
		result.Start.Timestamp.Time)

	if result.Start.Details.Protocol == "TCP" {
		s.Log("Transfer (sent):     %.2f MBytes\n"+
			"Bitrate  (sent):     %.2f Mbits/sec\n"+
			"Transfer (received): %.2f MBytes\n"+
			"Bitrate  (received): %.2f Mbits/sec",
			result.End.TcpSent.MBytes,
			result.End.TcpSent.MbitsPerSecond,
			result.End.TcpReceived.MBytes,
			result.End.TcpReceived.MbitsPerSecond)
	} else {
		s.Log("Transfer:     %.2f MBytes\n"+
			"Bitrate:      %.2f Mbits/sec\n"+
			"Jitter:       %.3f ms\n"+
			"Packets:      %d\n"+
			"Packets lost: %d\n"+
			"Percent lost: %.2f%%",
			result.End.Udp.MBytes,
			result.End.Udp.MbitsPerSecond,
			result.End.Udp.JitterMs,
			result.End.Udp.Packets,
			result.End.Udp.LostPackets,
			result.End.Udp.LostPercent)
	}
	s.Log("*******************************************\n")
}
