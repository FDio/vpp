package hst

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"strings"
	"time"
)

const networkTopologyDir string = "topo-network/"
const containerTopologyDir string = "topo-containers/"

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

// NewHttpClient creates [http.Client] with disabled proxy and redirects, it also sets timeout to 30seconds.
func NewHttpClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport
	transport.(*http.Transport).Proxy = nil
	transport.(*http.Transport).DisableKeepAlives = true
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

/*
RunCurlContainer execute curl command with given args.
Container with name "curl" must be available.
Curl runs in verbose mode and progress meter switch off by default.
*/
func (s *HstSuite) RunCurlContainer(args string) (string, string) {
	curlCont := s.GetContainerByName("curl")
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
func (s *HstSuite) CollectNginxLogs(containerName string) {
	nginxContainer := s.GetContainerByName(containerName)
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
func (s *HstSuite) CollectEnvoyLogs(containerName string) {
	envoyContainer := s.GetContainerByName(containerName)
	targetDir := envoyContainer.Suite.getLogDirPath()
	source := envoyContainer.GetHostWorkDir() + "/" + envoyContainer.Name + "-"
	cmd := exec.Command("cp", "-t", targetDir, source+"access.log")
	s.Log(cmd.String())
	err := cmd.Run()
	if err != nil {
		s.Log(fmt.Sprint(err))
	}
}

func (s *HstSuite) StartIperfServerApp(running chan error, done chan struct{}, env []string) {
	cmd := exec.Command("iperf3", "-4", "-s", "-p", s.GetPortFromPpid())
	if env != nil {
		cmd.Env = env
	}
	s.Log(cmd)
	err := cmd.Start()
	if err != nil {
		msg := fmt.Errorf("failed to start iperf server: %v", err)
		running <- msg
		return
	}
	running <- nil
	<-done
	cmd.Process.Kill()
}

func (s *HstSuite) StartIperfClientApp(ipAddress string, env []string, clnCh chan error, clnRes chan string) {
	defer func() {
		clnCh <- nil
	}()

	nTries := 0

	for {
		cmd := exec.Command("iperf3", "-c", ipAddress, "-u", "-l", "1460", "-b", "10g", "-p", s.GetPortFromPpid())
		if env != nil {
			cmd.Env = env
		}
		s.Log(cmd)
		o, err := cmd.CombinedOutput()
		if err != nil {
			if nTries > 5 {
				clnRes <- ""
				clnCh <- fmt.Errorf("failed to start client app '%s'.\n%s", err, o)
				return
			}
			time.Sleep(1 * time.Second)
			nTries++
			continue
		} else {
			clnRes <- fmt.Sprintf("Client output: %s", o)
		}
		break
	}
}

func (s *HstSuite) StartHttpServer(running chan struct{}, done chan struct{}, addressPort, netNs string) {
	cmd := newCommand([]string{"./http_server", addressPort, s.Ppid, s.ProcessIndex}, netNs)
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

	cmd := newCommand([]string{"wget", "--timeout=10", "--no-proxy", "--tries=5", "-O", "/dev/null", server_ip + ":" + port + "/" + query},
		netNs)
	s.Log(cmd)
	o, err := cmd.CombinedOutput()
	if err != nil {
		finished <- fmt.Errorf("wget error: '%v\n\n%s'", err, o)
		return
	} else if !strings.Contains(string(o), "200 OK") {
		finished <- fmt.Errorf("wget error: response not 200 OK")
		return
	}
	finished <- nil
}

// Start a server app. 'processName' is used to check whether the app started correctly.
func (s *HstSuite) StartServerApp(c *Container, processName string, cmd string,
	running chan error, done chan struct{}) {

	s.Log("starting server")
	c.ExecServer(cmd)
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
	clnCh chan error, clnRes chan string) {
	defer func() {
		close(clnCh)
		close(clnRes)
	}()

	s.Log("starting client app, please wait")

	nTries := 0
	for {
		// exec.Cmd can only be used once, which is why it's in the loop
		cmd2 := exec.Command("/bin/sh", "-c", "docker exec "+c.getEnvVarsAsCliOption()+" "+
			c.Name+" "+cmd)
		s.Log(cmd2)
		o, err := cmd2.CombinedOutput()
		if err != nil {
			s.Log(err)
			if nTries > 5 {
				clnRes <- ""
				clnCh <- fmt.Errorf("failed to start client app '%s'", err)
				s.AssertNil(err, fmt.Sprint(err))
				break
			}
			time.Sleep(1 * time.Second)
			nTries++
		} else {
			clnRes <- fmt.Sprintf("Client output: %s", o)
			break
		}
	}
}
