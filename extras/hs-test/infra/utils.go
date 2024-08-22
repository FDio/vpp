package hst

import (
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
func NewHttpClient() *http.Client {
	transport := http.DefaultTransport
	transport.(*http.Transport).Proxy = nil
	transport.(*http.Transport).DisableKeepAlives = true
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Second * 30,
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
