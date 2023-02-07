package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

const vclTemplate = `vcl {
  app-socket-api %[1]s/var/run/app_ns_sockets/%[2]s
  app-scope-global
  app-scope-local
  namespace-id %[2]s
  namespace-secret %[2]s
  use-mq-eventfd
}
`

const NetworkTopologyDir string = "topo-network/"
const ContainerTopologyDir string = "topo-containers/"

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

func StartServerApp(running chan error, done chan struct{}, env []string) {
	cmd := exec.Command("iperf3", "-4", "-s")
	if env != nil {
		cmd.Env = env
	}
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

func StartClientApp(ipAddress string, env []string, clnCh chan error, clnRes chan string) {
	defer func() {
		clnCh <- nil
	}()

	nTries := 0

	for {
		cmd := exec.Command("iperf3", "-c", ipAddress, "-u", "-l", "1460", "-b", "10g")
		if env != nil {
			cmd.Env = env
		}
		o, err := cmd.CombinedOutput()
		if err != nil {
			if nTries > 5 {
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

func assertFileSize(f1, f2 string) error {
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

func startHttpServer(running chan struct{}, done chan struct{}, addressPort, netNs string) {
	cmd := NewCommand([]string{"./http_server", addressPort}, netNs)
	err := cmd.Start()
	if err != nil {
		fmt.Println("Failed to start http server")
		return
	}
	running <- struct{}{}
	<-done
	cmd.Process.Kill()
}

func startWget(finished chan error, server_ip, port, query, netNs string) {
	defer func() {
		finished <- errors.New("wget error")
	}()

	cmd := NewCommand([]string{"wget", "--timeout=10", "--no-proxy", "--tries=5", "-O", "/dev/null", server_ip + ":" + port + "/" + query},
		netNs)
	o, err := cmd.CombinedOutput()
	if err != nil {
		finished <- fmt.Errorf("wget error: '%v\n\n%s'", err, o)
		return
	} else if strings.Contains(string(o), "200 OK") == false {
		finished <- fmt.Errorf("wget error: response not 200 OK")
		return
	}
	finished <- nil
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
