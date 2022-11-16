package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/edwarnicke/exechelper"
)

const configTemplate = `unix {
  nodaemon
  log %[1]s/var/log/vpp/vpp.log
  full-coredump
  cli-listen %[1]s/var/run/vpp/cli.sock
  runtime-dir %[1]s/var/run
  gid vpp
}

api-trace {
  on
}

api-segment {
  gid vpp
}

socksvr {
  socket-name %[1]s/var/run/vpp/api.sock
}

statseg {
  socket-name %[1]s/var/run/vpp/stats.sock
}

plugins {
	plugin unittest_plugin.so { enable }
    plugin dpdk_plugin.so { disable }
    plugin crypto_aesni_plugin.so { enable }
    plugin quic_plugin.so { enable }
    plugin crypto_ipsecmb_plugin.so { disable }
}

`

const vclTemplate = `vcl {
  app-socket-api %[1]s
  app-scope-global
  app-scope-local
  namespace-id %[2]s
  namespace-secret %[2]s
  use-mq-eventfd
}
`

const TopologyDir string = "topo/"

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

func StartClientApp(env []string, clnCh chan error) {
	defer func() {
		clnCh <- nil
	}()

	nTries := 0

	for {
		cmd := exec.Command("iperf3", "-c", "10.10.10.1", "-u", "-l", "1460", "-b", "10g")
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
			fmt.Printf("Client output: %s", o)
		}
		break
	}
}

// run vpphelper in docker
func hstExec(args string, instance string) (string, error) {
	syncFile := fmt.Sprintf("/tmp/%s/sync/rc", instance)
	os.Remove(syncFile)

	c := "docker exec -d " + instance + " /hs-test " + args
	err := exechelper.Run(c)
	if err != nil {
		return "", err
	}

	res, err := waitForSyncFile(syncFile)

	if err != nil {
		return "", fmt.Errorf("failed to read sync file while executing './hs-test %s': %v", args, err)
	}

	o := res.StdOutput + res.ErrOutput
	if res.Code != 0 {
		return o, fmt.Errorf("cmd resulted in non-zero value %d: %s", res.Code, res.Desc)
	}
	return o, err
}

func waitForSyncFile(fname string) (*JsonResult, error) {
	var res JsonResult

	for i := 0; i < 360; i++ {
		f, err := os.Open(fname)
		if err == nil {
			defer f.Close()

			data, err := ioutil.ReadFile(fname)
			if err != nil {
				return nil, fmt.Errorf("read error: %v", err)
			}
			err = json.Unmarshal(data, &res)
			if err != nil {
				return nil, fmt.Errorf("json unmarshal error: %v", err)
			}
			return &res, nil
		}
		time.Sleep(1 * time.Second)
	}
	return nil, fmt.Errorf("no sync file found")
}

func dockerRun(instance, args string) error {
	exechelper.Run(fmt.Sprintf("mkdir -p /tmp/%s/sync", instance))
	syncPath := fmt.Sprintf("-v /tmp/%s/sync:/tmp/sync", instance)
	cmd := "docker run --cap-add=all -d --privileged --network host --rm "
	cmd += syncPath
	cmd += " " + args
	cmd += " --name " + instance + " hs-test/vpp"
	fmt.Println(cmd)
	return exechelper.Run(cmd)
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

func dockerExec(cmd string, instance string) ([]byte, error) {
	c := "docker exec -d " + instance + " " + cmd
	return exechelper.CombinedOutput(c)
}

func vppctl(t *testing.T, containerName string, socket string, command string) (string) {
	dockerExecCommand := fmt.Sprintf("docker exec --detach=false %[1]s vppctl -s %[2]s %[3]s",
		containerName, socket, command)
	output, err := exechelper.CombinedOutput(dockerExecCommand)
	if err != nil {
		t.Errorf("vppctl %s failed: %v", command, err)
	}
	return string(output)
}

func startEnvoy(ctx context.Context, dockerInstance string) <-chan error {
	errCh := make(chan error)
	wd, err := os.Getwd()
	if err != nil {
		errCh <- err
		return errCh
	}

	c := []string{"docker", "run", "--rm", "--name", "envoy",
		"-v", fmt.Sprintf("%s/envoy/proxy.yaml:/etc/envoy/envoy.yaml", wd),
		"-v", fmt.Sprintf("shared-vol:/tmp/%s", dockerInstance),
		"-v", fmt.Sprintf("%s/envoy:/tmp", wd),
		"-e", "ENVOY_UID=0",
		"-e", "VCL_CONFIG=/tmp/vcl.conf",
		"envoyproxy/envoy-contrib:v1.21-latest"}
	fmt.Println(c)

	go func(errCh chan error) {
		count := 0
		var cmd *exec.Cmd
		for ; ; count++ {
			cmd = NewCommand(c, "")
			err = cmd.Start()
			if err == nil {
				break
			}
			if count > 5 {
				errCh <- fmt.Errorf("failed to start envoy docker after %d attempts", count)
				return
			}
		}

		err = cmd.Wait()
		if err != nil {
			errCh <- fmt.Errorf("failed to start docker: %v", err)
			return
		}
		<-ctx.Done()
	}(errCh)
	return errCh
}

func setupEnvoy(t *testing.T, ctx context.Context, dockerInstance string) error {
	errCh := startEnvoy(ctx, dockerInstance)
	select {
	case err := <-errCh:
		return err
	default:
	}

	go func(ctx context.Context, errCh <-chan error) {
		for {
			select {
			// handle cancel() call from outside to gracefully stop the routine
			case <-ctx.Done():
				return
			default:
				select {
				case err := <-errCh:
					fmt.Printf("error while running envoy: %v", err)
				default:
				}
			}
		}
	}(ctx, errCh)
	return nil
}

func configureVppProxy() error {
	_, err := dockerExec("vppctl test proxy server server-uri tcp://10.0.0.2/555 client-uri tcp://10.0.1.1/666",
		"vpp-proxy")
	if err != nil {
		return fmt.Errorf("error while configuring vpp proxy test: %v", err)
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

func startWget(finished chan error, server_ip, port string, netNs string) {
	fname := "test_file_10M"
	defer func() {
		finished <- errors.New("wget error")
	}()

	cmd := NewCommand([]string{"wget", "--tries=5", "-q", "-O", "/dev/null", server_ip + ":" + port + "/" + fname},
		netNs)
	o, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("wget error: '%s'.\n%s", err, o)
		return
	}
	fmt.Printf("Client output: %s", o)
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
