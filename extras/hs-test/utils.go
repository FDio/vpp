package main

import (
	"errors"
	"fmt"
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
}

`

const TopologyDir string = "topo/"

type SyncResult struct {
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
