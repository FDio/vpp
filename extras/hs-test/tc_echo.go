package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/edwarnicke/exechelper"
	"github.com/edwarnicke/govpp/binapi/vlib"
	"github.com/edwarnicke/vpphelper"
)

func getArgs() string {
	s := ""
	for i := 2; i < len(os.Args); i++ {
		s = s + " " + os.Args[i]
	}
	return s
}

func ApiCliInband(root, cmd string) *SyncResult {
	ctx, _ := newVppContext()
	con := vpphelper.DialContext(ctx, filepath.Join(root, "/var/run/vpp/api.sock"))
	cliInband := vlib.CliInband{Cmd: cmd}
	cliInbandReply, err := vlib.NewServiceClient(con).CliInband(ctx, &cliInband)
	return NewResult(err, ResultWithStdout(cliInbandReply.Reply))
}

func TcEchoClient(args []string) *SyncResult {
	outBuff := bytes.NewBuffer([]byte{})
	errBuff := bytes.NewBuffer([]byte{})

	cmd := fmt.Sprintf("vpp_echo client socket-name /tmp/echo-cln/var/run/app_ns_sockets/2 use-app-socket-api uri %s://10.10.10.1/12344", args[2])
	err := exechelper.Run(cmd,
		exechelper.WithStdout(outBuff), exechelper.WithStderr(errBuff),
		exechelper.WithStdout(os.Stdout), exechelper.WithStderr(os.Stderr))

	return NewResult(err, ResultWithStdout(string(outBuff.String())),
		ResultWithStderr(string(errBuff.String())))
}

func TcEchoServer(args []string) *SyncResult {
	cmd := fmt.Sprintf("vpp_echo server TX=RX socket-name /tmp/echo-srv/var/run/app_ns_sockets/1 use-app-socket-api uri %s://10.10.10.1/12344", args[2])
	errCh := exechelper.Start(cmd)
	select {
	case err := <-errCh:
		writeSyncFile(NewResult(err, ResultWithDesc("echo_server: ")))
	default:
	}
	writeSyncFile(OkResult())
	return nil
}

func TcEchoSrvInternal() *SyncResult {
	cmd := fmt.Sprintf("test echo server %s uri tcp://10.10.10.1/1234", getArgs())
	return ApiCliInband("/tmp/2veths", cmd)
}

func TcEchoClnInternal() *SyncResult {
	cmd := fmt.Sprintf("test echo client %s uri tcp://10.10.10.1/1234", getArgs())
	return ApiCliInband("/tmp/2veths", cmd)
}
