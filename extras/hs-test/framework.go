package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"

	"git.fd.io/govpp.git/api"
	"github.com/edwarnicke/govpp/binapi/af_packet"
	interfaces "github.com/edwarnicke/govpp/binapi/interface"
	"github.com/edwarnicke/govpp/binapi/interface_types"
	ip_types "github.com/edwarnicke/govpp/binapi/ip_types"
	"github.com/networkservicemesh/sdk/pkg/tools/log"
	"github.com/networkservicemesh/sdk/pkg/tools/log/logruslogger"
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

type ConfFn func(context.Context, api.Connection) error

func newVppContext() (context.Context, context.CancelFunc) {
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
	)
	ctx = log.WithLog(ctx, logruslogger.New(ctx, map[string]interface{}{"cmd": os.Args[0]}))
	return ctx, cancel
}

func Vppcli(runDir, command string) (string, error) {
	cmd := exec.Command("vppctl", "-s", fmt.Sprintf("%s/var/run/vpp/cli.sock", runDir), command)
	o, err := cmd.CombinedOutput()
	if err != nil {
		log.Default().Errorf("failed to execute command: '%s'.\n", err)
	}
	log.Default().Debugf("Command output %s", string(o))
	return string(o), err
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
		log.Default().Errorf("wget error: '%s'.\n%s", err, o)
		return
	}
	log.Default().Debugf("Client output: %s", o)
	finished <- nil
}

func configureAfPacket(ctx context.Context, vppCon api.Connection,
	name, interfaceAddress string) (interface_types.InterfaceIndex, error) {
	ifaceClient := interfaces.NewServiceClient(vppCon)
	afPacketCreate := &af_packet.AfPacketCreateV2{
		UseRandomHwAddr: true,
		HostIfName:      name,
		NumRxQueues:     1,
	}
	afPacketCreateRsp, err := af_packet.NewServiceClient(vppCon).AfPacketCreateV2(ctx, afPacketCreate)
	if err != nil {
		log.FromContext(ctx).Fatalf("failed to create af packet: %v", err)
		return 0, err
	}
	_, err = ifaceClient.SwInterfaceSetFlags(ctx, &interfaces.SwInterfaceSetFlags{
		SwIfIndex: afPacketCreateRsp.SwIfIndex,
		Flags:     interface_types.IF_STATUS_API_FLAG_ADMIN_UP,
	})
	if err != nil {
		log.FromContext(ctx).Fatal("set interface state up failed: ", err)
		return 0, err
	}
	ipPrefix, err := ip_types.ParseAddressWithPrefix(interfaceAddress)
	if err != nil {
		log.FromContext(ctx).Fatal("parse ip address ", err)
		return 0, err
	}
	ipAddress := &interfaces.SwInterfaceAddDelAddress{
		IsAdd:     true,
		SwIfIndex: afPacketCreateRsp.SwIfIndex,
		Prefix:    ipPrefix,
	}
	_, errx := ifaceClient.SwInterfaceAddDelAddress(ctx, ipAddress)
	if errx != nil {
		log.FromContext(ctx).Fatal("add ip address ", err)
		return 0, err
	}
	return afPacketCreateRsp.SwIfIndex, nil
}

/* func createtempDir() string {
	dir, err := ioutil.TempDir("/tmp", "hstf-vpp-*")
	if err != nil {
		fmt.Println("error creating temp dir: ", err)
		return ""
	}
	return dir
} */

/* func checkAppExists(name string) {
    path, err := exec.LookPath(name)
    if err != nil {
        fmt.Printf("didn't find '%s' executable\n", name)
    }
} */

func exitOnErrCh(ctx context.Context, cancel context.CancelFunc, errCh <-chan error) {
	// If we already have an error, log it and exit
	select {
	case err := <-errCh:
		log.FromContext(ctx).Fatal(err)
	default:
	}
	go func(ctx context.Context, errCh <-chan error) {
		<-errCh
		cancel()
	}(ctx, errCh)
}
