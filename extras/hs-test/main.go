package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"

	"github.com/edwarnicke/govpp/binapi/af_packet"
	interfaces "github.com/edwarnicke/govpp/binapi/interface"
	"github.com/edwarnicke/govpp/binapi/interface_types"
	ip_types "github.com/edwarnicke/govpp/binapi/ip_types"

	"git.fd.io/govpp.git/api"
)

type CfgTable map[string]func([]string) *SyncResult

var cfgTable CfgTable

type ConfFn func(context.Context, api.Connection) error

func newVppContext() (context.Context, context.CancelFunc) {
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
	)
	return ctx, cancel
}

func Vppcli(runDir, command string) (string, error) {
	cmd := exec.Command("vppctl", "-s", fmt.Sprintf("%s/var/run/vpp/cli.sock", runDir), command)
	o, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("failed to execute command: '%v'.\n", err)
	}
	fmt.Printf("Command output %s", string(o))
	return string(o), err
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
		fmt.Printf("failed to create af packet: %v", err)
		return 0, err
	}
	_, err = ifaceClient.SwInterfaceSetFlags(ctx, &interfaces.SwInterfaceSetFlags{
		SwIfIndex: afPacketCreateRsp.SwIfIndex,
		Flags:     interface_types.IF_STATUS_API_FLAG_ADMIN_UP,
	})
	if err != nil {
		fmt.Printf("set interface state up failed: %v\n", err)
		return 0, err
	}
	ipPrefix, err := ip_types.ParseAddressWithPrefix(interfaceAddress)
	if err != nil {
		fmt.Printf("parse ip address %v\n", err)
		return 0, err
	}
	ipAddress := &interfaces.SwInterfaceAddDelAddress{
		IsAdd:     true,
		SwIfIndex: afPacketCreateRsp.SwIfIndex,
		Prefix:    ipPrefix,
	}
	_, errx := ifaceClient.SwInterfaceAddDelAddress(ctx, ipAddress)
	if errx != nil {
		fmt.Printf("add ip address %v\n", err)
		return 0, err
	}
	return afPacketCreateRsp.SwIfIndex, nil
}

func exitOnErrCh(ctx context.Context, cancel context.CancelFunc, errCh <-chan error) {
	// If we already have an error, log it and exit
	select {
	case err := <-errCh:
		fmt.Printf("%v", err)
	default:
	}
	go func(ctx context.Context, errCh <-chan error) {
		<-errCh
		cancel()
	}(ctx, errCh)
}

func writeSyncFile(res *SyncResult) error {
	syncFile := "/tmp/sync/rc"

	var jsonRes JsonResult

	jsonRes.ErrOutput = res.ErrOutput
	jsonRes.StdOutput = res.StdOutput
	if res.Err != nil {
		jsonRes.Code = 1
		jsonRes.Desc = fmt.Sprintf("%s :%v", res.Desc, res.Err)
	} else {
		jsonRes.Code = 0
	}

	str, err := json.Marshal(jsonRes)
	if err != nil {
		return fmt.Errorf("error marshaling json result data! %v", err)
	}

	_, err = os.Open(syncFile)
	if err != nil {
		// expecting the file does not exist
		f, e := os.Create(syncFile)
		if e != nil {
			return fmt.Errorf("failed to open sync file")
		}
		defer f.Close()
		f.Write([]byte(str))
	} else {
		return fmt.Errorf("sync file exists, delete the file frst")
	}
	return nil
}

func main() {
	if len(os.Args) == 0 {
		fmt.Println("args required")
		return
	}

	if os.Args[1] == "rm" {
		topology, err := LoadTopology(TopologyDir, os.Args[2])
		if err != nil {
			fmt.Printf("falied to load topologies: %v\n", err)
			os.Exit(1)
		}
		topology.Unconfigure()
		os.Exit(0)
	}

	registerConfigCallbacks()

	var err error
	res := processArgs()
	err = writeSyncFile(res)
	if err != nil {
		fmt.Printf("failed to write to sync file: %v\n", err)
	}
}

func NewResult(err error, opts ...ResultOptionFn) *SyncResult {
	res := &SyncResult{
		Err: err,
	}
	for _, o := range opts {
		o(res)
	}
	return res
}

type ResultOptionFn func(res *SyncResult)

func ResultWithDesc(s string) ResultOptionFn {
	return func(res *SyncResult) {
		res.Desc = s
	}
}

func ResultWithStderr(s string) ResultOptionFn {
	return func(res *SyncResult) {
		res.ErrOutput = s
	}
}

func ResultWithStdout(s string) ResultOptionFn {
	return func(res *SyncResult) {
		res.ErrOutput = s
	}
}

func OkResult() *SyncResult {
	return NewResult(nil)
}

func reg(key string, fn func([]string) *SyncResult) {
	cfgTable[key] = fn
}

func registerConfigCallbacks() {
	cfgTable = make(map[string]func([]string) *SyncResult)
	reg("echo-client", TcEchoClient)
	reg("echo-srv-internal", Tc2Veths)
	reg("echo-cln-internal", Tc2Veths)
	reg("echo-server", TcEchoServer)
	reg("vpp-proxy", TcVppProxy)
	reg("vpp-envoy", TcEnvoyProxy)
	reg("http-tps", TcHttpTps)
	reg("2veths", Tc2Veths)
}

func processArgs() *SyncResult {
	fn := cfgTable[os.Args[1]]
	if fn == nil {
		return NewResult(fmt.Errorf("internal: no config found for %s", os.Args[1]))
	}
	return fn(os.Args)
}
