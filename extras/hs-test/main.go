package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"

	"git.fd.io/govpp.git/api"
)

type CfgTable map[string]func([]string) *ActionResult

var cfgTable CfgTable

type ConfFn func(context.Context, api.Connection) error

func newVppContext() (context.Context, context.CancelFunc) {
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
	)
	return ctx, cancel
}

func Vppcli(runDir, command string) (string, error) { // TODO what to do about this function and the duplicate I added?
	cmd := exec.Command("vppctl", "-s", fmt.Sprintf("%s/var/run/vpp/cli.sock", runDir), command)
	o, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("failed to execute command: '%v'.\n", err)
	}
	fmt.Printf("Command output %s", string(o))
	return string(o), err
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

func writeSyncFile(res *ActionResult) error {
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
		return fmt.Errorf("sync file exists, delete the file first")
	}
	return nil
}

func NewActionResult(err error, opts ...ActionResultOptionFn) *ActionResult {
	res := &ActionResult{
		Err: err,
	}
	for _, o := range opts {
		o(res)
	}
	return res
}

type ActionResultOptionFn func(res *ActionResult)

func ActionResultWithDesc(s string) ActionResultOptionFn {
	return func(res *ActionResult) {
		res.Desc = s
	}
}

func ActionResultWithStderr(s string) ActionResultOptionFn {
	return func(res *ActionResult) {
		res.ErrOutput = s
	}
}

func ActionResultWithStdout(s string) ActionResultOptionFn {
	return func(res *ActionResult) {
		res.StdOutput = s
	}
}

func OkResult() *ActionResult {
	return NewActionResult(nil)
}

func reg(key string, fn func([]string) *ActionResult) {
	cfgTable[key] = fn
}

func processArgs() *ActionResult {
	fn := cfgTable[os.Args[1]]
	if fn == nil {
		return NewActionResult(fmt.Errorf("internal: no config found for %s", os.Args[1]))
	}
	return fn(os.Args)
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

	RegisterActions()

	var err error
	res := processArgs()
	err = writeSyncFile(res)
	if err != nil {
		fmt.Printf("failed to write to sync file: %v\n", err)
	}
}
