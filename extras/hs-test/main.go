package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"git.fd.io/govpp.git/api"
	"github.com/edwarnicke/exechelper"
	"github.com/edwarnicke/govpp/binapi/session"
	"github.com/edwarnicke/govpp/binapi/vlib"
	"github.com/edwarnicke/vpphelper"
	"github.com/networkservicemesh/sdk/pkg/tools/log"
)

func configureProxyTcp(ifName0, ipAddr0, ifName1, ipAddr1 string) ConfFn {
	return func(ctx context.Context,
		vppConn api.Connection) error {

		_, err := configureAfPacket(ctx, vppConn, ifName0, ipAddr0)
		if err != nil {
			log.FromContext(ctx).Fatalf("failed to create af packet: %v", err)
			return err
		}
		_, err = configureAfPacket(ctx, vppConn, ifName1, ipAddr1)
		if err != nil {
			log.FromContext(ctx).Fatalf("failed to create af packet: %v", err)
			return err
		}
		return nil
	}
}

func writeSyncFile(res *SyncResult) error {
	syncFile := "/tmp/sync/rc"

	var jsonRes JsonResult

	jsonRes.ErrOutput = res.ErrOutput
	jsonRes.StdOutput = res.StdOutput
	if res.Err != nil {
		jsonRes.Code = 1
		jsonRes.Desc = fmt.Sprintf(res.Desc+":%v", res.Err)
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
		var topoBase TopoBase
		err := topoBase.LoadTopologies("topo/")
		if err != nil {
			fmt.Printf("falied to load topologies: %v\n", err)
			os.Exit(1)
		}
		topo := topoBase.FindTopoByName(os.Args[2])
		if topo == nil {
			fmt.Printf("topology %s not found", os.Args[2])
			os.Exit(1)
		}
		topo.RemoveConfig()
		os.Exit(0)
	}

	var err error
	res := processArgs()
	err = writeSyncFile(res)
	if err != nil {
		fmt.Printf("failed to write to sync file: %v\n", err)
	}
}

func newResult(err error, opts ...ResultOptionFn) *SyncResult {
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
	return newResult(nil)
}

func configure2vethsTopo(ifName, interfaceAddress, namespaceId string, secret uint64) ConfFn {
	return func(ctx context.Context,
		vppConn api.Connection) error {

		swIfIndex, err := configureAfPacket(ctx, vppConn, ifName, interfaceAddress)
		if err != nil {
			log.FromContext(ctx).Fatalf("failed to create af packet: %v", err)
		}
		_, er := session.NewServiceClient(vppConn).AppNamespaceAddDelV2(ctx, &session.AppNamespaceAddDelV2{
			Secret:      secret,
			SwIfIndex:   swIfIndex,
			NamespaceID: namespaceId,
		})
		if er != nil {
			log.FromContext(ctx).Fatal("add app namespace ", err)
			return err
		}

		_, er1 := session.NewServiceClient(vppConn).SessionEnableDisable(ctx, &session.SessionEnableDisable{
			IsEnable: true,
		})
		if er1 != nil {
			log.FromContext(ctx).Fatalf("session enable %w", err)
			return err
		}
		return nil
	}
}

func processArgs() *SyncResult {

	if os.Args[1] == "vpp-proxy" {
		ctx, cancel := newVppContext()
		defer cancel()

		con, vppErrCh := vpphelper.StartAndDialContext(ctx, vpphelper.WithVppConfig(configTemplate))
		exitOnErrCh(ctx, cancel, vppErrCh)

		confFn := configureProxyTcp("vpp0", "10.0.0.2/24", "vpp1", "10.0.1.2/24")
		err := confFn(ctx, con)
		if err != nil {
			return newResult(err, ResultWithDesc("configuration failed"))
		}
		writeSyncFile(OkResult())
		<-ctx.Done()

	} else if os.Args[1] == "vpp-envoy" {
		var startup Stanza
		startup.
			NewStanza("session").
			Append("enable").
			Append("use-app-socket-api").
			Append("evt_qs_memfd_seg").
			Append("event-queue-length 100000").Close()
		ctx, cancel := newVppContext()
		defer cancel()

		con, vppErrCh := vpphelper.StartAndDialContext(ctx,
			vpphelper.WithVppConfig(configTemplate+startup.ToString()),
			vpphelper.WithRootDir("/tmp/vpp-envoy"))
		exitOnErrCh(ctx, cancel, vppErrCh)

		confFn := configureProxyTcp("vpp0", "10.0.0.2/24", "vpp1", "10.0.1.2/24")
		err := confFn(ctx, con)
		if err != nil {
			return newResult(err, ResultWithDesc("configuration failed"))
		}
		err0 := exechelper.Run("chmod 777 -R /tmp/vpp-envoy")
		if err0 != nil {
			return newResult(err, ResultWithDesc("setting permissions failed"))
		}
		writeSyncFile(OkResult())
		<-ctx.Done()
	} else if os.Args[1] == "http-tps" {
		ctx, cancel := newVppContext()
		defer cancel()
		con, vppErrCh := vpphelper.StartAndDialContext(ctx,
			vpphelper.WithVppConfig(configTemplate))
		exitOnErrCh(ctx, cancel, vppErrCh)

		confFn := configureProxyTcp("vpp0", "10.0.0.2/24", "vpp1", "10.0.1.2/24")
		err := confFn(ctx, con)
		if err != nil {
			return newResult(err, ResultWithDesc("configuration failed"))
		}

		_, err = session.NewServiceClient(con).SessionEnableDisable(ctx, &session.SessionEnableDisable{
			IsEnable: true,
		})
		if err != nil {
			return newResult(err, ResultWithDesc("configuration failed"))
		}
		Vppcli("", "http tps uri tcp://0.0.0.0/8080")
		writeSyncFile(OkResult())
		<-ctx.Done()
	} else if os.Args[1] == "2veths" {
		var startup Stanza
		startup.
			NewStanza("session").
			Append("enable").
			Append("use-app-socket-api").Close()

		ctx, cancel := newVppContext()
		defer cancel()
		con, vppErrCh := vpphelper.StartAndDialContext(ctx,
			vpphelper.WithVppConfig(configTemplate+startup.ToString()),
			vpphelper.WithRootDir(fmt.Sprintf("/tmp/%s", os.Args[1])))
		exitOnErrCh(ctx, cancel, vppErrCh)

		var fn func(context.Context, api.Connection) error
		if os.Args[2] == "srv" {
			fn = configure2vethsTopo("vppsrv", "10.10.10.1/24", "1", 1)
		} else {
			fn = configure2vethsTopo("vppcln", "10.10.10.2/24", "2", 2)
		}
		err := fn(ctx, con)
		if err != nil {
			return newResult(err, ResultWithDesc("configuration failed"))
		}
		writeSyncFile(OkResult())
		<-ctx.Done()
	} else if os.Args[1] == "echo-server" {
		cmd := fmt.Sprintf("vpp_echo server TX=RX socket-name /tmp/echo-srv/var/run/app_ns_sockets/1 use-app-socket-api uri %s://10.10.10.1/12344", os.Args[2])
		errCh := exechelper.Start(cmd)
		select {
		case err := <-errCh:
			writeSyncFile(newResult(err, ResultWithDesc("echo_server: ")))
		default:
		}
		writeSyncFile(OkResult())
	} else if os.Args[1] == "echo-client" {
		outBuff := bytes.NewBuffer([]byte{})
		errBuff := bytes.NewBuffer([]byte{})

		cmd := fmt.Sprintf("vpp_echo client socket-name /tmp/echo-cln/var/run/app_ns_sockets/2 use-app-socket-api uri %s://10.10.10.1/12344", os.Args[2])
		err := exechelper.Run(cmd,
			exechelper.WithStdout(outBuff), exechelper.WithStderr(errBuff),
			exechelper.WithStdout(os.Stdout), exechelper.WithStderr(os.Stderr))

		return newResult(err, ResultWithStdout(string(outBuff.String())),
			ResultWithStderr(string(errBuff.String())))
	} else if os.Args[1] == "echo-srv-internal" {
		cmd := fmt.Sprintf("test echo server %s uri tcp://10.10.10.1/1234", getArgs())
		return ApiCliInband("/tmp/2veths", cmd)
	} else if os.Args[1] == "echo-cln-internal" {
		cmd := fmt.Sprintf("test echo client %s uri tcp://10.10.10.1/1234", getArgs())
		return ApiCliInband("/tmp/2veths", cmd)
	}
	return nil
}

func ApiCliInband(root, cmd string) *SyncResult {
	ctx, _ := newVppContext()
	con := vpphelper.DialContext(ctx, filepath.Join(root, "/var/run/vpp/api.sock"))
	cliInband := vlib.CliInband{Cmd: cmd}
	cliInbandReply, err := vlib.NewServiceClient(con).CliInband(ctx, &cliInband)
	return newResult(err, ResultWithStdout(cliInbandReply.Reply))
}

func getArgs() string {
	s := ""
	for i := 2; i < len(os.Args); i++ {
		s = s + " " + os.Args[i]
	}
	return s
}
