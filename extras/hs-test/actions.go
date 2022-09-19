package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"git.fd.io/govpp.git/api"
	"github.com/edwarnicke/exechelper"
	"github.com/edwarnicke/govpp/binapi/af_packet"
	interfaces "github.com/edwarnicke/govpp/binapi/interface"
	"github.com/edwarnicke/govpp/binapi/interface_types"
	ip_types "github.com/edwarnicke/govpp/binapi/ip_types"
	"github.com/edwarnicke/govpp/binapi/session"
	"github.com/edwarnicke/govpp/binapi/vlib"
	"github.com/edwarnicke/vpphelper"
)

func RegisterActions() {
	cfgTable = make(map[string]func([]string) *ActionResult)
	reg("echo-srv-internal", Configure2Veths)
	reg("echo-cln-internal", Configure2Veths)
	reg("echo-client", RunEchoClient)
	reg("echo-server", RunEchoServer)
	reg("vpp-proxy", ConfigureVppProxy)
	reg("vpp-envoy", ConfigureEnvoyProxy)
	reg("http-tps", ConfigureHttpTps)
	reg("2veths", Configure2Veths)
}

func configureProxyTcp(ifName0, ipAddr0, ifName1, ipAddr1 string) ConfFn {
	return func(ctx context.Context,
		vppConn api.Connection) error {

		_, err := configureAfPacket(ctx, vppConn, ifName0, ipAddr0)
		if err != nil {
			fmt.Printf("failed to create af packet: %v", err)
			return err
		}
		_, err = configureAfPacket(ctx, vppConn, ifName1, ipAddr1)
		if err != nil {
			fmt.Printf("failed to create af packet: %v", err)
			return err
		}
		return nil
	}
}

func ConfigureVppProxy(args []string) *ActionResult {
	ctx, cancel := newVppContext()
	defer cancel()

	con, vppErrCh := vpphelper.StartAndDialContext(ctx, vpphelper.WithVppConfig(configTemplate))
	exitOnErrCh(ctx, cancel, vppErrCh)

	confFn := configureProxyTcp("vpp0", "10.0.0.2/24", "vpp1", "10.0.1.2/24")
	err := confFn(ctx, con)
	if err != nil {
		return NewActionResult(err, ActionResultWithDesc("configuration failed"))
	}
	writeSyncFile(OkResult())
	<-ctx.Done()
	return nil
}

func ConfigureEnvoyProxy(args []string) *ActionResult {
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
		return NewActionResult(err, ActionResultWithDesc("configuration failed"))
	}
	err0 := exechelper.Run("chmod 777 -R /tmp/vpp-envoy")
	if err0 != nil {
		return NewActionResult(err, ActionResultWithDesc("setting permissions failed"))
	}
	writeSyncFile(OkResult())
	<-ctx.Done()
	return nil
}

func getArgs() string {
	s := ""
	for i := 2; i < len(os.Args); i++ {
		s = s + " " + os.Args[i]
	}
	return s
}

func ApiCliInband(root, cmd string) *ActionResult {
	ctx, _ := newVppContext()
	con := vpphelper.DialContext(ctx, filepath.Join(root, "/var/run/vpp/api.sock"))
	cliInband := vlib.CliInband{Cmd: cmd}
	cliInbandReply, err := vlib.NewServiceClient(con).CliInband(ctx, &cliInband)
	return NewActionResult(err, ActionResultWithStdout(cliInbandReply.Reply))
}

func RunEchoClient(args []string) *ActionResult {
	outBuff := bytes.NewBuffer([]byte{})
	errBuff := bytes.NewBuffer([]byte{})

	cmd := fmt.Sprintf("vpp_echo client socket-name /tmp/echo-cln/var/run/app_ns_sockets/2 use-app-socket-api uri %s://10.10.10.1/12344", args[2])
	err := exechelper.Run(cmd,
		exechelper.WithStdout(outBuff), exechelper.WithStderr(errBuff),
		exechelper.WithStdout(os.Stdout), exechelper.WithStderr(os.Stderr))

	return NewActionResult(err, ActionResultWithStdout(string(outBuff.String())),
		ActionResultWithStderr(string(errBuff.String())))
}

func RunEchoServer(args []string) *ActionResult {
	cmd := fmt.Sprintf("vpp_echo server TX=RX socket-name /tmp/echo-srv/var/run/app_ns_sockets/1 use-app-socket-api uri %s://10.10.10.1/12344", args[2])
	errCh := exechelper.Start(cmd)
	select {
	case err := <-errCh:
		writeSyncFile(NewActionResult(err, ActionResultWithDesc("echo_server: ")))
	default:
	}
	writeSyncFile(OkResult())
	return nil
}

func RunEchoSrvInternal() *ActionResult {
	cmd := fmt.Sprintf("test echo server %s uri tcp://10.10.10.1/1234", getArgs())
	return ApiCliInband("/tmp/2veths", cmd)
}

func RunEchoClnInternal() *ActionResult {
	cmd := fmt.Sprintf("test echo client %s uri tcp://10.10.10.1/1234", getArgs())
	return ApiCliInband("/tmp/2veths", cmd)
}
func configure2vethsTopo(ifName, interfaceAddress, namespaceId string, secret uint64) ConfFn {
	return func(ctx context.Context,
		vppConn api.Connection) error {

		swIfIndex, err := configureAfPacket(ctx, vppConn, ifName, interfaceAddress)
		if err != nil {
			fmt.Printf("failed to create af packet: %v", err)
		}
		_, er := session.NewServiceClient(vppConn).AppNamespaceAddDelV2(ctx, &session.AppNamespaceAddDelV2{
			Secret:      secret,
			SwIfIndex:   swIfIndex,
			NamespaceID: namespaceId,
		})
		if er != nil {
			fmt.Printf("add app namespace: %v", err)
			return err
		}

		_, er1 := session.NewServiceClient(vppConn).SessionEnableDisable(ctx, &session.SessionEnableDisable{
			IsEnable: true,
		})
		if er1 != nil {
			fmt.Printf("session enable %v", err)
			return err
		}
		return nil
	}
}

func Configure2Veths(args []string) *ActionResult {
	var startup Stanza
	startup.
		NewStanza("session").
		Append("enable").
		Append("use-app-socket-api").Close()

	ctx, cancel := newVppContext()
	defer cancel()
	con, vppErrCh := vpphelper.StartAndDialContext(ctx,
		vpphelper.WithVppConfig(configTemplate+startup.ToString()),
		vpphelper.WithRootDir(fmt.Sprintf("/tmp/%s", args[1])))
	exitOnErrCh(ctx, cancel, vppErrCh)

	var fn func(context.Context, api.Connection) error
	if args[2] == "srv" {
		fn = configure2vethsTopo("vppsrv", "10.10.10.1/24", "1", 1)
	} else {
		fn = configure2vethsTopo("vppcln", "10.10.10.2/24", "2", 2)
	}
	err := fn(ctx, con)
	if err != nil {
		return NewActionResult(err, ActionResultWithDesc("configuration failed"))
	}
	writeSyncFile(OkResult())
	<-ctx.Done()
	return nil
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

func ConfigureHttpTps(args []string) *ActionResult {
	ctx, cancel := newVppContext()
	defer cancel()
	con, vppErrCh := vpphelper.StartAndDialContext(ctx,
		vpphelper.WithVppConfig(configTemplate))
	exitOnErrCh(ctx, cancel, vppErrCh)

	confFn := configureProxyTcp("vpp0", "10.0.0.2/24", "vpp1", "10.0.1.2/24")
	err := confFn(ctx, con)
	if err != nil {
		return NewActionResult(err, ActionResultWithDesc("configuration failed"))
	}

	_, err = session.NewServiceClient(con).SessionEnableDisable(ctx, &session.SessionEnableDisable{
		IsEnable: true,
	})
	if err != nil {
		return NewActionResult(err, ActionResultWithDesc("configuration failed"))
	}
	Vppcli("", "http tps uri tcp://0.0.0.0/8080")
	writeSyncFile(OkResult())
	<-ctx.Done()
	return nil
}
