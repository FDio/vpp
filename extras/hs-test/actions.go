package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"encoding/json"

	"git.fd.io/govpp.git/api"
	"github.com/edwarnicke/exechelper"
	"github.com/edwarnicke/govpp/binapi/af_packet"
	"github.com/edwarnicke/govpp/binapi/ethernet_types"
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
	reg("vcl-test-server", RunVclEchoServer)
	reg("vcl-test-client", RunVclEchoClient)
	reg("http-cli-srv", RunHttpCliSrv)
	reg("http-cli-cln", RunHttpCliCln)
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

func RunHttpCliSrv(args []string) *ActionResult {
	cmd := fmt.Sprintf("http cli server")
	return ApiCliInband("/tmp/2veths", cmd)
}

func RunHttpCliCln(args []string) *ActionResult {
	cmd := fmt.Sprintf("http cli client uri http://10.10.10.1/80 query %s", getArgs())
	fmt.Println(cmd)
	return ApiCliInband("/tmp/2veths", cmd)
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

func RunVclEchoServer(args []string) *ActionResult {
	f, err := os.Create("vcl_1.conf")
	if err != nil {
		return NewActionResult(err, ActionResultWithStderr(("create vcl config: ")))
	}
	fmt.Fprintf(f, vclTemplate, "/tmp/echo-srv/var/run/app_ns_sockets/1", "1")
	f.Close()

	os.Setenv("VCL_CONFIG", "/vcl_1.conf")
	cmd := fmt.Sprintf("vcl_test_server -p %s 12346", args[2])
	errCh := exechelper.Start(cmd)
	select {
	case err := <-errCh:
		writeSyncFile(NewActionResult(err, ActionResultWithDesc("vcl_test_server: ")))
	default:
	}
	writeSyncFile(OkResult())
	return nil
}

func RunVclEchoClient(args []string) *ActionResult {
	outBuff := bytes.NewBuffer([]byte{})
	errBuff := bytes.NewBuffer([]byte{})

	f, err := os.Create("vcl_2.conf")
	if err != nil {
		return NewActionResult(err, ActionResultWithStderr(("create vcl config: ")))
	}
	fmt.Fprintf(f, vclTemplate, "/tmp/echo-cln/var/run/app_ns_sockets/2", "2")
	f.Close()

	os.Setenv("VCL_CONFIG", "/vcl_2.conf")
	cmd := fmt.Sprintf("vcl_test_client -U -p %s 10.10.10.1 12346", args[2])
	err = exechelper.Run(cmd,
		exechelper.WithStdout(outBuff), exechelper.WithStderr(errBuff),
		exechelper.WithStdout(os.Stdout), exechelper.WithStderr(os.Stderr))

	return NewActionResult(err, ActionResultWithStdout(string(outBuff.String())),
		ActionResultWithStderr(string(errBuff.String())))
}

func configure2vethsTopo(ifName, interfaceAddress, namespaceId string, secret uint64, optionalHardwareAddress ...string) ConfFn {
	return func(ctx context.Context,
		vppConn api.Connection) error {

		var swIfIndex interface_types.InterfaceIndex
		var err error
		if optionalHardwareAddress == nil {
			swIfIndex, err = configureAfPacket(ctx, vppConn, ifName, interfaceAddress)
		} else {
			swIfIndex, err = configureAfPacket(ctx, vppConn, ifName, interfaceAddress, optionalHardwareAddress[0])
		}
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

	// TODO encapsulate config parsing and put it somewhere sensible (in vpp.go?)
	// ...  this place should have no idea about VppConfig struct and its fields
	var vppConfigInput VppConfig
	err := json.Unmarshal([]byte(args[2]), &vppConfigInput)
	if err != nil {
		return NewActionResult(err, ActionResultWithDesc("parsing configuration failed"))
	}

	vppConfig := fmt.Sprintf(configTemplate, "%[1]s", vppConfigInput.CliSocketFilePath)

	con, vppErrCh := vpphelper.StartAndDialContext(ctx,
		vpphelper.WithVppConfig(vppConfig+startup.ToString()),
		vpphelper.WithRootDir(fmt.Sprintf("/tmp/%s", args[1])))
	exitOnErrCh(ctx, cancel, vppErrCh)

	var fn func(context.Context, api.Connection) error
	if vppConfigInput.Variant == "srv" {
		fn = configure2vethsTopo("vppsrv", "10.10.10.1/24", "1", 1)
	} else if vppConfigInput.Variant == "srv-with-preset-hw-addr" {
		fn = configure2vethsTopo("vppsrv", "10.10.10.1/24", "1", 1, "00:00:5e:00:53:01")
	} else {
		fn = configure2vethsTopo("vppcln", "10.10.10.2/24", "2", 2)
	}
	err = fn(ctx, con)
	if err != nil {
		return NewActionResult(err, ActionResultWithDesc("configuration failed"))
	}
	writeSyncFile(OkResult())
	<-ctx.Done()
	return nil
}

func configureAfPacket(ctx context.Context, vppCon api.Connection,
	name, interfaceAddress string, optionalHardwareAddress ...string) (interface_types.InterfaceIndex, error) {
	var err error
	ifaceClient := interfaces.NewServiceClient(vppCon)
	afPacketCreate := af_packet.AfPacketCreateV2{
		UseRandomHwAddr: true,
		HostIfName:      name,
		NumRxQueues:     1,
	}
	if len(optionalHardwareAddress) > 0 {
		afPacketCreate.HwAddr, err = ethernet_types.ParseMacAddress(optionalHardwareAddress[0])
		if err != nil {
			fmt.Printf("failed to parse mac address: %v", err)
			return 0, err
		}
		afPacketCreate.UseRandomHwAddr = false
	}
	afPacketCreateRsp, err := af_packet.NewServiceClient(vppCon).AfPacketCreateV2(ctx, &afPacketCreate)
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
