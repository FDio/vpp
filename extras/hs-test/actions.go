package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"git.fd.io/govpp.git/api"
	"github.com/edwarnicke/exechelper"
	"github.com/edwarnicke/govpp/binapi/af_packet"
	"github.com/edwarnicke/govpp/binapi/ethernet_types"
	interfaces "github.com/edwarnicke/govpp/binapi/interface"
	"github.com/edwarnicke/govpp/binapi/interface_types"
	ip_types "github.com/edwarnicke/govpp/binapi/ip_types"
	"github.com/edwarnicke/govpp/binapi/session"
	"github.com/edwarnicke/govpp/binapi/tapv2"
	"github.com/edwarnicke/govpp/binapi/vlib"
	"github.com/edwarnicke/vpphelper"

	newgovpp "go.fd.io/govpp"
	newvpe "go.fd.io/govpp/binapi/vpe"
	newcore "go.fd.io/govpp/core"
	newinterfaces "go.fd.io/govpp/binapi/interface"

	newapi "go.fd.io/govpp/api"
	newaf_packet "go.fd.io/govpp/binapi/af_packet"
	newethernet_types "go.fd.io/govpp/binapi/ethernet_types"
	newinterface_types "go.fd.io/govpp/binapi/interface_types"
	newip_types "go.fd.io/govpp/binapi/ip_types"
	newsession "go.fd.io/govpp/binapi/session"

	"os/signal"
)

var (
	workDir, _ = os.Getwd()
)

type ConfFn func(context.Context, api.Connection) error
type NewConfFn func(context.Context, newapi.Connection) error

type Actions struct {
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

func (a *Actions) RunHttpCliSrv(args []string) *ActionResult {
	cmd := fmt.Sprintf("http cli server")
	return ApiCliInband(workDir, cmd)
}

func (a *Actions) RunHttpCliCln(args []string) *ActionResult {
	cmd := fmt.Sprintf("http cli client uri http://10.10.10.1/80 query %s", getArgs())
	fmt.Println(cmd)
	return ApiCliInband(workDir, cmd)
}

func (a *Actions) ConfigureVppProxy(args []string) *ActionResult {
	ctx, cancel := newVppContext()
	defer cancel()

	con, vppErrCh := vpphelper.StartAndDialContext(ctx,
		vpphelper.WithVppConfig(configTemplate),
		vpphelper.WithRootDir(workDir))
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

func (a *Actions) ConfigureEnvoyProxy(args []string) *ActionResult {
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
		vpphelper.WithRootDir(workDir))
	exitOnErrCh(ctx, cancel, vppErrCh)

	confFn := configureProxyTcp("vpp0", "10.0.0.2/24", "vpp1", "10.0.1.2/24")
	err := confFn(ctx, con)
	if err != nil {
		return NewActionResult(err, ActionResultWithDesc("configuration failed"))
	}
	err0 := exechelper.Run("chmod 777 -R " + workDir)
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

func (a *Actions) RunEchoClient(args []string) *ActionResult {
	outBuff := bytes.NewBuffer([]byte{})
	errBuff := bytes.NewBuffer([]byte{})

	cmd := fmt.Sprintf("vpp_echo client socket-name %s/var/run/app_ns_sockets/2 use-app-socket-api uri %s://10.10.10.1/12344", workDir, args[2])
	err := exechelper.Run(cmd,
		exechelper.WithStdout(outBuff), exechelper.WithStderr(errBuff),
		exechelper.WithStdout(os.Stdout), exechelper.WithStderr(os.Stderr))

	return NewActionResult(err, ActionResultWithStdout(string(outBuff.String())),
		ActionResultWithStderr(string(errBuff.String())))
}

func (a *Actions) NewRunEchoClient(args []string) *ActionResult {
	app_socket := fmt.Sprintf("%s/var/run/app_ns_sockets/2", workDir)
	uri := fmt.Sprintf("%s://10.10.10.1/12344", args[2])
	cmd := exec.Command("vpp_echo", "client", "socket-name", app_socket,
		"use-app-socket-api", "uri", uri)
	byteoutput, err := cmd.CombinedOutput()
	if err != nil {
		// log error
	}
	fmt.Println(string(byteoutput))

	return OkResult()
}

func (a *Actions) RunEchoServer(args []string) *ActionResult {
	cmd := fmt.Sprintf("vpp_echo server TX=RX socket-name %s/var/run/app_ns_sockets/1 use-app-socket-api uri %s://10.10.10.1/12344", workDir, args[2])
	errCh := exechelper.Start(cmd)
	select {
	case err := <-errCh:
		writeSyncFile(NewActionResult(err, ActionResultWithDesc("echo_server: ")))
	default:
	}
	writeSyncFile(OkResult())
	return nil
}

func (a *Actions) NewRunEchoServer(args []string) *ActionResult {
	app_socket := fmt.Sprintf("%s/var/run/app_ns_sockets/1", workDir)
	uri := fmt.Sprintf("%s://10.10.10.1/12344", args[2])
	cmd := exec.Command("vpp_echo", "server", "TX=RX", "socket-name",
		app_socket, "use-app-socket-api", "uri", uri)
	err := cmd.Start()
	if err != nil {
		// log error
	}
	err = cmd.Process.Release()
	if err != nil {
		// log error
	}
	return OkResult()
}

func (a *Actions) RunEchoSrvInternal(args []string) *ActionResult {
	cmd := fmt.Sprintf("test echo server %s uri tcp://10.10.10.1/1234", getArgs())
	return ApiCliInband(workDir, cmd)
}

func (a *Actions) RunEchoClnInternal(args []string) *ActionResult {
	cmd := fmt.Sprintf("test echo client %s uri tcp://10.10.10.1/1234", getArgs())
	return ApiCliInband(workDir, cmd)
}

func (a *Actions) RunVclEchoServer(args []string) *ActionResult {
	f, err := os.Create("vcl_1.conf")
	if err != nil {
		return NewActionResult(err, ActionResultWithStderr(("create vcl config: ")))
	}
	socketPath := fmt.Sprintf("%s/var/run/app_ns_sockets/1", workDir)
	fmt.Fprintf(f, vclTemplate, socketPath, "1")
	f.Close()

	os.Setenv("VCL_CONFIG", "./vcl_1.conf")
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

func (a *Actions) RunVclEchoClient(args []string) *ActionResult {
	outBuff := bytes.NewBuffer([]byte{})
	errBuff := bytes.NewBuffer([]byte{})

	f, err := os.Create("vcl_2.conf")
	if err != nil {
		return NewActionResult(err, ActionResultWithStderr(("create vcl config: ")))
	}
	socketPath := fmt.Sprintf("%s/var/run/app_ns_sockets/2", workDir)
	fmt.Fprintf(f, vclTemplate, socketPath, "2")
	f.Close()

	os.Setenv("VCL_CONFIG", "./vcl_2.conf")
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

func newConfigure2vethsTopo(
	ifName,
	interfaceAddress,
	namespaceId string,
	secret uint64, optionalHardwareAddress ...string,
) NewConfFn {
	return func(ctx context.Context,
		vppConn newapi.Connection) error {

		var swIfIndex newinterface_types.InterfaceIndex
		var err error
		if optionalHardwareAddress == nil {
			swIfIndex, err = newConfigureAfPacket(ctx, vppConn, ifName, interfaceAddress)
		} else {
			swIfIndex, err = newConfigureAfPacket(ctx, vppConn, ifName, interfaceAddress, optionalHardwareAddress[0])
		}
		if err != nil {
			fmt.Printf("failed to create af packet: %v", err)
		}
		_, er := newsession.NewServiceClient(vppConn).AppNamespaceAddDelV2(ctx, &newsession.AppNamespaceAddDelV2{
			Secret:      secret,
			SwIfIndex:   swIfIndex,
			NamespaceID: namespaceId,
		})
		if er != nil {
			fmt.Printf("add app namespace: %v", err)
			return err
		}

		_, er1 := newsession.NewServiceClient(vppConn).SessionEnableDisable(ctx, &newsession.SessionEnableDisable{
			IsEnable: true,
		})
		if er1 != nil {
			fmt.Printf("session enable %v", err)
			return err
		}
		return nil
	}
}

func (a *Actions) Configure2Veths(args []string) *ActionResult {
	var startup Stanza
	startup.
		NewStanza("session").
		Append("enable").
		Append("use-app-socket-api").Close()

	ctx, cancel := newVppContext()
	defer cancel()

	vppConfig, err := deserializeVppConfig(args[2])
	if err != nil {
		return NewActionResult(err, ActionResultWithDesc("deserializing configuration failed"))
	}

	con, vppErrCh := vpphelper.StartAndDialContext(ctx,
		vpphelper.WithVppConfig(vppConfig.getTemplate()+startup.ToString()),
		vpphelper.WithRootDir(workDir))
	exitOnErrCh(ctx, cancel, vppErrCh)

	var fn func(context.Context, api.Connection) error
	switch vppConfig.Variant {
	case "srv":
		fn = configure2vethsTopo("vppsrv", "10.10.10.1/24", "1", 1)
	case "srv-with-preset-hw-addr":
		fn = configure2vethsTopo("vppsrv", "10.10.10.1/24", "1", 1, "00:00:5e:00:53:01")
	case "cln":
		fallthrough
	default:
		fn = configure2vethsTopo("vppcln", "10.10.10.2/24", "2", 2)
	}
	err = fn(ctx, con)
//	if err != nil {
//		return NewActionResult(err, ActionResultWithDesc("configuration failed"))
//	}
//	writeSyncFile(OkResult())
//	<-ctx.Done()
	return nil
}

func (a *Actions) ConfigureVpp(args []string) *ActionResult {
	// TODO put each section in its own function
	// 1.) Prepare contents of VPP config file
	var startup Stanza
	startup.
		NewStanza("session").
		Append("enable").
		Append("use-app-socket-api").Close()
	vppConfig, _ := deserializeVppConfig(args[2])
	fullTemplate := vppConfig.getTemplate() + startup.ToString()
	finalVppConfig := fmt.Sprintf(fullTemplate, workDir)

	// 2.) Create folders and config file
	if err := os.MkdirAll(filepath.Join(workDir, "/var/run/vpp"), 0700); os.IsNotExist(err) {
		return NewActionResult(err, ActionResultWithStderr("configuration failed"))
	}
	if err := os.MkdirAll(filepath.Join(workDir, "/var/log/vpp"), 0700); os.IsNotExist(err) {
		return NewActionResult(err, ActionResultWithStderr("configuration failed"))
	}
	if err := os.MkdirAll(filepath.Join(workDir, "/etc/vpp"), 0700); os.IsNotExist(err) {
		return NewActionResult(err, ActionResultWithStderr("configuration failed"))
	}
	finalVppConfigFilepath := filepath.Join(workDir, "/etc/vpp/startup.conf") 
	f, err := os.Create(finalVppConfigFilepath)
	if err != nil {
		return NewActionResult(err, ActionResultWithStderr(("create vcl config: ")))
	}
	fmt.Fprintf(f, finalVppConfig)
	f.Close()

	// 3.) Start VPP
	cmd := exec.Command("vpp", "-c", finalVppConfigFilepath)
        err = cmd.Start()
        if err != nil {
                fmt.Println("error", err)
        }
        fmt.Printf("Command started...")
        err = cmd.Process.Release()
        if err != nil {
                fmt.Printf("Command finished with error: %v", err)
        }

	// 4.) Connect to VPP via API socket
	// connect to VPP asynchronously
	sockAddress := workDir + "/var/run/vpp/api.sock"
	conn, connEv, err := newgovpp.AsyncConnect(
		sockAddress,
		newcore.DefaultMaxReconnectAttempts,
		newcore.DefaultReconnectInterval)
	if err != nil {
		fmt.Println("async connect error: ", err)
	}
	defer conn.Disconnect()

	// wait for Connected event
	e := <-connEv
	if e.State != newcore.Connected {
		fmt.Println("connecting to VPP failed: ", e.Error)
	}

	// check compatibility of used messages
	ch, err := conn.NewAPIChannel()
	if err != nil {
		fmt.Println("creating channel failed: ", err)
	}
	defer ch.Close()
	if err := ch.CheckCompatiblity(newvpe.AllMessages()...); err != nil {
		fmt.Println("compatibility error: ", err)
	}
	if err := ch.CheckCompatiblity(newinterfaces.AllMessages()...); err != nil {
		fmt.Println("compatibility error: ", err)
	}

	var fn func(context.Context, newapi.Connection) error
	switch vppConfig.Variant {
	case "srv":
		fn = newConfigure2vethsTopo("vppsrv", "10.10.10.1/24", "1", 1)
	case "srv-with-preset-hw-addr":
		fn = newConfigure2vethsTopo("vppsrv", "10.10.10.1/24", "1", 1, "00:00:5e:00:53:01")
	case "cln":
		fallthrough
	default:
		fn = newConfigure2vethsTopo("vppcln", "10.10.10.2/24", "2", 2)
	}

	ctx, _ := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
	)
	err = fn(ctx, conn)


	return OkResult()
}

func newConfigureAfPacket(ctx context.Context, vppCon newapi.Connection,
	name, interfaceAddress string, optionalHardwareAddress ...string) (newinterface_types.InterfaceIndex, error) {
	var err error
	ifaceClient := newinterfaces.NewServiceClient(vppCon)
	afPacketCreate := newaf_packet.AfPacketCreateV2{
		UseRandomHwAddr: true,
		HostIfName:      name,
		NumRxQueues:     1,
	}
	if len(optionalHardwareAddress) > 0 {
		afPacketCreate.HwAddr, err = newethernet_types.ParseMacAddress(optionalHardwareAddress[0])
		if err != nil {
			fmt.Printf("failed to parse mac address: %v", err)
			return 0, err
		}
		afPacketCreate.UseRandomHwAddr = false
	}
	afPacketCreateRsp, err := newaf_packet.NewServiceClient(vppCon).AfPacketCreateV2(ctx, &afPacketCreate)
	if err != nil {
		fmt.Printf("failed to create af packet: %v", err)
		return 0, err
	}
	_, err = ifaceClient.SwInterfaceSetFlags(ctx, &newinterfaces.SwInterfaceSetFlags{
		SwIfIndex: afPacketCreateRsp.SwIfIndex,
		Flags:     newinterface_types.IF_STATUS_API_FLAG_ADMIN_UP,
	})
	if err != nil {
		fmt.Printf("set interface state up failed: %v\n", err)
		return 0, err
	}
	ipPrefix, err := newip_types.ParseAddressWithPrefix(interfaceAddress)
	if err != nil {
		fmt.Printf("parse ip address %v\n", err)
		return 0, err
	}
	ipAddress := &newinterfaces.SwInterfaceAddDelAddress{
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

func (a *Actions) ConfigureHttpTps(args []string) *ActionResult {
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

func (a *Actions) ConfigureTap(args []string) *ActionResult {
	var startup Stanza
	startup.
		NewStanza("session").
		Append("enable").
		Append("use-app-socket-api").Close()

	ctx, cancel := newVppContext()
	defer cancel()
	con, vppErrCh := vpphelper.StartAndDialContext(ctx,
		vpphelper.WithRootDir(workDir),
		vpphelper.WithVppConfig(configTemplate+startup.ToString()))
	exitOnErrCh(ctx, cancel, vppErrCh)
	ifaceClient := interfaces.NewServiceClient(con)

	pref, err := ip_types.ParseIP4Prefix("10.10.10.2/24")
	if err != nil {
		return NewActionResult(err, ActionResultWithDesc("failed to parse ip4 address"))
	}
	createTapReply, err := tapv2.NewServiceClient(con).TapCreateV2(ctx, &tapv2.TapCreateV2{
		HostIfNameSet:    true,
		HostIfName:       "tap0",
		HostIP4PrefixSet: true,
		HostIP4Prefix:    ip_types.IP4AddressWithPrefix(pref),
	})
	if err != nil {
		return NewActionResult(err, ActionResultWithDesc("failed to configure tap"))
	}
	ipPrefix, err := ip_types.ParseAddressWithPrefix("10.10.10.1/24")
	if err != nil {
		return NewActionResult(err, ActionResultWithDesc("parsing ip address failed"))
	}
	ipAddress := &interfaces.SwInterfaceAddDelAddress{
		IsAdd:     true,
		SwIfIndex: createTapReply.SwIfIndex,
		Prefix:    ipPrefix,
	}
	_, errx := ifaceClient.SwInterfaceAddDelAddress(ctx, ipAddress)
	if errx != nil {
		return NewActionResult(err, ActionResultWithDesc("configuring ip address failed"))
	}
	_, err = ifaceClient.SwInterfaceSetFlags(ctx, &interfaces.SwInterfaceSetFlags{
		SwIfIndex: createTapReply.SwIfIndex,
		Flags:     interface_types.IF_STATUS_API_FLAG_ADMIN_UP,
	})
	if err != nil {
		return NewActionResult(err, ActionResultWithDesc("failed to set interface state"))
	}
	_, err = session.NewServiceClient(con).SessionEnableDisable(ctx, &session.SessionEnableDisable{
		IsEnable: true,
	})
	if err != nil {
		return NewActionResult(err, ActionResultWithDesc("configuration failed"))
	}
	writeSyncFile(OkResult())
	<-ctx.Done()
	return nil
}
