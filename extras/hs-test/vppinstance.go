package main

import (
	"fmt"
	"github.com/edwarnicke/exechelper"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.fd.io/govpp"
	"go.fd.io/govpp/api"
	"go.fd.io/govpp/binapi/af_packet"
	interfaces "go.fd.io/govpp/binapi/interface"
	"go.fd.io/govpp/binapi/interface_types"
	"go.fd.io/govpp/binapi/session"
	"go.fd.io/govpp/binapi/tapv2"
	"go.fd.io/govpp/binapi/vpe"
	"go.fd.io/govpp/core"
)

const vppConfigTemplate = `unix {
  nodaemon
  log %[1]s%[4]s
  full-coredump
  cli-listen %[1]s%[2]s
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
  socket-name %[1]s%[3]s
}

statseg {
  socket-name %[1]s/var/run/vpp/stats.sock
}

plugins {
  plugin default { disable }

  plugin unittest_plugin.so { enable }
  plugin quic_plugin.so { enable }
  plugin af_packet_plugin.so { enable }
  plugin hs_apps_plugin.so { enable }
  plugin http_plugin.so { enable }
}

logging {
  default-log-level debug
  default-syslog-log-level debug
}

`

const (
	defaultCliSocketFilePath = "/var/run/vpp/cli.sock"
	defaultApiSocketFilePath = "/var/run/vpp/api.sock"
	defaultLogFilePath       = "/var/log/vpp/vpp.log"
)

type VppInstance struct {
	container        *Container
	additionalConfig Stanza
	connection       *core.Connection
	apiChannel       api.Channel
}

func (vpp *VppInstance) Suite() *HstSuite {
	return vpp.container.suite
}

func (vpp *VppInstance) getCliSocket() string {
	return fmt.Sprintf("%s%s", vpp.container.GetContainerWorkDir(), defaultCliSocketFilePath)
}

func (vpp *VppInstance) getRunDir() string {
	return vpp.container.GetContainerWorkDir() + "/var/run/vpp"
}

func (vpp *VppInstance) getLogDir() string {
	return vpp.container.GetContainerWorkDir() + "/var/log/vpp"
}

func (vpp *VppInstance) getEtcDir() string {
	return vpp.container.GetContainerWorkDir() + "/etc/vpp"
}

func (vpp *VppInstance) start() error {
	// Create folders
	containerWorkDir := vpp.container.GetContainerWorkDir()

	vpp.container.exec("mkdir --mode=0700 -p " + vpp.getRunDir())
	vpp.container.exec("mkdir --mode=0700 -p " + vpp.getLogDir())
	vpp.container.exec("mkdir --mode=0700 -p " + vpp.getEtcDir())

	// Create startup.conf inside the container
	configContent := fmt.Sprintf(
		vppConfigTemplate,
		containerWorkDir,
		defaultCliSocketFilePath,
		defaultApiSocketFilePath,
		defaultLogFilePath,
	)
	configContent += vpp.additionalConfig.ToString()
	startupFileName := vpp.getEtcDir() + "/startup.conf"
	vpp.container.createFile(startupFileName, configContent)

	if *IsVppDebug {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT)
		cont := make(chan bool, 1)
		go func() {
			sig := <-sig
			fmt.Println(sig)
			cont <- true
		}()

		// Start VPP in GDB and wait for user to attach it
		vpp.container.execServer("su -c \"gdb -ex run --args vpp -c " + startupFileName + " &> /proc/1/fd/1\"")
		fmt.Println("run following command in different terminal:")
		fmt.Println("docker exec -it " + vpp.container.name + " gdb -ex \"attach $(docker exec " + vpp.container.name + " pidof gdb)\"")
		fmt.Println("Afterwards press CTRL+C to continue")
		<-cont
		fmt.Println("continuing...")
	} else {
		// Start VPP
		vpp.container.execServer("su -c \"vpp -c " + startupFileName + " &> /proc/1/fd/1\"")
	}

	// Connect to VPP and store the connection
	sockAddress := vpp.container.GetHostWorkDir() + defaultApiSocketFilePath
	conn, connEv, err := govpp.AsyncConnect(
		sockAddress,
		core.DefaultMaxReconnectAttempts,
		core.DefaultReconnectInterval)
	if err != nil {
		fmt.Println("async connect error: ", err)
	}
	vpp.connection = conn

	// ... wait for Connected event
	e := <-connEv
	if e.State != core.Connected {
		fmt.Println("connecting to VPP failed: ", e.Error)
	}

	// ... check compatibility of used messages
	ch, err := conn.NewAPIChannel()
	if err != nil {
		fmt.Println("creating channel failed: ", err)
	}
	if err := ch.CheckCompatiblity(vpe.AllMessages()...); err != nil {
		fmt.Println("compatibility error: ", err)
	}
	if err := ch.CheckCompatiblity(interfaces.AllMessages()...); err != nil {
		fmt.Println("compatibility error: ", err)
	}
	vpp.apiChannel = ch

	return nil
}

func (vpp *VppInstance) vppctl(command string, arguments ...any) string {
	vppCliCommand := fmt.Sprintf(command, arguments...)
	containerExecCommand := fmt.Sprintf("docker exec --detach=false %[1]s vppctl -s %[2]s %[3]s",
		vpp.container.name, vpp.getCliSocket(), vppCliCommand)
	vpp.Suite().log(containerExecCommand)
	output, err := exechelper.CombinedOutput(containerExecCommand)
	vpp.Suite().assertNil(err)

	return string(output)
}

func (vpp *VppInstance) waitForApp(appName string, timeout int) {
	for i := 0; i < timeout; i++ {
		o := vpp.vppctl("show app")
		if strings.Contains(o, appName) {
			return
		}
		time.Sleep(1 * time.Second)
	}
	vpp.Suite().assertNil(1, "Timeout while waiting for app '%s'", appName)
	return
}

func (vpp *VppInstance) createAfPacket(
	veth *NetInterface,
) (interface_types.InterfaceIndex, error) {
	createReq := &af_packet.AfPacketCreateV2{
		UseRandomHwAddr: true,
		HostIfName:      veth.Name(),
	}
	if veth.HwAddress() != (MacAddress{}) {
		createReq.UseRandomHwAddr = false
		createReq.HwAddr = veth.HwAddress()
	}
	createReply := &af_packet.AfPacketCreateV2Reply{}

	if err := vpp.apiChannel.SendRequest(createReq).ReceiveReply(createReply); err != nil {
		return 0, err
	}
	veth.SetIndex(createReply.SwIfIndex)

	// Set to up
	upReq := &interfaces.SwInterfaceSetFlags{
		SwIfIndex: veth.Index(),
		Flags:     interface_types.IF_STATUS_API_FLAG_ADMIN_UP,
	}
	upReply := &interfaces.SwInterfaceSetFlagsReply{}

	if err := vpp.apiChannel.SendRequest(upReq).ReceiveReply(upReply); err != nil {
		return 0, err
	}

	// Add address
	if veth.AddressWithPrefix() == (AddressWithPrefix{}) {
		var err error
		var ip4Address string
		if ip4Address, err = veth.addresser.NewIp4Address(veth.Peer().networkNumber); err == nil {
			veth.SetAddress(ip4Address)
		} else {
			return 0, err
		}
	}
	addressReq := &interfaces.SwInterfaceAddDelAddress{
		IsAdd:     true,
		SwIfIndex: veth.Index(),
		Prefix:    veth.AddressWithPrefix(),
	}
	addressReply := &interfaces.SwInterfaceAddDelAddressReply{}

	if err := vpp.apiChannel.SendRequest(addressReq).ReceiveReply(addressReply); err != nil {
		return 0, err
	}

	return veth.Index(), nil
}

func (vpp *VppInstance) addAppNamespace(
	secret uint64,
	ifx interface_types.InterfaceIndex,
	namespaceId string,
) error {
	req := &session.AppNamespaceAddDelV2{
		Secret:      secret,
		SwIfIndex:   ifx,
		NamespaceID: namespaceId,
	}
	reply := &session.AppNamespaceAddDelV2Reply{}

	if err := vpp.apiChannel.SendRequest(req).ReceiveReply(reply); err != nil {
		return err
	}

	sessionReq := &session.SessionEnableDisable{
		IsEnable: true,
	}
	sessionReply := &session.SessionEnableDisableReply{}

	if err := vpp.apiChannel.SendRequest(sessionReq).ReceiveReply(sessionReply); err != nil {
		return err
	}

	return nil
}

func (vpp *VppInstance) createTap(
	tap *NetInterface,
	tapId ...uint32,
) error {
	var id uint32 = 1
	if len(tapId) > 0 {
		id = tapId[0]
	}
	createTapReq := &tapv2.TapCreateV2{
		ID:               id,
		HostIfNameSet:    true,
		HostIfName:       tap.Name(),
		HostIP4PrefixSet: true,
		HostIP4Prefix:    tap.IP4AddressWithPrefix(),
	}
	createTapReply := &tapv2.TapCreateV2Reply{}

	// Create tap interface
	if err := vpp.apiChannel.SendRequest(createTapReq).ReceiveReply(createTapReply); err != nil {
		return err
	}

	// Add address
	addAddressReq := &interfaces.SwInterfaceAddDelAddress{
		IsAdd:     true,
		SwIfIndex: createTapReply.SwIfIndex,
		Prefix:    tap.Peer().AddressWithPrefix(),
	}
	addAddressReply := &interfaces.SwInterfaceAddDelAddressReply{}

	if err := vpp.apiChannel.SendRequest(addAddressReq).ReceiveReply(addAddressReply); err != nil {
		return err
	}

	// Set interface to up
	upReq := &interfaces.SwInterfaceSetFlags{
		SwIfIndex: createTapReply.SwIfIndex,
		Flags:     interface_types.IF_STATUS_API_FLAG_ADMIN_UP,
	}
	upReply := &interfaces.SwInterfaceSetFlagsReply{}

	if err := vpp.apiChannel.SendRequest(upReq).ReceiveReply(upReply); err != nil {
		return err
	}

	return nil
}

func (vpp *VppInstance) saveLogs() {
	logTarget := vpp.container.getLogDirPath() + "vppinstance-" + vpp.container.name + ".log"
	logSource := vpp.container.GetHostWorkDir() + defaultLogFilePath
	cmd := exec.Command("cp", logSource, logTarget)
	vpp.Suite().T().Helper()
	vpp.Suite().log(cmd.String())
	cmd.Run()
}

func (vpp *VppInstance) disconnect() {
	vpp.connection.Disconnect()
	vpp.apiChannel.Close()
}
