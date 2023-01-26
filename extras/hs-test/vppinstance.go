package main

import (
	"encoding/json"
	"fmt"
	"github.com/edwarnicke/exechelper"
	"os"

	"go.fd.io/govpp"
	"go.fd.io/govpp/api"
	"go.fd.io/govpp/binapi/af_packet"
	interfaces "go.fd.io/govpp/binapi/interface"
	"go.fd.io/govpp/binapi/interface_types"
	"go.fd.io/govpp/binapi/ip_types"
	"go.fd.io/govpp/binapi/session"
	"go.fd.io/govpp/binapi/vpe"
	"go.fd.io/govpp/core"
)

const vppConfigTemplate = `unix {
  nodaemon
  log %[1]s/var/log/vpp/vpp.log
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
  socket-name %[1]s/var/run/vpp/api.sock
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

`

const (
	defaultCliSocketFilePath = "/var/run/vpp/cli.sock"
	defaultApiSocketFilePath = "/var/run/vpp/api.sock"
)

type VppInstance struct {
	container      *Container
	config         *VppConfig
	actionFuncName string
	connection     *core.Connection
	apiChannel     api.Channel
}

type VppConfig struct {
	variant           string
	cliSocketFilePath string
	additionalConfig  Stanza
}

func (vc *VppConfig) getTemplate() string {
	return fmt.Sprintf(vppConfigTemplate, "%[1]s", vc.cliSocketFilePath)
}

func (vpp *VppInstance) set2VethsServer() {
	vpp.actionFuncName = "Configure2Veths"
	vpp.config.variant = "srv"
}

func (vpp *VppInstance) set2VethsClient() {
	vpp.actionFuncName = "Configure2Veths"
	vpp.config.variant = "cln"
}

func (vpp *VppInstance) setVppProxy() {
	vpp.actionFuncName = "ConfigureVppProxy"
}

func (vpp *VppInstance) setEnvoyProxy() {
	vpp.actionFuncName = "ConfigureEnvoyProxy"
}

func (vpp *VppInstance) setCliSocket(filePath string) {
	vpp.config.cliSocketFilePath = filePath
}

func (vpp *VppInstance) getCliSocket() string {
	return fmt.Sprintf("%s%s", vpp.container.GetContainerWorkDir(), vpp.config.cliSocketFilePath)
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

/**
 * TODO separate the four sections into their own functions
 */
func (vpp *VppInstance) start() error {
	// Create folders
	containerWorkDir := vpp.container.GetContainerWorkDir()

	vpp.container.exec("mkdir --mode=0700 -p " + vpp.getRunDir())
	vpp.container.exec("mkdir --mode=0700 -p " + vpp.getLogDir())
	vpp.container.exec("mkdir --mode=0700 -p " + vpp.getEtcDir())

	// Create startup.conf and copy it to container
	f, err := os.CreateTemp("/tmp", "startup.conf")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())

	configContent := fmt.Sprintf(vppConfigTemplate, containerWorkDir, vpp.config.cliSocketFilePath)
	configContent += vpp.config.additionalConfig.ToString()
	if _, err := f.Write([]byte(configContent)); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	startupFileName := vpp.getEtcDir() + "/startup.conf"
	vpp.container.copy(f.Name(), startupFileName)

	// Start VPP
	if vpp.container.exec("vpp -c " + startupFileName); err != nil {
		return err
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

	fmt.Println("Connection OK.")
	fmt.Printf("VPP instance address: %p\n", vpp)
	fmt.Printf("Channel address: %p\n", &vpp.apiChannel)
	fmt.Printf("Connection address: %p\n", vpp.connection)
	return nil
}

func (vpp *VppInstance) vppctl(command string) (string, error) {
	cliExecCommand := fmt.Sprintf("docker exec --detach=false %[1]s vppctl -s %[2]s %[3]s",
		vpp.container.name, vpp.getCliSocket(), command)
	output, err := exechelper.CombinedOutput(cliExecCommand)
	if err != nil {
		return "", fmt.Errorf("vppctl failed: %s", err)
	}

	return string(output), nil
}

func NewVppInstance(c *Container) *VppInstance {
	vppConfig := new(VppConfig)
	vppConfig.cliSocketFilePath = defaultCliSocketFilePath
	vpp := new(VppInstance)
	vpp.container = c
	vpp.config = vppConfig
	return vpp
}

func serializeVppConfig(vppConfig VppConfig) (string, error) {
	serializedConfig, err := json.Marshal(vppConfig)
	if err != nil {
		return "", fmt.Errorf("vpp start failed: serializing configuration failed: %s", err)
	}
	return string(serializedConfig), nil
}

func deserializeVppConfig(input string) (VppConfig, error) {
	var vppConfig VppConfig
	err := json.Unmarshal([]byte(input), &vppConfig)
	if err != nil {
		// Since input is not a  valid JSON it is going be used as a variant value
		// for compatibility reasons
		vppConfig.variant = input
		vppConfig.cliSocketFilePath = defaultCliSocketFilePath
	}
	return vppConfig, nil
}

func (vpp *VppInstance) showVersion() error {
	fmt.Println("Retrieving version..")

	req := &vpe.ShowVersion{}
	reply := &vpe.ShowVersionReply{}

	if err := vpp.apiChannel.SendRequest(req).ReceiveReply(reply); err != nil {
		fmt.Println("retrieving version error:", err)
	}

	fmt.Printf("VPP version: %q\n", reply.Version)
	fmt.Println()

	fmt.Println("Dumping interfaces..")

	n := 0
	reqCtx := vpp.apiChannel.SendMultiRequest(&interfaces.SwInterfaceDump{
		SwIfIndex: ^interface_types.InterfaceIndex(0),
	})
	for {
		msg := &interfaces.SwInterfaceDetails{}
		stop, err := reqCtx.ReceiveReply(msg)
		if stop {
			break
		}
		if err != nil {
			fmt.Println(err, "dumping interfaces")
			return err
		}
		n++
		fmt.Printf(" - interface #%d: %+v\n", n, msg)
	}

	fmt.Println("OK")
	fmt.Println()

	return nil
}

func (vpp *VppInstance) createAfPacket(
	iface NetConfig,
) (interface_types.InterfaceIndex, error) {
	veth := iface.(NetworkInterfaceVeth)

	createReq := &af_packet.AfPacketCreateV2{
		UseRandomHwAddr: true,
		HostIfName:      veth.GetName(),
	}
	createReply := &af_packet.AfPacketCreateV2Reply{}

	if err := vpp.apiChannel.SendRequest(createReq).ReceiveReply(createReply); err != nil {
		return 0, err
	}
	veth.index = createReply.SwIfIndex

	// Add address
	upReq := &interfaces.SwInterfaceSetFlags{
		SwIfIndex: veth.index,
		Flags:     interface_types.IF_STATUS_API_FLAG_ADMIN_UP,
	}
	upReply := &interfaces.SwInterfaceSetFlagsReply{}

	if err := vpp.apiChannel.SendRequest(upReq).ReceiveReply(upReply); err != nil {
		return 0, err
	}

	// Set to up
	ipPrefix, err := ip_types.ParseAddressWithPrefix(veth.ip4Address)
	if err != nil {
		return 0, err
	}
	addressReq := &interfaces.SwInterfaceAddDelAddress{
		IsAdd:     true,
		SwIfIndex: veth.index,
		Prefix:    ipPrefix,
	}
	addressReply := &interfaces.SwInterfaceAddDelAddressReply{}

	if err := vpp.apiChannel.SendRequest(addressReq).ReceiveReply(addressReply); err != nil {
		return 0, err
	}

	return veth.index, nil
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

func (vpp *VppInstance) disconnect() {
	fmt.Println("Disconnecting from VPP")
	vpp.connection.Disconnect()
	vpp.apiChannel.Close()
}
