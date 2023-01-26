package main

import (
	"encoding/json"
	"fmt"
	"github.com/edwarnicke/exechelper"

	"go.fd.io/govpp"
	"go.fd.io/govpp/api"
	"go.fd.io/govpp/binapi/af_packet"
	interfaces "go.fd.io/govpp/binapi/interface"
	"go.fd.io/govpp/binapi/interface_types"
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
	Variant           string
	CliSocketFilePath string
	additionalConfig  Stanza
}

func (vc *VppConfig) getTemplate() string {
	return fmt.Sprintf(vppConfigTemplate, "%[1]s", vc.CliSocketFilePath)
}

func (vpp *VppInstance) set2VethsServer() {
	vpp.actionFuncName = "Configure2Veths"
	vpp.config.Variant = "srv"
}

func (vpp *VppInstance) set2VethsClient() {
	vpp.actionFuncName = "Configure2Veths"
	vpp.config.Variant = "cln"
}

func (vpp *VppInstance) setVppProxy() {
	vpp.actionFuncName = "ConfigureVppProxy"
}

func (vpp *VppInstance) setEnvoyProxy() {
	vpp.actionFuncName = "ConfigureEnvoyProxy"
}

func (vpp *VppInstance) setCliSocket(filePath string) {
	vpp.config.CliSocketFilePath = filePath
}

func (vpp *VppInstance) getCliSocket() string {
	return fmt.Sprintf("%s%s", vpp.container.GetContainerWorkDir(), vpp.config.CliSocketFilePath)
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

func (vpp *VppInstance) legacyStart() error {
	if vpp.actionFuncName == "" {
		return fmt.Errorf("vpp start failed: action function name must not be blank")
	}

	serializedConfig, err := serializeVppConfig(vpp.config)
	if err != nil {
		return fmt.Errorf("serialize vpp config: %v", err)
	}
	args := fmt.Sprintf("%s '%s'", vpp.actionFuncName, serializedConfig)
	_, err = vpp.container.execAction(args)
	if err != nil {
		return fmt.Errorf("vpp start failed: %s", err)
	}
	return nil
}

func (vpp *VppInstance) start() error {
	if vpp.actionFuncName != "" {
		return vpp.legacyStart()
	}

	// Create folders
	containerWorkDir := vpp.container.GetContainerWorkDir()

	vpp.container.exec("mkdir --mode=0700 -p " + vpp.getRunDir())
	vpp.container.exec("mkdir --mode=0700 -p " + vpp.getLogDir())
	vpp.container.exec("mkdir --mode=0700 -p " + vpp.getEtcDir())

	// Create startup.conf inside the container
	configContent := fmt.Sprintf(vppConfigTemplate, containerWorkDir, vpp.config.CliSocketFilePath)
	configContent += vpp.config.additionalConfig.ToString()
	startupFileName := vpp.getEtcDir() + "/startup.conf"
	vpp.container.createFile(startupFileName, configContent)

	// Start VPP
	if err := vpp.container.execServer("vpp -c " + startupFileName); err != nil {
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

	return nil
}

func (vpp *VppInstance) vppctl(command string, arguments ...any) (string, error) {
	vppCliCommand := fmt.Sprintf(command, arguments...)
	containerExecCommand := fmt.Sprintf("docker exec --detach=false %[1]s vppctl -s %[2]s %[3]s",
		vpp.container.name, vpp.getCliSocket(), vppCliCommand)
	output, err := exechelper.CombinedOutput(containerExecCommand)
	if err != nil {
		return "", fmt.Errorf("vppctl failed: %s", err)
	}

	return string(output), nil
}

func NewVppInstance(c *Container) *VppInstance {
	vppConfig := new(VppConfig)
	vppConfig.CliSocketFilePath = defaultCliSocketFilePath
	vpp := new(VppInstance)
	vpp.container = c
	vpp.config = vppConfig
	return vpp
}

func serializeVppConfig(vppConfig *VppConfig) (string, error) {
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
		vppConfig.Variant = input
		vppConfig.CliSocketFilePath = defaultCliSocketFilePath
	}
	return vppConfig, nil
}

func (vpp *VppInstance) createAfPacket(
	veth *NetworkInterfaceVeth,
) (interface_types.InterfaceIndex, error) {
	createReq := &af_packet.AfPacketCreateV2{
		UseRandomHwAddr: true,
		HostIfName:      veth.Name(),
	}
	if veth.hwAddress != (MacAddress{}) {
		createReq.UseRandomHwAddr = false
		createReq.HwAddr = veth.hwAddress
	}
	createReply := &af_packet.AfPacketCreateV2Reply{}

	if err := vpp.apiChannel.SendRequest(createReq).ReceiveReply(createReply); err != nil {
		return 0, err
	}
	veth.index = createReply.SwIfIndex

	// Set to up
	upReq := &interfaces.SwInterfaceSetFlags{
		SwIfIndex: veth.index,
		Flags:     interface_types.IF_STATUS_API_FLAG_ADMIN_UP,
	}
	upReply := &interfaces.SwInterfaceSetFlagsReply{}

	if err := vpp.apiChannel.SendRequest(upReq).ReceiveReply(upReply); err != nil {
		return 0, err
	}

	// Add address
	if veth.ip4Address == (AddressWithPrefix{}) {
		ipPrefix, err := vpp.container.suite.NewAddress()
		if err != nil {
			return 0, err
		}
		veth.ip4Address = ipPrefix
	}
	addressReq := &interfaces.SwInterfaceAddDelAddress{
		IsAdd:     true,
		SwIfIndex: veth.index,
		Prefix:    veth.ip4Address,
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
	vpp.connection.Disconnect()
	vpp.apiChannel.Close()
}
