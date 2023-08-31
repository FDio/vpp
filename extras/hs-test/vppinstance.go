package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/edwarnicke/exechelper"

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
	additionalConfig []Stanza
	connection       *core.Connection
	apiChannel       api.Channel
	cpus             []int
}

func (vpp *VppInstance) GetSuite() *HstSuite {
	return vpp.container.suite
}

func (vpp *VppInstance) GetCliSocket() string {
	return fmt.Sprintf("%s%s", vpp.container.GetContainerWorkDir(), defaultCliSocketFilePath)
}

func (vpp *VppInstance) GetRunDir() string {
	return vpp.container.GetContainerWorkDir() + "/var/run/vpp"
}

func (vpp *VppInstance) GetLogDir() string {
	return vpp.container.GetContainerWorkDir() + "/var/log/vpp"
}

func (vpp *VppInstance) GetEtcDir() string {
	return vpp.container.GetContainerWorkDir() + "/etc/vpp"
}

func (vpp *VppInstance) Start() error {
	// Create folders
	containerWorkDir := vpp.container.GetContainerWorkDir()

	vpp.container.Exec("mkdir --mode=0700 -p " + vpp.GetRunDir())
	vpp.container.Exec("mkdir --mode=0700 -p " + vpp.GetLogDir())
	vpp.container.Exec("mkdir --mode=0700 -p " + vpp.GetEtcDir())

	// Create startup.conf inside the container
	configContent := fmt.Sprintf(
		vppConfigTemplate,
		containerWorkDir,
		defaultCliSocketFilePath,
		defaultApiSocketFilePath,
		defaultLogFilePath,
	)
	configContent += vpp.GenerateCpuConfig()
	for _, c := range vpp.additionalConfig {
		configContent += c.ToString()
	}
	startupFileName := vpp.GetEtcDir() + "/startup.conf"
	vpp.container.CreateFile(startupFileName, configContent)

	// create wrapper script for vppctl with proper CLI socket path
	cliContent := "#!/usr/bin/bash\nvppctl -s " + vpp.GetRunDir() + "/cli.sock"
	vppcliFileName := "/usr/bin/vppcli"
	vpp.container.CreateFile(vppcliFileName, cliContent)
	vpp.container.Exec("chmod 0755 " + vppcliFileName)

	if *isVppDebug {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT)
		cont := make(chan bool, 1)
		go func() {
			<-sig
			cont <- true
		}()

		// Start VPP in GDB and wait for user to attach it
		vpp.container.ExecServer("su -c \"gdb -ex run --args vpp -c " + startupFileName + " &> /proc/1/fd/1\"")
		fmt.Println("run following command in different terminal:")
		fmt.Println("docker exec -it " + vpp.container.name + " gdb -ex \"attach $(docker exec " + vpp.container.name + " pidof gdb)\"")
		fmt.Println("Afterwards press CTRL+C to continue")
		<-cont
		fmt.Println("continuing...")
	} else {
		// Start VPP
		vpp.container.ExecServer("su -c \"vpp -c " + startupFileName + " &> /proc/1/fd/1\"")
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

func (vpp *VppInstance) Vppctl(command string, arguments ...any) string {
	vppCliCommand := fmt.Sprintf(command, arguments...)
	containerExecCommand := fmt.Sprintf("docker exec --detach=false %[1]s vppctl -s %[2]s %[3]s",
		vpp.container.name, vpp.GetCliSocket(), vppCliCommand)
	vpp.GetSuite().Log(containerExecCommand)
	output, err := exechelper.CombinedOutput(containerExecCommand)
	vpp.GetSuite().AssertNil(err)

	return string(output)
}

func (vpp *VppInstance) GetSessionStat(stat string) int {
	o := vpp.Vppctl("show session stats")
	vpp.GetSuite().Log(o)
	for _, line := range strings.Split(o, "\n") {
		if strings.Contains(line, stat) {
			tokens := strings.Split(strings.TrimSpace(line), " ")
			val, err := strconv.Atoi(tokens[0])
			if err != nil {
				vpp.GetSuite().FailNow("failed to parse stat value %s", err)
				return 0
			}
			return val
		}
	}
	return 0
}

func (vpp *VppInstance) WaitForApp(appName string, timeout int) {
	for i := 0; i < timeout; i++ {
		o := vpp.Vppctl("show app")
		if strings.Contains(o, appName) {
			return
		}
		time.Sleep(1 * time.Second)
	}
	vpp.GetSuite().AssertNil(1, "Timeout while waiting for app '%s'", appName)
}

func (vpp *VppInstance) CreateAfPacket(
	veth *NetInterface,
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
	if veth.AddressWithPrefix() == (AddressWithPrefix{}) {
		var err error
		var ip4Address string
		if ip4Address, err = veth.ip4AddrAllocator.NewIp4InterfaceAddress(veth.peer.networkNumber); err == nil {
			veth.ip4Address = ip4Address
		} else {
			return 0, err
		}
	}
	addressReq := &interfaces.SwInterfaceAddDelAddress{
		IsAdd:     true,
		SwIfIndex: veth.index,
		Prefix:    veth.AddressWithPrefix(),
	}
	addressReply := &interfaces.SwInterfaceAddDelAddressReply{}

	if err := vpp.apiChannel.SendRequest(addressReq).ReceiveReply(addressReply); err != nil {
		return 0, err
	}

	return veth.index, nil
}

func (vpp *VppInstance) AddAppNamespace(
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

func (vpp *VppInstance) CreateTap(
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
		HostIP4Prefix:    tap.Ip4AddressWithPrefix(),
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
		Prefix:    tap.peer.AddressWithPrefix(),
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

func (vpp *VppInstance) SaveLogs() {
	logTarget := vpp.container.GetLogDirPath() + "vppinstance-" + vpp.container.name + ".log"
	logSource := vpp.container.GetHostWorkDir() + defaultLogFilePath
	cmd := exec.Command("cp", logSource, logTarget)
	vpp.GetSuite().T().Helper()
	vpp.GetSuite().Log(cmd.String())
	cmd.Run()
}

func (vpp *VppInstance) Disconnect() {
	vpp.connection.Disconnect()
	vpp.apiChannel.Close()
}

func (vpp *VppInstance) GenerateCpuConfig() string {
	var c Stanza
	var s string
	if len(vpp.cpus) < 1 {
		return ""
	}
	c.NewStanza("cpu").
		Append(fmt.Sprintf("main-core %d", vpp.cpus[0]))
	workers := vpp.cpus[1:]

	if len(workers) > 0 {
		for i := 0; i < len(workers); i++ {
			if i != 0 {
				s = s + ", "
			}
			s = s + fmt.Sprintf("%d", workers[i])
		}
		c.Append(fmt.Sprintf("corelist-workers %s", s))
	}
	return c.Close().ToString()
}
