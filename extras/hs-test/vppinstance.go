package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/edwarnicke/exechelper"
	. "github.com/onsi/ginkgo/v2"
	"github.com/sirupsen/logrus"

	"go.fd.io/govpp"
	"go.fd.io/govpp/api"
	"go.fd.io/govpp/binapi/af_packet"
	interfaces "go.fd.io/govpp/binapi/interface"
	"go.fd.io/govpp/binapi/interface_types"
	"go.fd.io/govpp/binapi/session"
	"go.fd.io/govpp/binapi/tapv2"
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
  plugin http_static_plugin.so { enable }
  plugin prom_plugin.so { enable }
  plugin tlsopenssl_plugin.so { enable }
  plugin ping_plugin.so { enable }
  plugin nsim_plugin.so { enable }
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
	apiStream        api.Stream
	cpus             []int
}

func (vpp *VppInstance) getSuite() *HstSuite {
	return vpp.container.suite
}

func (vpp *VppInstance) getCliSocket() string {
	return fmt.Sprintf("%s%s", vpp.container.getContainerWorkDir(), defaultCliSocketFilePath)
}

func (vpp *VppInstance) getRunDir() string {
	return vpp.container.getContainerWorkDir() + "/var/run/vpp"
}

func (vpp *VppInstance) getLogDir() string {
	return vpp.container.getContainerWorkDir() + "/var/log/vpp"
}

func (vpp *VppInstance) getEtcDir() string {
	return vpp.container.getContainerWorkDir() + "/etc/vpp"
}

func (vpp *VppInstance) start() error {
	maxReconnectAttempts := 3
	// Replace default logger in govpp with our own
	govppLogger := logrus.New()
	govppLogger.SetOutput(io.MultiWriter(vpp.getSuite().logger.Writer(), GinkgoWriter))
	core.SetLogger(govppLogger)
	// Create folders
	containerWorkDir := vpp.container.getContainerWorkDir()

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
	configContent += vpp.generateCpuConfig()
	for _, c := range vpp.additionalConfig {
		configContent += c.toString()
	}
	startupFileName := vpp.getEtcDir() + "/startup.conf"
	vpp.container.createFile(startupFileName, configContent)

	// create wrapper script for vppctl with proper CLI socket path
	cliContent := "#!/usr/bin/bash\nvppctl -s " + vpp.getRunDir() + "/cli.sock"
	vppcliFileName := "/usr/bin/vppcli"
	vpp.container.createFile(vppcliFileName, cliContent)
	vpp.container.exec("chmod 0755 " + vppcliFileName)

	vpp.getSuite().log("starting vpp")
	if *isVppDebug {
		// default = 3; VPP will timeout while debugging if there are not enough attempts
		maxReconnectAttempts = 5000
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGQUIT)
		cont := make(chan bool, 1)
		go func() {
			<-sig
			cont <- true
		}()

		vpp.container.execServer("su -c \"vpp -c " + startupFileName + " &> /proc/1/fd/1\"")
		fmt.Println("run following command in different terminal:")
		fmt.Println("docker exec -it " + vpp.container.name + " gdb -ex \"attach $(docker exec " + vpp.container.name + " pidof vpp)\"")
		fmt.Println("Afterwards press CTRL+\\ to continue")
		<-cont
		fmt.Println("continuing...")
	} else {
		// Start VPP
		vpp.container.execServer("su -c \"vpp -c " + startupFileName + " &> /proc/1/fd/1\"")
	}

	vpp.getSuite().log("connecting to vpp")
	// Connect to VPP and store the connection
	sockAddress := vpp.container.getHostWorkDir() + defaultApiSocketFilePath
	conn, connEv, err := govpp.AsyncConnect(
		sockAddress,
		maxReconnectAttempts,
		core.DefaultReconnectInterval)
	if err != nil {
		vpp.getSuite().log("async connect error: " + fmt.Sprint(err))
		return err
	}
	vpp.connection = conn

	// ... wait for Connected event
	e := <-connEv
	if e.State != core.Connected {
		vpp.getSuite().log("connecting to VPP failed: " + fmt.Sprint(e.Error))
	}

	ch, err := conn.NewStream(
		context.Background(),
		core.WithRequestSize(50),
		core.WithReplySize(50),
		core.WithReplyTimeout(time.Second*5))
	if err != nil {
		vpp.getSuite().log("creating stream failed: " + fmt.Sprint(err))
		return err
	}
	vpp.apiStream = ch

	return nil
}

func (vpp *VppInstance) vppctl(command string, arguments ...any) string {
	vppCliCommand := fmt.Sprintf(command, arguments...)
	containerExecCommand := fmt.Sprintf("docker exec --detach=false %[1]s vppctl -s %[2]s %[3]s",
		vpp.container.name, vpp.getCliSocket(), vppCliCommand)
	vpp.getSuite().log(containerExecCommand)
	output, err := exechelper.CombinedOutput(containerExecCommand)
	vpp.getSuite().assertNil(err)

	return string(output)
}

func (vpp *VppInstance) GetSessionStat(stat string) int {
	o := vpp.vppctl("show session stats")
	vpp.getSuite().log(o)
	for _, line := range strings.Split(o, "\n") {
		if strings.Contains(line, stat) {
			tokens := strings.Split(strings.TrimSpace(line), " ")
			val, err := strconv.Atoi(tokens[0])
			if err != nil {
				Fail("failed to parse stat value %s" + fmt.Sprint(err))
				return 0
			}
			return val
		}
	}
	return 0
}

func (vpp *VppInstance) waitForApp(appName string, timeout int) {
	vpp.getSuite().log("waiting for app " + appName)
	for i := 0; i < timeout; i++ {
		o := vpp.vppctl("show app")
		if strings.Contains(o, appName) {
			return
		}
		time.Sleep(1 * time.Second)
	}
	vpp.getSuite().assertNil(1, "Timeout while waiting for app '%s'", appName)
}

func (vpp *VppInstance) createAfPacket(
	veth *NetInterface,
) (interface_types.InterfaceIndex, error) {
	createReq := &af_packet.AfPacketCreateV3{
		Mode:            1,
		UseRandomHwAddr: true,
		HostIfName:      veth.Name(),
		Flags:           af_packet.AfPacketFlags(11),
	}
	if veth.hwAddress != (MacAddress{}) {
		createReq.UseRandomHwAddr = false
		createReq.HwAddr = veth.hwAddress
	}

	vpp.getSuite().log("create af-packet interface " + veth.Name())
	if err := vpp.apiStream.SendMsg(createReq); err != nil {
		vpp.getSuite().hstFail()
		return 0, err
	}
	replymsg, err := vpp.apiStream.RecvMsg()
	if err != nil {
		return 0, err
	}
	reply := replymsg.(*af_packet.AfPacketCreateV3Reply)
	err = api.RetvalToVPPApiError(reply.Retval)
	if err != nil {
		return 0, err
	}

	veth.index = reply.SwIfIndex

	// Set to up
	upReq := &interfaces.SwInterfaceSetFlags{
		SwIfIndex: veth.index,
		Flags:     interface_types.IF_STATUS_API_FLAG_ADMIN_UP,
	}

	vpp.getSuite().log("set af-packet interface " + veth.Name() + " up")
	if err := vpp.apiStream.SendMsg(upReq); err != nil {
		return 0, err
	}
	replymsg, err = vpp.apiStream.RecvMsg()
	if err != nil {
		return 0, err
	}
	reply2 := replymsg.(*interfaces.SwInterfaceSetFlagsReply)
	if err = api.RetvalToVPPApiError(reply2.Retval); err != nil {
		return 0, err
	}

	// Add address
	if veth.addressWithPrefix() == (AddressWithPrefix{}) {
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
		Prefix:    veth.addressWithPrefix(),
	}

	vpp.getSuite().log("af-packet interface " + veth.Name() + " add address " + veth.ip4Address)
	if err := vpp.apiStream.SendMsg(addressReq); err != nil {
		return 0, err
	}
	replymsg, err = vpp.apiStream.RecvMsg()
	if err != nil {
		return 0, err
	}
	reply3 := replymsg.(*interfaces.SwInterfaceAddDelAddressReply)
	err = api.RetvalToVPPApiError(reply3.Retval)
	if err != nil {
		return 0, err
	}

	return veth.index, nil
}

func (vpp *VppInstance) addAppNamespace(
	secret uint64,
	ifx interface_types.InterfaceIndex,
	namespaceId string,
) error {
	req := &session.AppNamespaceAddDelV4{
		IsAdd:       true,
		Secret:      secret,
		SwIfIndex:   ifx,
		NamespaceID: namespaceId,
		SockName:    defaultApiSocketFilePath,
	}

	vpp.getSuite().log("add app namespace " + namespaceId)
	if err := vpp.apiStream.SendMsg(req); err != nil {
		return err
	}
	replymsg, err := vpp.apiStream.RecvMsg()
	if err != nil {
		return err
	}
	reply := replymsg.(*session.AppNamespaceAddDelV4Reply)
	if err = api.RetvalToVPPApiError(reply.Retval); err != nil {
		return err
	}

	sessionReq := &session.SessionEnableDisable{
		IsEnable: true,
	}

	vpp.getSuite().log("enable app namespace " + namespaceId)
	if err := vpp.apiStream.SendMsg(sessionReq); err != nil {
		return err
	}
	replymsg, err = vpp.apiStream.RecvMsg()
	if err != nil {
		return err
	}
	reply2 := replymsg.(*session.SessionEnableDisableReply)
	if err = api.RetvalToVPPApiError(reply2.Retval); err != nil {
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
	createTapReq := &tapv2.TapCreateV3{
		ID:               id,
		HostIfNameSet:    true,
		HostIfName:       tap.Name(),
		HostIP4PrefixSet: true,
		HostIP4Prefix:    tap.ip4AddressWithPrefix(),
	}

	vpp.getSuite().log("create tap interface " + tap.Name())
	// Create tap interface
	if err := vpp.apiStream.SendMsg(createTapReq); err != nil {
		return err
	}
	replymsg, err := vpp.apiStream.RecvMsg()
	if err != nil {
		return err
	}
	reply := replymsg.(*tapv2.TapCreateV3Reply)
	if err = api.RetvalToVPPApiError(reply.Retval); err != nil {
		return err
	}

	// Add address
	addAddressReq := &interfaces.SwInterfaceAddDelAddress{
		IsAdd:     true,
		SwIfIndex: reply.SwIfIndex,
		Prefix:    tap.peer.addressWithPrefix(),
	}

	vpp.getSuite().log("tap interface " + tap.Name() + " add address " + tap.peer.ip4Address)
	if err := vpp.apiStream.SendMsg(addAddressReq); err != nil {
		return err
	}
	replymsg, err = vpp.apiStream.RecvMsg()
	if err != nil {
		return err
	}
	reply2 := replymsg.(*interfaces.SwInterfaceAddDelAddressReply)
	if err = api.RetvalToVPPApiError(reply2.Retval); err != nil {
		return err
	}

	// Set interface to up
	upReq := &interfaces.SwInterfaceSetFlags{
		SwIfIndex: reply.SwIfIndex,
		Flags:     interface_types.IF_STATUS_API_FLAG_ADMIN_UP,
	}

	vpp.getSuite().log("set tap interface " + tap.Name() + " up")
	if err := vpp.apiStream.SendMsg(upReq); err != nil {
		return err
	}
	replymsg, err = vpp.apiStream.RecvMsg()
	if err != nil {
		return err
	}
	reply3 := replymsg.(*interfaces.SwInterfaceSetFlagsReply)
	if err = api.RetvalToVPPApiError(reply3.Retval); err != nil {
		return err
	}

	return nil
}

func (vpp *VppInstance) saveLogs() {
	logTarget := vpp.container.getLogDirPath() + "vppinstance-" + vpp.container.name + ".log"
	logSource := vpp.container.getHostWorkDir() + defaultLogFilePath
	cmd := exec.Command("cp", logSource, logTarget)
	vpp.getSuite().log(cmd.String())
	cmd.Run()
}

func (vpp *VppInstance) disconnect() {
	vpp.connection.Disconnect()
	vpp.apiStream.Close()
}

func (vpp *VppInstance) generateCpuConfig() string {
	var c Stanza
	var s string
	if len(vpp.cpus) < 1 {
		return ""
	}
	c.newStanza("cpu").
		append(fmt.Sprintf("main-core %d", vpp.cpus[0]))
	vpp.getSuite().log(fmt.Sprintf("main-core %d", vpp.cpus[0]))
	workers := vpp.cpus[1:]

	if len(workers) > 0 {
		for i := 0; i < len(workers); i++ {
			if i != 0 {
				s = s + ", "
			}
			s = s + fmt.Sprintf("%d", workers[i])
		}
		c.append(fmt.Sprintf("corelist-workers %s", s))
		vpp.getSuite().log("corelist-workers " + s)
	}
	return c.close().toString()
}
