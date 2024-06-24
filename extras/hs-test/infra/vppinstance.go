package hst

import (
	"context"
	"fmt"
	"go.fd.io/govpp/binapi/ethernet_types"
	"io"
	"net"
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
  plugin mactime_plugin.so { enable }
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
	Container        *Container
	AdditionalConfig []Stanza
	Connection       *core.Connection
	ApiStream        api.Stream
	Cpus             []int
	CpuConfig        VppCpuConfig
}

type VppCpuConfig struct {
	PinMainCpu         bool
	PinWorkersCorelist bool
	SkipCores          int
}

func (vpp *VppInstance) getSuite() *HstSuite {
	return vpp.Container.Suite
}

func (vpp *VppInstance) getCliSocket() string {
	return fmt.Sprintf("%s%s", vpp.Container.GetContainerWorkDir(), defaultCliSocketFilePath)
}

func (vpp *VppInstance) getRunDir() string {
	return vpp.Container.GetContainerWorkDir() + "/var/run/vpp"
}

func (vpp *VppInstance) getLogDir() string {
	return vpp.Container.GetContainerWorkDir() + "/var/log/vpp"
}

func (vpp *VppInstance) getEtcDir() string {
	return vpp.Container.GetContainerWorkDir() + "/etc/vpp"
}

func (vpp *VppInstance) Start() error {
	maxReconnectAttempts := 3
	// Replace default logger in govpp with our own
	govppLogger := logrus.New()
	govppLogger.SetOutput(io.MultiWriter(vpp.getSuite().Logger.Writer(), GinkgoWriter))
	core.SetLogger(govppLogger)
	// Create folders
	containerWorkDir := vpp.Container.GetContainerWorkDir()

	vpp.Container.Exec("mkdir --mode=0700 -p " + vpp.getRunDir())
	vpp.Container.Exec("mkdir --mode=0700 -p " + vpp.getLogDir())
	vpp.Container.Exec("mkdir --mode=0700 -p " + vpp.getEtcDir())

	// Create startup.conf inside the container
	configContent := fmt.Sprintf(
		vppConfigTemplate,
		containerWorkDir,
		defaultCliSocketFilePath,
		defaultApiSocketFilePath,
		defaultLogFilePath,
	)
	configContent += vpp.generateVPPCpuConfig()
	for _, c := range vpp.AdditionalConfig {
		configContent += c.ToString()
	}
	startupFileName := vpp.getEtcDir() + "/startup.conf"
	vpp.Container.CreateFile(startupFileName, configContent)

	// create wrapper script for vppctl with proper CLI socket path
	cliContent := "#!/usr/bin/bash\nvppctl -s " + vpp.getRunDir() + "/cli.sock"
	vppcliFileName := "/usr/bin/vppcli"
	vpp.Container.CreateFile(vppcliFileName, cliContent)
	vpp.Container.Exec("chmod 0755 " + vppcliFileName)

	vpp.getSuite().Log("starting vpp")
	if *IsVppDebug {
		// default = 3; VPP will timeout while debugging if there are not enough attempts
		maxReconnectAttempts = 5000
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGQUIT)
		cont := make(chan bool, 1)
		go func() {
			<-sig
			cont <- true
		}()

		vpp.Container.ExecServer("su -c \"vpp -c " + startupFileName + " &> /proc/1/fd/1\"")
		fmt.Println("run following command in different terminal:")
		fmt.Println("docker exec -it " + vpp.Container.Name + " gdb -ex \"attach $(docker exec " + vpp.Container.Name + " pidof vpp)\"")
		fmt.Println("Afterwards press CTRL+\\ to continue")
		<-cont
		fmt.Println("continuing...")
	} else {
		// Start VPP
		vpp.Container.ExecServer("su -c \"vpp -c " + startupFileName + " &> /proc/1/fd/1\"")
	}

	vpp.getSuite().Log("connecting to vpp")
	// Connect to VPP and store the connection
	sockAddress := vpp.Container.GetHostWorkDir() + defaultApiSocketFilePath
	conn, connEv, err := govpp.AsyncConnect(
		sockAddress,
		maxReconnectAttempts,
		core.DefaultReconnectInterval)
	if err != nil {
		vpp.getSuite().Log("async connect error: " + fmt.Sprint(err))
		return err
	}
	vpp.Connection = conn

	// ... wait for Connected event
	e := <-connEv
	if e.State != core.Connected {
		vpp.getSuite().Log("connecting to VPP failed: " + fmt.Sprint(e.Error))
		return e.Error
	}

	ch, err := conn.NewStream(
		context.Background(),
		core.WithRequestSize(50),
		core.WithReplySize(50),
		core.WithReplyTimeout(time.Second*5))
	if err != nil {
		vpp.getSuite().Log("creating stream failed: " + fmt.Sprint(err))
		return err
	}
	vpp.ApiStream = ch

	return nil
}

func (vpp *VppInstance) Vppctl(command string, arguments ...any) string {
	vppCliCommand := fmt.Sprintf(command, arguments...)
	containerExecCommand := fmt.Sprintf("docker exec --detach=false %[1]s vppctl -s %[2]s %[3]s",
		vpp.Container.Name, vpp.getCliSocket(), vppCliCommand)
	vpp.getSuite().Log(containerExecCommand)
	output, err := exechelper.CombinedOutput(containerExecCommand)
	vpp.getSuite().AssertNil(err)

	return string(output)
}

func (vpp *VppInstance) GetSessionStat(stat string) int {
	o := vpp.Vppctl("show session stats")
	vpp.getSuite().Log(o)
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

func (vpp *VppInstance) WaitForApp(appName string, timeout int) {
	vpp.getSuite().Log("waiting for app " + appName)
	for i := 0; i < timeout; i++ {
		o := vpp.Vppctl("show app")
		if strings.Contains(o, appName) {
			return
		}
		time.Sleep(1 * time.Second)
	}
	vpp.getSuite().AssertNil(1, "Timeout while waiting for app '%s'", appName)
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
	if veth.HwAddress != (MacAddress{}) {
		createReq.UseRandomHwAddr = false
		createReq.HwAddr = veth.HwAddress
	}

	vpp.getSuite().Log("create af-packet interface " + veth.Name())
	if err := vpp.ApiStream.SendMsg(createReq); err != nil {
		vpp.getSuite().HstFail()
		return 0, err
	}
	replymsg, err := vpp.ApiStream.RecvMsg()
	if err != nil {
		return 0, err
	}
	reply := replymsg.(*af_packet.AfPacketCreateV3Reply)
	err = api.RetvalToVPPApiError(reply.Retval)
	if err != nil {
		return 0, err
	}

	veth.Index = reply.SwIfIndex

	// Set to up
	upReq := &interfaces.SwInterfaceSetFlags{
		SwIfIndex: veth.Index,
		Flags:     interface_types.IF_STATUS_API_FLAG_ADMIN_UP,
	}

	vpp.getSuite().Log("set af-packet interface " + veth.Name() + " up")
	if err := vpp.ApiStream.SendMsg(upReq); err != nil {
		return 0, err
	}
	replymsg, err = vpp.ApiStream.RecvMsg()
	if err != nil {
		return 0, err
	}
	reply2 := replymsg.(*interfaces.SwInterfaceSetFlagsReply)
	if err = api.RetvalToVPPApiError(reply2.Retval); err != nil {
		return 0, err
	}

	// Add address
	if veth.AddressWithPrefix() == (AddressWithPrefix{}) {
		var err error
		var ip4Address string
		if ip4Address, err = veth.Ip4AddrAllocator.NewIp4InterfaceAddress(veth.Peer.NetworkNumber); err == nil {
			veth.Ip4Address = ip4Address
		} else {
			return 0, err
		}
	}
	addressReq := &interfaces.SwInterfaceAddDelAddress{
		IsAdd:     true,
		SwIfIndex: veth.Index,
		Prefix:    veth.AddressWithPrefix(),
	}

	vpp.getSuite().Log("af-packet interface " + veth.Name() + " add address " + veth.Ip4Address)
	if err := vpp.ApiStream.SendMsg(addressReq); err != nil {
		return 0, err
	}
	replymsg, err = vpp.ApiStream.RecvMsg()
	if err != nil {
		return 0, err
	}
	reply3 := replymsg.(*interfaces.SwInterfaceAddDelAddressReply)
	err = api.RetvalToVPPApiError(reply3.Retval)
	if err != nil {
		return 0, err
	}

	return veth.Index, nil
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

	vpp.getSuite().Log("add app namespace " + namespaceId)
	if err := vpp.ApiStream.SendMsg(req); err != nil {
		return err
	}
	replymsg, err := vpp.ApiStream.RecvMsg()
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

	vpp.getSuite().Log("enable app namespace " + namespaceId)
	if err := vpp.ApiStream.SendMsg(sessionReq); err != nil {
		return err
	}
	replymsg, err = vpp.ApiStream.RecvMsg()
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
		HostIP4Prefix:    tap.Ip4AddressWithPrefix(),
	}

	vpp.getSuite().Log("create tap interface " + tap.Name())
	// Create tap interface
	if err := vpp.ApiStream.SendMsg(createTapReq); err != nil {
		return err
	}
	replymsg, err := vpp.ApiStream.RecvMsg()
	if err != nil {
		return err
	}
	reply := replymsg.(*tapv2.TapCreateV3Reply)
	if err = api.RetvalToVPPApiError(reply.Retval); err != nil {
		return err
	}
	tap.Peer.Index = reply.SwIfIndex

	// Get name and mac
	if err := vpp.ApiStream.SendMsg(&interfaces.SwInterfaceDump{
		SwIfIndex: reply.SwIfIndex,
	}); err != nil {
		return err
	}
	replymsg, err = vpp.ApiStream.RecvMsg()
	if err != nil {
		return err
	}
	ifDetails := replymsg.(*interfaces.SwInterfaceDetails)
	tap.Peer.name = ifDetails.InterfaceName
	tap.Peer.HwAddress = ifDetails.L2Address

	// Add address
	addAddressReq := &interfaces.SwInterfaceAddDelAddress{
		IsAdd:     true,
		SwIfIndex: reply.SwIfIndex,
		Prefix:    tap.Peer.AddressWithPrefix(),
	}

	vpp.getSuite().Log("tap interface " + tap.Name() + " add address " + tap.Peer.Ip4Address)
	if err := vpp.ApiStream.SendMsg(addAddressReq); err != nil {
		return err
	}
	replymsg, err = vpp.ApiStream.RecvMsg()
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

	vpp.getSuite().Log("set tap interface " + tap.Name() + " up")
	if err := vpp.ApiStream.SendMsg(upReq); err != nil {
		return err
	}
	replymsg, err = vpp.ApiStream.RecvMsg()
	if err != nil {
		return err
	}
	reply3 := replymsg.(*interfaces.SwInterfaceSetFlagsReply)
	if err = api.RetvalToVPPApiError(reply3.Retval); err != nil {
		return err
	}

	// Get host mac
	netIntf, err := net.InterfaceByName(tap.Name())
	if err == nil {
		tap.HwAddress, _ = ethernet_types.ParseMacAddress(netIntf.HardwareAddr.String())
	}

	return nil
}

func (vpp *VppInstance) saveLogs() {
	logTarget := vpp.Container.getLogDirPath() + "vppinstance-" + vpp.Container.Name + ".log"
	logSource := vpp.Container.GetHostWorkDir() + defaultLogFilePath
	cmd := exec.Command("cp", logSource, logTarget)
	vpp.getSuite().Log(cmd.String())
	cmd.Run()
}

func (vpp *VppInstance) Disconnect() {
	vpp.Connection.Disconnect()
	vpp.ApiStream.Close()
}

func (vpp *VppInstance) setDefaultCpuConfig() {
	vpp.CpuConfig.PinMainCpu = true
	vpp.CpuConfig.PinWorkersCorelist = true
	vpp.CpuConfig.SkipCores = 0
}

func (vpp *VppInstance) generateVPPCpuConfig() string {
	var c Stanza
	var s string
	startCpu := 0
	if len(vpp.Cpus) < 1 {
		return ""
	}

	c.NewStanza("cpu")

	// If skip-cores is valid, use as start value to assign main/workers CPUs
	if vpp.CpuConfig.SkipCores != 0 {
		c.Append(fmt.Sprintf("skip-cores %d", vpp.CpuConfig.SkipCores))
		vpp.getSuite().Log(fmt.Sprintf("skip-cores %d", vpp.CpuConfig.SkipCores))
	}

	if len(vpp.Cpus) > vpp.CpuConfig.SkipCores {
		startCpu = vpp.CpuConfig.SkipCores
	}

	if vpp.CpuConfig.PinMainCpu {
		c.Append(fmt.Sprintf("main-core %d", vpp.Cpus[startCpu]))
		vpp.getSuite().Log(fmt.Sprintf("main-core %d", vpp.Cpus[startCpu]))
	}

	workers := vpp.Cpus[startCpu+1:]

	if len(workers) > 0 {
		if vpp.CpuConfig.PinWorkersCorelist {
			for i := 0; i < len(workers); i++ {
				if i != 0 {
					s = s + ", "
				}
				s = s + fmt.Sprintf("%d", workers[i])
			}
			c.Append(fmt.Sprintf("corelist-workers %s", s))
			vpp.getSuite().Log("corelist-workers " + s)
		} else {
			s = fmt.Sprintf("%d", len(workers))
			c.Append(fmt.Sprintf("workers %s", s))
			vpp.getSuite().Log("workers " + s)
		}
	}

	return c.Close().ToString()
}
