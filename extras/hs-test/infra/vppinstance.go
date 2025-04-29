package hst

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.fd.io/govpp/binapi/ethernet_types"

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
  coredump-size unlimited
  cli-listen %[1]s%[2]s
  runtime-dir %[1]s/var/run
  %[5]s
}

api-trace {
  on
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
  plugin http_unittest_plugin.so { enable }
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
	Consistent_qp            = 256
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
	UseWorkers         bool
	PinWorkersCorelist bool
	RelativeCores      bool
	SkipCores          int
}

type VppMemTrace struct {
	Count     int      `json:"count"`
	Size      int      `json:"bytes"`
	Sample    string   `json:"sample"`
	Traceback []string `json:"traceback"`
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

// Appends a string to '[host-work-dir]/cli-config.conf'.
// Creates the conf file if it doesn't exist. Used for dry-run mode.
func (vpp *VppInstance) AppendToCliConfig(vppCliConfig string) {
	f, err := os.OpenFile(vpp.Container.GetHostWorkDir()+"/cli-config.conf", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	vpp.getSuite().AssertNil(err)
	_, err = f.Write([]byte(vppCliConfig))
	vpp.getSuite().AssertNil(err)
	err = f.Close()
	vpp.getSuite().AssertNil(err)
}

func (vpp *VppInstance) Start() error {
	containerWorkDir := vpp.Container.GetContainerWorkDir()
	var cliConfig string
	if *DryRun {
		cliConfig = fmt.Sprintf("exec %s/cli-config.conf", containerWorkDir)
	}

	vpp.Container.Exec(false, "mkdir --mode=0700 -p "+vpp.getRunDir())
	vpp.Container.Exec(false, "mkdir --mode=0700 -p "+vpp.getLogDir())
	vpp.Container.Exec(false, "mkdir --mode=0700 -p "+vpp.getEtcDir())

	// Create startup.conf inside the container
	configContent := fmt.Sprintf(
		vppConfigTemplate,
		containerWorkDir,
		defaultCliSocketFilePath,
		defaultApiSocketFilePath,
		defaultLogFilePath,
		cliConfig,
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
	vpp.Container.Exec(false, "chmod 0755 "+vppcliFileName)

	if *DryRun {
		vpp.getSuite().Log("%s* Commands to start VPP and VPPCLI:", Colors.pur)
		vpp.getSuite().Log("vpp -c %s/startup.conf", vpp.getEtcDir())
		vpp.getSuite().Log("vppcli (= vppctl -s %s/cli.sock)%s\n", vpp.getRunDir(), Colors.rst)
		return nil
	}

	maxReconnectAttempts := 3
	// Replace default logger in govpp with our own
	govppLogger := logrus.New()
	govppLogger.SetOutput(io.MultiWriter(vpp.getSuite().Logger.Writer(), GinkgoWriter))
	core.SetLogger(govppLogger)

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

		vpp.Container.ExecServer(false, "su -c \"vpp -c "+startupFileName+" &> /proc/1/fd/1\"")
		fmt.Println("run following command in different terminal:")
		fmt.Println("docker exec -it " + vpp.Container.Name + " gdb -ex \"attach $(docker exec " + vpp.Container.Name + " pidof vpp)\"")
		fmt.Println("Afterwards press CTRL+\\ to continue")
		<-cont
		fmt.Println("continuing...")
	} else {
		// Start VPP
		vpp.Container.ExecServer(false, "su -c \"vpp -c "+startupFileName+" &> /proc/1/fd/1\"")
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

	AddReportEntry("VPP version", vpp.Vppctl("show version verbose"), ReportEntryVisibilityNever)

	return nil
}

func (vpp *VppInstance) Stop() {
	pid, err := vpp.Container.Exec(false, "pidof vpp")
	pid = strings.TrimSpace(pid)
	// Stop VPP only if it's still running
	if err == nil {
		vpp.getSuite().Log("Stopping VPP")
		vpp.Container.Exec(false, "bash -c \"kill -15 "+pid+"\"")
	}
}

func (vpp *VppInstance) Vppctl(command string, arguments ...any) string {
	vppCliCommand := fmt.Sprintf(command, arguments...)
	containerExecCommand := fmt.Sprintf("docker exec --detach=false %[1]s vppctl -s %[2]s %[3]s",
		vpp.Container.Name, vpp.getCliSocket(), vppCliCommand)
	vpp.getSuite().Log(containerExecCommand)
	output, err := exechelper.CombinedOutput(containerExecCommand)

	// If an error occurs, retrieve the caller function's name.
	// If retrieving the caller name fails, perform a regular assert.
	// If the caller is 'teardown', only log the error instead of asserting.
	if err != nil {
		pc, _, _, ok := runtime.Caller(1)
		if !ok {
			vpp.getSuite().AssertNil(err)
		} else {
			fn := runtime.FuncForPC(pc)
			if fn != nil && strings.Contains(fn.Name(), "TearDownTest") {
				vpp.getSuite().Log("vppctl failed in test teardown (skipping assert): %v", err)
			} else {
				vpp.getSuite().AssertNil(err)
			}
		}
	}

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

func (vpp *VppInstance) createAfPacket(veth *NetInterface, IPv6 bool) (interface_types.InterfaceIndex, error) {
	var ipAddress string
	var err error

	if *DryRun {
		if IPv6 {
			if ipAddress, err = veth.Ip6AddrAllocator.NewIp6InterfaceAddress(veth.Peer.NetworkNumber); err == nil {
				veth.Ip6Address = ipAddress
			}
		} else {
			if ipAddress, err = veth.Ip4AddrAllocator.NewIp4InterfaceAddress(veth.Peer.NetworkNumber); err == nil {
				veth.Ip4Address = ipAddress
			}
		}
		if err != nil {
			return 0, err
		}

		vppCliConfig := fmt.Sprintf(
			"create host-interface name %s\n"+
				"set int state host-%s up\n"+
				"set int ip addr host-%s %s\n",
			veth.Name(),
			veth.Name(),
			veth.Name(), ipAddress)
		vpp.AppendToCliConfig(vppCliConfig)
		vpp.getSuite().Log("%s* Interface added:\n%s%s", Colors.grn, vppCliConfig, Colors.rst)
		return 1, nil
	}

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
	if veth.AddressWithPrefix(IPv6) == (AddressWithPrefix{}) {
		if IPv6 {
			if ipAddress, err = veth.Ip6AddrAllocator.NewIp6InterfaceAddress(veth.Peer.NetworkNumber); err == nil {
				veth.Ip6Address = ipAddress
			}
		} else {
			if ipAddress, err = veth.Ip4AddrAllocator.NewIp4InterfaceAddress(veth.Peer.NetworkNumber); err == nil {
				veth.Ip4Address = ipAddress
			}
		}
		if err != nil {
			return 0, err
		}
	}
	addressReq := &interfaces.SwInterfaceAddDelAddress{
		IsAdd:     true,
		SwIfIndex: veth.Index,
		Prefix:    veth.AddressWithPrefix(IPv6),
	}

	vpp.getSuite().Log("af-packet interface " + veth.Name() + " add address " + ipAddress)
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

func (vpp *VppInstance) CreateTap(tap *NetInterface, IPv6 bool, numRxQueues uint16, tapId uint32, flags ...uint32) error {
	var tapFlags uint32 = 0

	if len(flags) > 0 {
		tapFlags = flags[0]
	}

	if *DryRun {
		flagsCli := ""
		ipAddress := ""
		ipAddressPeer := ""

		if tapFlags == Consistent_qp {
			flagsCli = "consistent-qp"
		}

		if IPv6 {
			ipAddress = "host-ip6-addr " + tap.Ip6Address
			ipAddressPeer = tap.Peer.Ip6Address
		} else {
			ipAddress = "host-ip4-addr " + tap.Ip4Address
			ipAddressPeer = tap.Peer.Ip4Address
		}

		vppCliConfig := fmt.Sprintf("create tap id %d host-if-name %s %s num-rx-queues %d %s\n"+
			"set int ip addr tap%d %s\n"+
			"set int state tap%d up\n",
			tapId,
			tap.name,
			ipAddress,
			numRxQueues,
			flagsCli,
			tapId,
			ipAddressPeer,
			tapId,
		)
		vpp.AppendToCliConfig(vppCliConfig)
		vpp.getSuite().Log("%s* Interface added:\n%s%s", Colors.grn, vppCliConfig, Colors.rst)
		return nil
	}

	createTapReq := &tapv2.TapCreateV3{
		ID:               tapId,
		HostIfNameSet:    true,
		HostIfName:       tap.Name(),
		HostIP4PrefixSet: true,
		HostIP4Prefix:    tap.Ip4AddressWithPrefix(),
		HostIP6PrefixSet: true,
		HostIP6Prefix:    tap.Ip6AddressWithPrefix(),
		NumRxQueues:      numRxQueues,
		TapFlags:         tapv2.TapFlags(tapFlags),
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
		Prefix:    tap.Peer.AddressWithPrefix(IPv6),
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

	if IPv6 {
		timeoutCounter := 1.0
		for {
			if timeoutCounter <= 5 {
				vpp.getSuite().Log("Waiting for 'tentative' flag to disappear [%vs/5s]", timeoutCounter)
				out, err := vpp.Container.Exec(false, "ip -6 addr show dev %s", tap.Name())
				if err != nil {
					vpp.getSuite().Log(out)
					return err
				}
				if !strings.Contains(out, "tentative") {
					break
				}
				time.Sleep(time.Millisecond * 500)
				timeoutCounter += 0.5
			} else {
				return errors.New("tentative flag did not disappear in time")
			}
		}
	}

	return nil
}

func (vpp *VppInstance) DeleteTap(tapInterface *NetInterface) error {
	deleteReq := &tapv2.TapDeleteV2{
		SwIfIndex: tapInterface.Peer.Index,
	}
	vpp.getSuite().Log("delete tap interface " + tapInterface.Name())
	if err := vpp.ApiStream.SendMsg(deleteReq); err != nil {
		return err
	}
	replymsg, err := vpp.ApiStream.RecvMsg()
	if err != nil {
		return err
	}
	reply := replymsg.(*tapv2.TapDeleteV2Reply)
	if err = api.RetvalToVPPApiError(reply.Retval); err != nil {
		return err
	}
	return nil
}

func (vpp *VppInstance) saveLogs() {
	logTarget := vpp.getSuite().getLogDirPath() + "vppinstance-" + vpp.Container.Name + ".log"
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
	vpp.CpuConfig.UseWorkers = true
	vpp.CpuConfig.PinWorkersCorelist = true
	vpp.CpuConfig.RelativeCores = false
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

	if vpp.CpuConfig.RelativeCores {
		c.Append("relative")
		vpp.getSuite().Log("relative")
	}

	// If skip-cores is valid, use as start value to assign main/workers CPUs
	if vpp.CpuConfig.SkipCores != 0 {
		c.Append(fmt.Sprintf("skip-cores %d", vpp.CpuConfig.SkipCores))
		vpp.getSuite().Log(fmt.Sprintf("skip-cores %d", vpp.CpuConfig.SkipCores))
	}

	if len(vpp.Cpus) > vpp.CpuConfig.SkipCores {
		startCpu = vpp.CpuConfig.SkipCores
	}

	if vpp.CpuConfig.PinMainCpu {
		if vpp.CpuConfig.RelativeCores {
			c.Append(fmt.Sprintf("main-core %d", startCpu))
			vpp.getSuite().Log(fmt.Sprintf("main-core %d", startCpu))
		} else {
			c.Append(fmt.Sprintf("main-core %d", vpp.Cpus[startCpu]))
			vpp.getSuite().Log(fmt.Sprintf("main-core %d", vpp.Cpus[startCpu]))
		}
	}

	workers := vpp.Cpus[startCpu+1:]
	workersRelativeCpu := startCpu + 1

	if len(workers) > 0 && vpp.CpuConfig.UseWorkers {
		if vpp.CpuConfig.PinWorkersCorelist {
			for i := 0; i < len(workers); i++ {
				if i != 0 {
					s = s + ", "
				}

				if vpp.CpuConfig.RelativeCores {
					s = s + fmt.Sprintf("%d", workersRelativeCpu)
					workersRelativeCpu++
				} else {
					s = s + fmt.Sprintf("%d", workers[i])
				}

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

// EnableMemoryTrace enables memory traces of VPP main-heap
func (vpp *VppInstance) EnableMemoryTrace() {
	vpp.getSuite().Log(vpp.Vppctl("memory-trace on main-heap"))
}

// GetMemoryTrace dumps memory traces for analysis
func (vpp *VppInstance) GetMemoryTrace() ([]VppMemTrace, error) {
	var trace []VppMemTrace
	vpp.getSuite().Log(vpp.Vppctl("save memory-trace trace.json"))
	err := vpp.Container.GetFile("/tmp/trace.json", "/tmp/trace.json")
	if err != nil {
		return nil, err
	}
	fileBytes, err := os.ReadFile("/tmp/trace.json")
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(fileBytes, &trace)
	if err != nil {
		return nil, err
	}
	return trace, nil
}

// memTracesSuppressCli filter out CLI related samples
func memTracesSuppressCli(traces []VppMemTrace) []VppMemTrace {
	var filtered []VppMemTrace
	for i := 0; i < len(traces); i++ {
		isCli := false
		for j := 0; j < len(traces[i].Traceback); j++ {
			if strings.Contains(traces[i].Traceback[j], "unix_cli") {
				isCli = true
				break
			}
		}
		if !isCli {
			filtered = append(filtered, traces[i])
		}
	}
	return filtered
}

// MemLeakCheck compares memory traces at different point in time, analyzes if memory leaks happen and produces report
func (vpp *VppInstance) MemLeakCheck(first, second []VppMemTrace) {
	totalBytes := 0
	totalCounts := 0
	trace1 := memTracesSuppressCli(first)
	trace2 := memTracesSuppressCli(second)
	report := ""
	for i := 0; i < len(trace2); i++ {
		match := false
		for j := 0; j < len(trace1); j++ {
			if trace1[j].Sample == trace2[i].Sample {
				if trace2[i].Size > trace1[j].Size {
					deltaBytes := trace2[i].Size - trace1[j].Size
					deltaCounts := trace2[i].Count - trace1[j].Count
					report += fmt.Sprintf("grow %d byte(s) in %d allocation(s) from:\n", deltaBytes, deltaCounts)
					for j := 0; j < len(trace2[i].Traceback); j++ {
						report += fmt.Sprintf("\t#%d %s\n", j, trace2[i].Traceback[j])
					}
					totalBytes += deltaBytes
					totalCounts += deltaCounts
				}
				match = true
				break
			}
		}
		if !match {
			report += fmt.Sprintf("\nleak of %d byte(s) in %d allocation(s) from:\n", trace2[i].Size, trace2[i].Count)
			for j := 0; j < len(trace2[i].Traceback); j++ {
				report += fmt.Sprintf("\t#%d %s\n", j, trace2[i].Traceback[j])
			}
			totalBytes += trace2[i].Size
			totalCounts += trace2[i].Count
		}
	}
	summary := fmt.Sprintf("\nSUMMARY: %d byte(s) leaked in %d allocation(s)\n", totalBytes, totalCounts)
	AddReportEntry(summary, report)
}

// CollectEventLogs saves event logs to the test execution directory
func (vpp *VppInstance) CollectEventLogs() {
	vpp.getSuite().Log(vpp.Vppctl("event-logger save event_log"))
	targetDir := vpp.Container.Suite.getLogDirPath()
	err := vpp.Container.GetFile("/tmp/event_log", targetDir+"/"+vpp.Container.Name+"-event_log")
	if err != nil {
		vpp.getSuite().Log(fmt.Sprint(err))
	}
}

// EnablePcapTrace enables packet capture on all interfaces and maximum 10000 packets
func (vpp *VppInstance) EnablePcapTrace() {
	vpp.getSuite().Log(vpp.Vppctl("pcap trace rx tx max 10000 intfc any file vppTest.pcap"))
}

// CollectPcapTrace saves pcap trace to the test execution directory
func (vpp *VppInstance) CollectPcapTrace() {
	vpp.getSuite().Log(vpp.Vppctl("pcap trace off"))
	targetDir := vpp.Container.Suite.getLogDirPath()
	err := vpp.Container.GetFile("/tmp/vppTest.pcap", targetDir+"/"+vpp.Container.Name+".pcap")
	if err != nil {
		vpp.getSuite().Log(fmt.Sprint(err))
	}
}
