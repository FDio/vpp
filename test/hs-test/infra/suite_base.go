package hst

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	containerTypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/edwarnicke/exechelper"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gmeasure"
	"gopkg.in/yaml.v3"
)

const (
	DEFAULT_NETWORK_NUM int = 1
)

var IsUnconfiguring = flag.Bool("unconfigure", false, "remove topology")
var NConfiguredCpus = flag.Int("cpus", 1, "number of CPUs assigned to non-vpp containers")
var NConfiguredVppCpus = flag.Int("vpp_cpus", 1, "number of CPUs assigned to vpp containers")
var VppSourceFileDir = flag.String("vppsrc", "", "vpp source file directory")
var IsDebugBuild = flag.Bool("debug_build", false, "some paths are different with debug build")
var UseCpu0 = flag.Bool("cpu0", false, "use cpu0")
var IsLeakCheck = flag.Bool("leak_check", false, "run leak-check tests")
var IsCoverage = flag.Bool("coverage", false, "use coverage run config")
var IsPersistent = flag.Bool("persist", false, "persists topology config")
var IsVerbose = flag.Bool("verbose", false, "verbose test output")
var WhoAmI = flag.String("whoami", "root", "what user ran hs-test")
var ParallelTotal = flag.Lookup("ginkgo.parallel.total")
var IsVppDebug = flag.Bool("debug", false, "attach gdb to vpp")
var DryRun = flag.Bool("dryrun", false, "set up containers but don't run tests")
var Timeout = flag.Int("timeout", 5, "test timeout override (in minutes)")
var PerfTesting = flag.Bool("perf", false, "perf test flag")
var HostPpid = flag.Int("host_ppid", os.Getppid(), "automatically set in Makefile")
var CpuOffset = flag.Int("cpu_offset", 0, "initial CPU offset")
var HyperThreading = flag.Bool("hyperthread", false, "whether to use hyperthreads in CPU allocation")
var NumaAwareCpuAlloc bool
var TestTimeout time.Duration
var RunningInCi bool
var TestsThatWillRun int
var Ppid string

const (
	LogDir    string = "/tmp/hs-test/"
	VolumeDir string = "/vol"
)

type HstSuite struct {
	ProcessIndex        string
	AllContainers       map[string]*Container
	StartedContainers   []*Container
	NetConfigs          []NetConfig
	NetInterfaces       map[string]*NetInterface
	Ip4AddrAllocator    *Ip4AddressAllocator
	Ip6AddrAllocator    *Ip6AddressAllocator
	TestIds             map[string]string
	CpuAllocator        *CpuAllocatorT
	CpuContexts         []*CpuContext
	CpusPerContainer    int
	CpusPerVppContainer int
	Docker              *client.Client
	CoverageRun         bool
	numOfNewPorts       int
	SkipIfNotEnoguhCpus bool
}

type colors struct {
	grn string
	pur string
	rst string
}

var Colors = colors{
	grn: "\033[32m",
	pur: "\033[35m",
	rst: "\033[0m",
}

// ../../src/vnet/udp/udp_local.h:foreach_udp4_dst_port
var reservedPorts = []string{
	"22",
	"53",
	"67",
	"68",
	"80",
	"443",
	"500",
	"2152",
	"3784",
	"3785",
	"4341",
	"4342",
	"4500",
	"4739",
	"4784",
	"4789",
	"4789",
	"48879",
	"4790",
	"5000",
	"5001",
	"6633",
	"6081",
	"53053",
	// reserved for h2specd
	"30000",
	"30001",
	"30002",
	"30003",
	"30004",
	"30005",
	"30006",
	"30007",
	"30008",
	"30009",
	"30010",
	"30011",
	"30012",
	"30013",
	"30014",
	"30015",
	"30016",
	"30017",
	"30018",
	"30019",
	"30020",
	"30021",
	"30022",
	"30023",
	"30024",
	"30025",
	"30026",
	"30027",
	"30028",
	"30029",
	"30030",
	"30031",
	"30032",
	"30033",
	"30034",
	"30035",
	"30036",
	"30037",
	"30038",
	"30039",
	"30040",
	"30041",
	"30042",
	"30043",
	"30044",
	"30045",
	"30046",
	"30047",
	"30048",
	"30049",
	"30050",
	"30051",
	"30052",
	"30053",
	"30054",
	"30055",
	"30056",
	"30080",
}

// used for colorful ReportEntry
type StringerStruct struct {
	Label string
}

// ColorableString for ReportEntry to use
func (s StringerStruct) ColorableString() string {
	return fmt.Sprintf("{{red}}%s{{/}}", s.Label)
}

// non-colorable String() is used by go's string formatting support but ignored by ReportEntry
func (s StringerStruct) String() string {
	return s.Label
}

func (s *HstSuite) getLogDirPath() string {
	testId := s.GetTestId()
	testName := GetCurrentTestName()
	logDirPath := LogDir + testName + "/" + testId + "/"

	cmd := exec.Command("mkdir", "-m", "777", "-p", logDirPath)
	if err := cmd.Run(); err != nil {
		Fail("mkdir error: " + fmt.Sprint(err))
	}

	return logDirPath
}

func (s *HstSuite) newDockerClient() {
	var err error
	s.Docker, err = client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	AssertNil(err)
	Log("docker client created")
}

func (s *HstSuite) AllocateCpus(containerName string) []int {
	var cpuCtx *CpuContext
	var err error

	if strings.Contains(containerName, "vpp") {
		// CPUs are allocated based on s.CpusPerVppContainer/s.CpusPerContainer (defaults can be overridden globally
		// or per test) and 'lastCpu' which serves as an offset. 'lastCpu' is incremented by 4 for each
		// GinkgoParallelProcess() in SetupTest() in hst_suite, because all suites use 4 containers
		// at most with 1 CPU each. GinkgoParallelProcess() offset doesn't impact MW or solo tests.
		// Numa aware cpu allocation will use the second numa
		// node if a container doesn't "fit" into the first node.
		cpuCtx, err = s.CpuAllocator.Allocate(s.CpusPerVppContainer, s.CpuAllocator.lastCpu)
	} else {
		cpuCtx, err = s.CpuAllocator.Allocate(s.CpusPerContainer, s.CpuAllocator.lastCpu)
	}

	AssertNil(err)
	s.AddCpuContext(cpuCtx)
	return cpuCtx.cpus
}

func (s *HstSuite) AddCpuContext(cpuCtx *CpuContext) {
	s.CpuContexts = append(s.CpuContexts, cpuCtx)
}

func (s *HstSuite) Skip(args string) {
	Skip(args)
}

func (s *HstSuite) SetupSuite() {
	RegisterFailHandler(func(message string, callerSkip ...int) {
		s.HstFail()
		Fail(message, callerSkip...)
	})
	CreateLogger()
	Log("[* SUITE SETUP]")
	s.ProcessIndex = fmt.Sprint(GinkgoParallelProcess())
	s.newDockerClient()

	var err error
	s.CpuAllocator, err = CpuAllocator()
	s.CpuAllocator.suite = s
	if err != nil {
		Fail("failed to init cpu allocator: " + fmt.Sprint(err))
	}
	s.CpusPerContainer = *NConfiguredCpus
	s.CpusPerVppContainer = *NConfiguredVppCpus
	s.CoverageRun = *IsCoverage
}

func (s *HstSuite) TeardownSuite() {
	defer LogFile.Close()
	defer s.Docker.Close()
	if *IsPersistent || *DryRun {
		s.Skip("Skipping suite teardown")
	}
	Log("[* SUITE TEARDOWN]")
	// allow ports to be reused by removing them from reservedPorts slice
	reservedPorts = reservedPorts[:len(reservedPorts)-s.numOfNewPorts]
	if s.Ip4AddrAllocator != nil {
		s.Ip4AddrAllocator.DeleteIpAddresses()
	}

	if s.Ip6AddrAllocator != nil {
		s.Ip6AddrAllocator.DeleteIpAddresses()
	}
	s.UnconfigureNetworkTopology()
}

func (s *HstSuite) SetupTest() {
	TestCounterFunc()
	Log("[* TEST SETUP]")
	// doesn't impact MW/solo tests
	s.CpuAllocator.lastCpu = (GinkgoParallelProcess() - 1) * 4
	s.StartedContainers = s.StartedContainers[:0]
	s.SkipIfUnconfiguring()
	s.SetupContainers()
}

func (s *HstSuite) TeardownTest() {
	if *IsPersistent || *DryRun {
		s.Skip("Skipping test teardown")
	}
	Log("[* TEST TEARDOWN]")
	s.SkipIfNotEnoguhCpus = false
	// reset to defaults
	s.CpusPerContainer = *NConfiguredCpus
	s.CpusPerVppContainer = *NConfiguredVppCpus
	coreDump := s.WaitForCoreDump()
	s.ResetContainers()

	if coreDump {
		Fail("VPP crashed")
	}
}

func (s *HstSuite) SkipIfUnconfiguring() {
	if *IsUnconfiguring {
		s.Skip("skipping to unconfigure")
	}
}

func (s *HstSuite) SkipIfNotCoverage() {
	if !s.CoverageRun {
		s.Skip("skipping, not a coverage run")
	}
}

func (s *HstSuite) SetupContainers() {
	for _, container := range s.AllContainers {
		if !container.IsOptional {
			container.Run()
		}
	}
}

func (s *HstSuite) LogVppInstance(container *Container, maxLines int) {
	if container.VppInstance == nil {
		return
	}

	logSource := container.GetHostWorkDir() + defaultLogFilePath
	file, err := os.Open(logSource)
	if err != nil {
		Log("%v", err)
		return
	}
	err = os.Chmod(logSource, 0666)
	if err != nil {
		Log("%v", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var lines []string
	var counter int

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		counter++
		if counter > maxLines {
			lines = lines[1:]
			counter--
		}
	}

	Log("vvvvvvvvvvvvvvv " + container.Name + " [VPP instance]:")
	for _, line := range lines {
		Log(line)
	}
	Log("^^^^^^^^^^^^^^^\n\n")
}

func (s *HstSuite) HstFail() {
	for _, container := range s.StartedContainers {
		out, err := container.log(20)
		if err != nil {
			Log("An error occured while obtaining '" + container.Name + "' container logs: " + fmt.Sprint(err))
			Log("The container might not be running - check logs in " + s.getLogDirPath())
			continue
		}
		Log("\nvvvvvvvvvvvvvvv " +
			container.Name + ":\n" +
			out +
			"^^^^^^^^^^^^^^^\n\n")
		s.LogVppInstance(container, 20)
	}
}

func (s *HstSuite) SkipIfMultiWorker(args ...any) {
	if *NConfiguredCpus > 1 {
		s.Skip("test case not supported with multiple vpp workers")
	}
}

func (s *HstSuite) SkipUnlessLeakCheck() {
	if !*IsLeakCheck {
		s.Skip("leak-check tests excluded")
	}
}

func (s *HstSuite) SkipIfArm() {
	if runtime.GOARCH == "arm64" {
		s.Skip("test case not supported on arm")
	}
}

type coreInfo struct {
	file    string
	binPath string
}

func (s *HstSuite) WaitForCoreDump() bool {
	var coreFiles []coreInfo
	dir, err := os.Open(s.getLogDirPath())
	if err != nil {
		Log(err)
		return false
	}
	defer dir.Close()

	files, err := dir.Readdirnames(0)
	if err != nil {
		Log(err)
		return false
	}
	for _, file := range files {
		coreBin, isCore := GetCoreProcessName(s.getLogDirPath() + file)
		if isCore {
			coreFiles = append(coreFiles, coreInfo{file, coreBin})
		}
	}
	timeout := 60
	waitTime := 5

	if len(coreFiles) == 0 {
		return false
	}
	arch, _ := exechelper.Output("uname -m")
	archStr := strings.TrimSpace(string(arch))
	for _, core := range coreFiles {
		corePath := s.getLogDirPath() + core.file
		os.Chmod(corePath, 0666)
		Log(fmt.Sprintf("WAITING FOR CORE DUMP (%s)", corePath))
		for i := waitTime; i <= timeout; i += waitTime {
			fileInfo, err := os.Stat(corePath)
			if err != nil {
				Log("Error while reading file info: " + fmt.Sprint(err))
				return true
			}
			currSize := fileInfo.Size()
			Log(fmt.Sprintf("Waiting %ds/%ds...", i, timeout))
			time.Sleep(time.Duration(waitTime) * time.Second)
			fileInfo, _ = os.Stat(corePath)

			if currSize == fileInfo.Size() {
				debug := ""
				if *IsDebugBuild {
					debug = "_debug"
				}
				var binPath, libPath string
				if strings.Contains(core.binPath, "vpp") {
					binPath = fmt.Sprintf("../../build-root/build-vpp%s-native/vpp/bin/vpp", debug)
					libPath = fmt.Sprintf("build-root/build-vpp%s-native/vpp/lib/%s-linux-gnu/vpp_plugins",
						debug, archStr)
				} else if strings.Contains(core.binPath, "vcl_test_client") {
					binPath = fmt.Sprintf("../../build-root/build-vpp%s-native/vpp/bin/vcl_test_client", debug)
					libPath = fmt.Sprintf("build-root/build-vpp%s-native/vpp/lib/%s-linux-gnu/vpp_plugins",
						debug, archStr)
				} else if strings.Contains(core.binPath, "vcl_test_server") {
					binPath = fmt.Sprintf("../../build-root/build-vpp%s-native/vpp/bin/vcl_test_server", debug)
					libPath = fmt.Sprintf("build-root/build-vpp%s-native/vpp/lib/%s-linux-gnu/vpp_plugins",
						debug, archStr)
				} else if strings.Contains(core.binPath, "vcl_test_cl_udp") {
					binPath = fmt.Sprintf("../../build-root/build-vpp%s-native/vpp/bin/vcl_test_cl_udp", debug)
					libPath = fmt.Sprintf("build-root/build-vpp%s-native/vpp/lib/%s-linux-gnu/vpp_plugins",
						debug, archStr)
				} else if strings.Contains(core.binPath, "vpp_echo") {
					binPath = fmt.Sprintf("../../build-root/build-vpp%s-native/vpp/bin/vpp_echo", debug)
					libPath = fmt.Sprintf("build-root/build-vpp%s-native/vpp/lib/%s-linux-gnu/vpp_plugins",
						debug, archStr)
				} else {
					binPath = core.binPath
					// this was most likely LDP and we want symbol table
					libPath = fmt.Sprintf("build-root/build-vpp%s-native/vpp/lib/%s-linux-gnu", debug, archStr)
				}
				cmd := fmt.Sprintf("sudo gdb %s -c %s -ex 'set solib-search-path %s/%s' -ex 'bt full' -batch", binPath, corePath, *VppSourceFileDir, libPath)
				Log(cmd)
				output, _ := exechelper.Output(cmd)
				if strings.Contains(core.binPath, "vpp") {
					AddReportEntry("VPP Backtrace", StringerStruct{Label: string(output)})
				} else {
					AddReportEntry("APP Backtrace", StringerStruct{Label: string(output)})
				}
				f, err := os.OpenFile(s.getLogDirPath()+"backtrace.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, os.FileMode(0644))
				if err != nil {
					Log("Error opening backtrace.log: " + fmt.Sprint(err))
				} else {
					if _, err := f.Write(output); err != nil {
						Log("Error writing backtrace.log: " + fmt.Sprint(err))
					}
					f.Close()
				}
				if RunningInCi {
					err = os.Remove(corePath)
					if err == nil {
						Log("removed " + corePath)
					} else {
						Log(err)
					}
				}
				break
			}
		}
	}
	return true
}

func (s *HstSuite) ResetContainers() {
	s.CpuAllocator.lastCpu = 0
	for _, container := range s.StartedContainers {
		container.stop()
		Log("Removing container " + container.Name)
		if err := s.Docker.ContainerRemove(container.ctx, container.ID, containerTypes.RemoveOptions{RemoveVolumes: true, Force: true}); err != nil {
			Log(err)
		}
	}
}

func (s *HstSuite) GetNetNamespaceByName(name string) string {
	return s.ProcessIndex + name + Ppid
}

func (s *HstSuite) GetInterfaceByName(name string) *NetInterface {
	if s.NetInterfaces[s.ProcessIndex+name+Ppid] == nil {
		Fail(s.ProcessIndex + name + Ppid + ": Interface not found")
	}
	return s.NetInterfaces[s.ProcessIndex+name+Ppid]
}

func (s *HstSuite) GetContainerByName(name string) *Container {
	return s.AllContainers[s.ProcessIndex+name+Ppid]
}

/*
 * Create a copy and return its address, so that individial tests which call this
 * are not able to modify the original container and affect other tests by doing that
 */
func (s *HstSuite) GetTransientContainerByName(name string) *Container {
	containerCopy := *s.AllContainers[s.ProcessIndex+name+Ppid]
	return &containerCopy
}

func (s *HstSuite) LoadContainerTopology(topologyName string) {
	data, err := os.ReadFile(containerTopologyDir + topologyName + ".yaml")
	if err != nil {
		Fail("read error: " + fmt.Sprint(err))
	}
	var yamlTopo YamlTopology
	err = yaml.Unmarshal(data, &yamlTopo)
	if err != nil {
		Fail("unmarshal error: " + fmt.Sprint(err))
	}

	s.AllContainers = make(map[string]*Container)
	for _, elem := range yamlTopo.Containers {
		newContainer, err := newContainer(s, elem)
		newContainer.Suite = s
		newContainer.Name = newContainer.Suite.ProcessIndex + newContainer.Name + Ppid
		if err != nil {
			Fail("container config error: " + fmt.Sprint(err))
		}
		s.AllContainers[newContainer.Name] = newContainer
	}

	if *DryRun {
		Log(Colors.pur + "* Containers used by this suite (some might already be running):" + Colors.rst)
		for name := range s.AllContainers {
			Log("%sdocker start %s && docker exec -it %s bash%s", Colors.pur, name, name, Colors.rst)
		}
	}
}

func (s *HstSuite) LoadNetworkTopology(topologyName string) {
	data, err := os.ReadFile(networkTopologyDir + topologyName + ".yaml")
	if err != nil {
		Fail("read error: " + fmt.Sprint(err))
	}
	var yamlTopo YamlTopology
	err = yaml.Unmarshal(data, &yamlTopo)
	if err != nil {
		Fail("unmarshal error: " + fmt.Sprint(err))
	}

	s.Ip6AddrAllocator = NewIp6AddressAllocator()
	s.Ip4AddrAllocator = NewIp4AddressAllocator()
	s.NetInterfaces = make(map[string]*NetInterface)

	for _, elem := range yamlTopo.Devices {
		if _, ok := elem["ipv6"]; ok {
			elem["ipv6"] = elem["ipv6"].(bool)
		} else {
			elem["ipv6"] = false
		}
		if _, ok := elem["name"]; ok {
			if elem["name"].(string) != "" {
				elem["name"] = s.ProcessIndex + elem["name"].(string) + Ppid
			}
		}

		if host, ok := elem["host"].(NetDevConfig); ok {
			if host["name"].(string) != "" {
				host["name"] = s.ProcessIndex + host["name"].(string) + Ppid
			}
			if _, ok := host["netns"]; ok {
				host["netns"] = s.ProcessIndex + host["netns"].(string) + Ppid
			}
		}

		if _, ok := elem["netns"]; ok {
			elem["netns"] = s.ProcessIndex + elem["netns"].(string) + Ppid
		}

		if _, ok := elem["interfaces"]; ok {
			interfaceCount := len(elem["interfaces"].([]any))
			for i := range interfaceCount {
				elem["interfaces"].([]any)[i] = s.ProcessIndex + elem["interfaces"].([]any)[i].(string) + Ppid
			}
		}

		switch elem["type"].(string) {
		case NetNs:
			{
				if namespace, err := newNetNamespace(elem); err == nil {
					s.NetConfigs = append(s.NetConfigs, &namespace)
				} else {
					Fail("network config error: " + fmt.Sprint(err))
				}
			}
		case Veth, Tap:
			{
				if elem["ipv6"].(bool) {
					if netIf, err := newNetworkInterface6(elem, s.Ip6AddrAllocator); err == nil {
						s.NetConfigs = append(s.NetConfigs, netIf)
						s.NetInterfaces[netIf.Name()] = netIf
					} else {
						Fail("network config error: " + fmt.Sprint(err))
					}
				} else {
					if netIf, err := newNetworkInterface(elem, s.Ip4AddrAllocator); err == nil {
						s.NetConfigs = append(s.NetConfigs, netIf)
						s.NetInterfaces[netIf.Name()] = netIf
					} else {
						Fail("network config error: " + fmt.Sprint(err))
					}
				}

			}
		case Bridge:
			{
				if bridge, err := newBridge(elem); err == nil {
					s.NetConfigs = append(s.NetConfigs, &bridge)
				} else {
					Fail("network config error: " + fmt.Sprint(err))
				}
			}
		}
	}
}

func (s *HstSuite) ConfigureNetworkTopology(topologyName string) {
	s.LoadNetworkTopology(topologyName)

	if *IsUnconfiguring {
		return
	}

	for _, nc := range s.NetConfigs {
		Log(nc.Name())
		if err := nc.configure(); err != nil {
			Fail("Network config error: " + fmt.Sprint(err))
		}
	}
}

func (s *HstSuite) UnconfigureNetworkTopology() {
	unconfigureHelper := func(nc NetConfig) {
		err := nc.unconfigure()
		if err != nil {
			Log("Interface: %s | Type: %s | Error: %v", nc.Name(), nc.Type(), err)
			AssertNil(err)
		}
	}

	for _, nc := range s.NetConfigs {
		// remove namespaces last
		if nc.Type() == NetNs {
			defer unconfigureHelper(nc)
		} else {
			unconfigureHelper(nc)
		}
	}
}

func (s *HstSuite) LogStartedContainers() {
	Log("%s* Started containers:%s", Colors.grn, Colors.rst)
	for _, container := range s.StartedContainers {
		Log(Colors.grn + container.Name + Colors.rst)
	}
}

func (s *HstSuite) GetTestId() string {
	testName := GetCurrentTestName()

	if s.TestIds == nil {
		s.TestIds = map[string]string{}
	}

	if _, ok := s.TestIds[testName]; !ok {
		s.TestIds[testName] = time.Now().Format("060102_150405")
	}

	return s.TestIds[testName]
}

// Returns Ginkgo process index + last 3 digits of PID. If the port is in the 'reservedPorts' slice,
// increment port number by ten and check again. Generates a new port after each use. Always bigger or equal to 1000.
func (s *HstSuite) GeneratePort() string {
	var err error
	var portInt int
	port := Ppid

	port = s.ProcessIndex + port
	for len(port) < 3 {
		port += "0"
	}

	for slices.Contains(reservedPorts, port) {
		portInt, err = strconv.Atoi(port)
		AssertNil(err)
		portInt += 10
		port = fmt.Sprintf("%d", portInt)
	}
	reservedPorts = append(reservedPorts, port)
	s.numOfNewPorts++
	Log("generated port " + port)
	return port
}

func (s *HstSuite) GeneratePortAsInt() uint16 {
	port, err := strconv.Atoi(s.GeneratePort())
	AssertNil(err)
	return uint16(port)
}

/*
RunBenchmark creates Gomega's experiment with the passed-in name and samples the passed-in callback repeatedly (samplesNum times),
passing in suite context, experiment and your data.

You can also instruct runBenchmark to run with multiple concurrent workers.
Note that if running in parallel Gomega returns from Sample when spins up all samples and does not wait until all finished.
You can record multiple named measurements (float64 or duration) within passed-in callback.
runBenchmark then produces report to show statistical distribution of measurements.
*/
func (s *HstSuite) RunBenchmark(name string, samplesNum, parallelNum int, callback func(e *gmeasure.Experiment, data any), data any) {
	experiment := gmeasure.NewExperiment(name)

	experiment.Sample(func(idx int) {
		defer GinkgoRecover()
		callback(experiment, data)
	}, gmeasure.SamplingConfig{N: samplesNum, NumParallel: parallelNum})
	AddReportEntry(experiment.Name, experiment)
}

/*
LogHttpReq is Gomega's ghttp server handler which logs received HTTP request.

You should put it at the first place, so request is logged always.
*/
func (s *HstSuite) LogHttpReq(body bool) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		dump, err := httputil.DumpRequest(req, body)
		if err == nil {
			Log("\n> Received request (" + req.RemoteAddr + "):\n" +
				string(dump) +
				"\n------------------------------\n")
		}
	}
}
