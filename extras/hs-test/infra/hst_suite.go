package hst

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/edwarnicke/exechelper"

	containerTypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/onsi/gomega/gmeasure"
	"gopkg.in/yaml.v3"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	DEFAULT_NETWORK_NUM int = 1
)

var IsPersistent = flag.Bool("persist", false, "persists topology config")
var IsVerbose = flag.Bool("verbose", false, "verbose test output")
var IsCoverage = flag.Bool("coverage", false, "use coverage run config")
var IsUnconfiguring = flag.Bool("unconfigure", false, "remove topology")
var IsVppDebug = flag.Bool("debug", false, "attach gdb to vpp")
var NConfiguredCpus = flag.Int("cpus", 1, "number of CPUs assigned to vpp")
var VppSourceFileDir = flag.String("vppsrc", "", "vpp source file directory")
var IsDebugBuild = flag.Bool("debug_build", false, "some paths are different with debug build")
var UseCpu0 = flag.Bool("cpu0", false, "use cpu0")
var IsLeakCheck = flag.Bool("leak_check", false, "run leak-check tests")
var ParallelTotal = flag.Lookup("ginkgo.parallel.total")
var DryRun = flag.Bool("dryrun", false, "set up containers but don't run tests")
var SudoUser = flag.String("sudo_user", "root", "what user ran hs-test with sudo")
var NumaAwareCpuAlloc bool
var TestTimeout time.Duration
var RunningInCi bool

type HstSuite struct {
	AllContainers     map[string]*Container
	StartedContainers []*Container
	Volumes           []string
	NetConfigs        []NetConfig
	NetInterfaces     map[string]*NetInterface
	Ip4AddrAllocator  *Ip4AddressAllocator
	TestIds           map[string]string
	CpuAllocator      *CpuAllocatorT
	CpuContexts       []*CpuContext
	CpuCount          int
	Ppid              string
	ProcessIndex      string
	Logger            *log.Logger
	LogFile           *os.File
	Docker            *client.Client
	CoverageRun       bool
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
	"53",
	"67",
	"68",
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
	"6633",
	"6081",
	"53053",
}

// used for colorful ReportEntry
type StringerStruct struct {
	Label string
}

var testCounter uint16
var startTime time.Time = time.Now()

func testCounterFunc() {
	if ParallelTotal.Value.String() != "1" {
		return
	}
	testCounter++
	fmt.Printf("Test counter: %d\n"+
		"Time elapsed: %.2fs\n",
		testCounter, time.Since(startTime).Seconds())
}

// ColorableString for ReportEntry to use
func (s StringerStruct) ColorableString() string {
	return fmt.Sprintf("{{red}}%s{{/}}", s.Label)
}

// non-colorable String() is used by go's string formatting support but ignored by ReportEntry
func (s StringerStruct) String() string {
	return s.Label
}

func getTestFilename() string {
	_, filename, _, _ := runtime.Caller(2)
	return filepath.Base(filename)
}

func (s *HstSuite) getLogDirPath() string {
	testId := s.GetTestId()
	testName := s.GetCurrentTestName()
	logDirPath := logDir + testName + "/" + testId + "/"

	cmd := exec.Command("mkdir", "-p", logDirPath)
	if err := cmd.Run(); err != nil {
		Fail("mkdir error: " + fmt.Sprint(err))
	}

	return logDirPath
}

func (s *HstSuite) newDockerClient() {
	var err error
	s.Docker, err = client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	s.AssertNil(err)
	s.Log("docker client created")
}

func (s *HstSuite) SetupKindSuite() {
	s.CreateLogger()
	s.Log("[* SUITE SETUP]")
	s.newDockerClient()
	RegisterFailHandler(func(message string, callerSkip ...int) {
		s.HstFail()
		Fail(message, callerSkip...)
	})
	s.Ppid = fmt.Sprint(os.Getppid())
	// remove last number so we have space to prepend a process index (interfaces have a char limit)
	s.Ppid = s.Ppid[:len(s.Ppid)-1]
	s.ProcessIndex = fmt.Sprint(GinkgoParallelProcess())
}

func (s *HstSuite) SetupSuite() {
	s.CreateLogger()
	s.Log("[* SUITE SETUP]")
	s.newDockerClient()
	RegisterFailHandler(func(message string, callerSkip ...int) {
		s.HstFail()
		Fail(message, callerSkip...)
	})
	var err error
	s.Ppid = fmt.Sprint(os.Getppid())
	// remove last number so we have space to prepend a process index (interfaces have a char limit)
	s.Ppid = s.Ppid[:len(s.Ppid)-1]
	s.ProcessIndex = fmt.Sprint(GinkgoParallelProcess())
	s.CpuAllocator, err = CpuAllocator()
	if err != nil {
		Fail("failed to init cpu allocator: " + fmt.Sprint(err))
	}
	s.CpuCount = *NConfiguredCpus
	s.CoverageRun = *IsCoverage
}

func (s *HstSuite) AllocateCpus(containerName string) []int {
	var cpuCtx *CpuContext
	var err error
	currentTestName := CurrentSpecReport().LeafNodeText

	if strings.Contains(currentTestName, "MTTest") {
		prevContainerCount := s.CpuAllocator.maxContainerCount
		if strings.Contains(containerName, "vpp") {
			// CPU range is assigned based on the Ginkgo process index (or build number if
			// running in the CI), *NConfiguredCpus and a maxContainerCount.
			// maxContainerCount is set to 4 when CpuAllocator is initialized.
			// 4 is not a random number - all of our suites use a maximum of 4 containers simultaneously,
			// and it's also the maximum number of containers we can run with *NConfiguredCpus=2 (with CPU0=true)
			// on processors with 8 threads. Currently, the CpuAllocator puts all cores into a slice,
			// makes the length of the slice divisible by 4x*NConfiguredCpus, and then the minCpu and
			// maxCpu (range) for each container is calculated. Then we just offset based on minCpu,
			// the number of started containers and *NConfiguredCpus. This way, every container
			// uses the correct CPUs, even if multiple NUMA nodes are available.
			// However, because of this, if we want to assign different number of cores to different containers,
			// we have to change maxContainerCount to manipulate the CPU range. Hopefully a temporary workaround.
			s.CpuAllocator.maxContainerCount = 1
			cpuCtx, err = s.CpuAllocator.Allocate(1, 3, 0)
		} else {
			s.CpuAllocator.maxContainerCount = 3
			cpuCtx, err = s.CpuAllocator.Allocate(len(s.StartedContainers), s.CpuCount, 2)
		}
		s.CpuAllocator.maxContainerCount = prevContainerCount
	} else {
		cpuCtx, err = s.CpuAllocator.Allocate(len(s.StartedContainers), s.CpuCount, 0)
	}

	s.AssertNil(err)
	s.AddCpuContext(cpuCtx)
	return cpuCtx.cpus
}

func (s *HstSuite) AddCpuContext(cpuCtx *CpuContext) {
	s.CpuContexts = append(s.CpuContexts, cpuCtx)
}

func (s *HstSuite) TearDownSuite() {
	defer s.LogFile.Close()
	defer s.Docker.Close()
	if *IsPersistent || *DryRun {
		return
	}
	s.Log("[* SUITE TEARDOWN]")
	s.UnconfigureNetworkTopology()
}

func (s *HstSuite) TearDownTest() {
	s.Log("[* TEST TEARDOWN]")
	if *IsPersistent || *DryRun {
		return
	}
	coreDump := s.WaitForCoreDump()
	s.ResetContainers()

	if s.Ip4AddrAllocator != nil {
		s.Ip4AddrAllocator.DeleteIpAddresses()
	}

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

func (s *HstSuite) SetupTest() {
	testCounterFunc()
	s.Log("[* TEST SETUP]")
	s.StartedContainers = s.StartedContainers[:0]
	s.SkipIfUnconfiguring()
	s.SetupContainers()
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

	s.Log("vvvvvvvvvvvvvvv " + container.Name + " [VPP instance]:")
	for _, line := range lines {
		s.Log(line)
	}
	s.Log("^^^^^^^^^^^^^^^\n\n")
}

func (s *HstSuite) HstFail() {
	for _, container := range s.StartedContainers {
		out, err := container.log(20)
		if err != nil {
			s.Log("An error occured while obtaining '" + container.Name + "' container logs: " + fmt.Sprint(err))
			s.Log("The container might not be running - check logs in " + s.getLogDirPath())
			continue
		}
		s.Log("\nvvvvvvvvvvvvvvv " +
			container.Name + ":\n" +
			out +
			"^^^^^^^^^^^^^^^\n\n")
		s.LogVppInstance(container, 20)
	}
}

func (s *HstSuite) AssertNil(object interface{}, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, object).To(BeNil(), msgAndArgs...)
}

func (s *HstSuite) AssertNotNil(object interface{}, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, object).ToNot(BeNil(), msgAndArgs...)
}

func (s *HstSuite) AssertEqual(expected, actual interface{}, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, actual).To(Equal(expected), msgAndArgs...)
}

func (s *HstSuite) AssertNotEqual(expected, actual interface{}, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, actual).ToNot(Equal(expected), msgAndArgs...)
}

func (s *HstSuite) AssertContains(testString, contains interface{}, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, strings.ToLower(fmt.Sprint(testString))).To(ContainSubstring(strings.ToLower(fmt.Sprint(contains))), msgAndArgs...)
}

func (s *HstSuite) AssertNotContains(testString, contains interface{}, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, strings.ToLower(fmt.Sprint(testString))).ToNot(ContainSubstring(strings.ToLower(fmt.Sprint(contains))), msgAndArgs...)
}

func (s *HstSuite) AssertEmpty(object interface{}, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, object).To(BeEmpty(), msgAndArgs...)
}

func (s *HstSuite) AssertNotEmpty(object interface{}, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, object).ToNot(BeEmpty(), msgAndArgs...)
}

func (s *HstSuite) AssertMatchError(actual, expected error, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, actual).To(MatchError(expected), msgAndArgs...)
}

func (s *HstSuite) AssertGreaterThan(actual, expected interface{}, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, actual).Should(BeNumerically(">=", expected), msgAndArgs...)
}

func (s *HstSuite) AssertEqualWithinThreshold(actual, expected, threshold interface{}, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, actual).Should(BeNumerically("~", expected, threshold), msgAndArgs...)
}

func (s *HstSuite) AssertTimeEqualWithinThreshold(actual, expected time.Time, threshold time.Duration, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, actual).Should(BeTemporally("~", expected, threshold), msgAndArgs...)
}

func (s *HstSuite) AssertHttpStatus(resp *http.Response, expectedStatus int, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, resp).To(HaveHTTPStatus(expectedStatus), msgAndArgs...)
}

func (s *HstSuite) AssertHttpHeaderWithValue(resp *http.Response, key string, value interface{}, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, resp).To(HaveHTTPHeaderWithValue(key, value), msgAndArgs...)
}

func (s *HstSuite) AssertHttpHeaderNotPresent(resp *http.Response, key string, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, resp.Header.Get(key)).To(BeEmpty(), msgAndArgs...)
}

func (s *HstSuite) AssertHttpContentLength(resp *http.Response, expectedContentLen int64, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, resp).To(HaveHTTPHeaderWithValue("Content-Length", strconv.FormatInt(expectedContentLen, 10)), msgAndArgs...)
}

func (s *HstSuite) AssertHttpBody(resp *http.Response, expectedBody string, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, resp).To(HaveHTTPBody(expectedBody), msgAndArgs...)
}

func (s *HstSuite) AssertChannelClosed(timeout time.Duration, channel chan error) {
	EventuallyWithOffset(2, channel).WithTimeout(timeout).Should(BeClosed())
}

// Pass the parsed result struct and the minimum amount of data transferred in MB
func (s *HstSuite) AssertIperfMinTransfer(result IPerfResult, minTransferred int) {
	if result.Start.Details.Protocol == "TCP" {
		s.AssertGreaterThan(result.End.TcpReceived.MBytes, minTransferred)
	} else {
		s.AssertGreaterThan(result.End.Udp.MBytes, minTransferred)
	}
}

func (s *HstSuite) CreateLogger() {
	suiteName := s.GetCurrentSuiteName()
	var err error
	s.LogFile, err = os.Create("summary/" + suiteName + ".log")
	if err != nil {
		Fail("Unable to create log file.")
	}
	s.Logger = log.New(io.Writer(s.LogFile), "", log.LstdFlags)
}

// Logs to files by default, logs to stdout when VERBOSE=true with GinkgoWriter
// to keep console tidy
func (s *HstSuite) Log(log any, arg ...any) {
	var logStr string
	if len(arg) == 0 {
		logStr = fmt.Sprint(log)
	} else {
		logStr = fmt.Sprintf(fmt.Sprint(log), arg...)
	}
	logs := strings.Split(logStr, "\n")

	for _, line := range logs {
		s.Logger.Println(line)
	}
	if *IsVerbose {
		GinkgoWriter.Println(logStr)
	}
}

func (s *HstSuite) Skip(args string) {
	Skip(args)
}

func (s *HstSuite) SkipIfMultiWorker(args ...any) {
	if *NConfiguredCpus > 1 {
		s.Skip("test case not supported with multiple vpp workers")
	}
}

func (s *HstSuite) SkipIfNotEnoughAvailableCpus() {
	var maxRequestedCpu int
	availableCpus := len(s.CpuAllocator.cpus) - 1

	if *UseCpu0 {
		availableCpus++
	}

	maxRequestedCpu = (GinkgoParallelProcess() * s.CpuAllocator.maxContainerCount * s.CpuCount)

	if availableCpus < maxRequestedCpu {
		s.Skip(fmt.Sprintf("Test case cannot allocate requested cpus "+
			"(%d containers * %d cpus, %d available). Try using 'CPU0=true'",
			s.CpuAllocator.maxContainerCount, s.CpuCount, availableCpus))
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

func (s *HstSuite) WaitForCoreDump() bool {
	var filename string
	dir, err := os.Open(s.getLogDirPath())
	if err != nil {
		s.Log(err)
		return false
	}
	defer dir.Close()

	files, err := dir.Readdirnames(0)
	if err != nil {
		s.Log(err)
		return false
	}
	for _, file := range files {
		if strings.Contains(file, "core") {
			filename = file
		}
	}
	timeout := 60
	waitTime := 5

	if filename != "" {
		corePath := s.getLogDirPath() + filename
		s.Log(fmt.Sprintf("WAITING FOR CORE DUMP (%s)", corePath))
		for i := waitTime; i <= timeout; i += waitTime {
			fileInfo, err := os.Stat(corePath)
			if err != nil {
				s.Log("Error while reading file info: " + fmt.Sprint(err))
				return true
			}
			currSize := fileInfo.Size()
			s.Log(fmt.Sprintf("Waiting %ds/%ds...", i, timeout))
			time.Sleep(time.Duration(waitTime) * time.Second)
			fileInfo, _ = os.Stat(corePath)

			if currSize == fileInfo.Size() {
				debug := ""
				if *IsDebugBuild {
					debug = "_debug"
				}
				vppBinPath := fmt.Sprintf("../../build-root/build-vpp%s-native/vpp/bin/vpp", debug)
				pluginsLibPath := fmt.Sprintf("build-root/build-vpp%s-native/vpp/lib/x86_64-linux-gnu/vpp_plugins", debug)
				cmd := fmt.Sprintf("sudo gdb %s -c %s -ex 'set solib-search-path %s/%s' -ex 'bt full' -batch", vppBinPath, corePath, *VppSourceFileDir, pluginsLibPath)
				s.Log(cmd)
				output, _ := exechelper.Output(cmd)
				AddReportEntry("VPP Backtrace", StringerStruct{Label: string(output)})
				os.WriteFile(s.getLogDirPath()+"backtrace.log", output, os.FileMode(0644))
				if RunningInCi {
					err = os.Remove(corePath)
					if err == nil {
						s.Log("removed " + corePath)
					} else {
						s.Log(err)
					}
				}
				return true
			}
		}
	}
	return false
}

func (s *HstSuite) ResetContainers() {
	for _, container := range s.StartedContainers {
		container.stop()
		s.Log("Removing container " + container.Name)
		if err := s.Docker.ContainerRemove(container.ctx, container.ID, containerTypes.RemoveOptions{RemoveVolumes: true, Force: true}); err != nil {
			s.Log(err)
		}
	}
}

func (s *HstSuite) GetNetNamespaceByName(name string) string {
	return s.ProcessIndex + name + s.Ppid
}

func (s *HstSuite) GetInterfaceByName(name string) *NetInterface {
	return s.NetInterfaces[s.ProcessIndex+name+s.Ppid]
}

func (s *HstSuite) GetContainerByName(name string) *Container {
	return s.AllContainers[s.ProcessIndex+name+s.Ppid]
}

/*
 * Create a copy and return its address, so that individial tests which call this
 * are not able to modify the original container and affect other tests by doing that
 */
func (s *HstSuite) GetTransientContainerByName(name string) *Container {
	containerCopy := *s.AllContainers[s.ProcessIndex+name+s.Ppid]
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

	for _, elem := range yamlTopo.Volumes {
		volumeMap := elem["volume"].(VolumeConfig)
		hostDir := volumeMap["host-dir"].(string)
		workingVolumeDir := logDir + s.GetCurrentTestName() + volumeDir
		volDirReplacer := strings.NewReplacer("$HST_VOLUME_DIR", workingVolumeDir)
		hostDir = volDirReplacer.Replace(hostDir)
		s.Volumes = append(s.Volumes, hostDir)
	}

	s.AllContainers = make(map[string]*Container)
	for _, elem := range yamlTopo.Containers {
		newContainer, err := newContainer(s, elem)
		newContainer.Suite = s
		newContainer.Name = newContainer.Suite.ProcessIndex + newContainer.Name + newContainer.Suite.Ppid
		if err != nil {
			Fail("container config error: " + fmt.Sprint(err))
		}
		s.AllContainers[newContainer.Name] = newContainer
	}

	if *DryRun {
		s.Log(Colors.pur + "* Containers used by this suite (some might already be running):" + Colors.rst)
		for name := range s.AllContainers {
			s.Log("%sdocker start %s && docker exec -it %s bash%s", Colors.pur, name, name, Colors.rst)
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

	s.Ip4AddrAllocator = NewIp4AddressAllocator()
	s.NetInterfaces = make(map[string]*NetInterface)

	for _, elem := range yamlTopo.Devices {
		if _, ok := elem["name"]; ok {
			elem["name"] = s.ProcessIndex + elem["name"].(string) + s.Ppid
		}

		if peer, ok := elem["peer"].(NetDevConfig); ok {
			if peer["name"].(string) != "" {
				peer["name"] = s.ProcessIndex + peer["name"].(string) + s.Ppid
			}
			if _, ok := peer["netns"]; ok {
				peer["netns"] = s.ProcessIndex + peer["netns"].(string) + s.Ppid
			}
		}

		if _, ok := elem["netns"]; ok {
			elem["netns"] = s.ProcessIndex + elem["netns"].(string) + s.Ppid
		}

		if _, ok := elem["interfaces"]; ok {
			interfaceCount := len(elem["interfaces"].([]interface{}))
			for i := 0; i < interfaceCount; i++ {
				elem["interfaces"].([]interface{})[i] = s.ProcessIndex + elem["interfaces"].([]interface{})[i].(string) + s.Ppid
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
				if netIf, err := newNetworkInterface(elem, s.Ip4AddrAllocator); err == nil {
					s.NetConfigs = append(s.NetConfigs, netIf)
					s.NetInterfaces[netIf.Name()] = netIf
				} else {
					Fail("network config error: " + fmt.Sprint(err))
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
		s.Log(nc.Name())
		if err := nc.configure(); err != nil {
			Fail("Network config error: " + fmt.Sprint(err))
		}
	}
}

func (s *HstSuite) UnconfigureNetworkTopology() {
	for _, nc := range s.NetConfigs {
		nc.unconfigure()
	}
}

func (s *HstSuite) LogStartedContainers() {
	s.Log("%s* Started containers:%s", Colors.grn, Colors.rst)
	for _, container := range s.StartedContainers {
		s.Log(Colors.grn + container.Name + Colors.rst)
	}
}

func (s *HstSuite) GetTestId() string {
	testName := s.GetCurrentTestName()

	if s.TestIds == nil {
		s.TestIds = map[string]string{}
	}

	if _, ok := s.TestIds[testName]; !ok {
		s.TestIds[testName] = time.Now().Format("2006-01-02_15-04-05")
	}

	return s.TestIds[testName]
}

func (s *HstSuite) GetCurrentTestName() string {
	return strings.Split(CurrentSpecReport().LeafNodeText, "/")[1]
}

func (s *HstSuite) GetCurrentSuiteName() string {
	return CurrentSpecReport().ContainerHierarchyTexts[0]
}

// Returns last 3 digits of PID + Ginkgo process index as the 4th digit. If the port is in the 'reservedPorts' slice,
// increment port number by ten and check again.
func (s *HstSuite) GetPortFromPpid() string {
	port := s.Ppid
	var err error
	var portInt int
	for len(port) < 3 {
		port += "0"
	}
	port = port[len(port)-3:] + s.ProcessIndex
	for slices.Contains(reservedPorts, port) {
		portInt, err = strconv.Atoi(port)
		s.AssertNil(err)
		portInt += 10
		port = fmt.Sprintf("%d", portInt)
	}
	return port
}

/*
RunBenchmark creates Gomega's experiment with the passed-in name and samples the passed-in callback repeatedly (samplesNum times),
passing in suite context, experiment and your data.

You can also instruct runBenchmark to run with multiple concurrent workers.
Note that if running in parallel Gomega returns from Sample when spins up all samples and does not wait until all finished.
You can record multiple named measurements (float64 or duration) within passed-in callback.
runBenchmark then produces report to show statistical distribution of measurements.
*/
func (s *HstSuite) RunBenchmark(name string, samplesNum, parallelNum int, callback func(s *HstSuite, e *gmeasure.Experiment, data interface{}), data interface{}) {
	experiment := gmeasure.NewExperiment(name)

	experiment.Sample(func(idx int) {
		defer GinkgoRecover()
		callback(s, experiment, data)
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
			s.Log("\n> Received request (" + req.RemoteAddr + "):\n" +
				string(dump) +
				"\n------------------------------\n")
		}
	}
}
