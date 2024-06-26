package hst

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/onsi/gomega/gmeasure"
	"gopkg.in/yaml.v3"

	"github.com/edwarnicke/exechelper"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	DEFAULT_NETWORK_NUM int = 1
)

var IsPersistent = flag.Bool("persist", false, "persists topology config")
var IsVerbose = flag.Bool("verbose", false, "verbose test output")
var IsUnconfiguring = flag.Bool("unconfigure", false, "remove topology")
var IsVppDebug = flag.Bool("debug", false, "attach gdb to vpp")
var NConfiguredCpus = flag.Int("cpus", 1, "number of CPUs assigned to vpp")
var VppSourceFileDir = flag.String("vppsrc", "", "vpp source file directory")
var IsDebugBuild = flag.Bool("debug_build", false, "some paths are different with debug build")
var SuiteTimeout time.Duration

type HstSuite struct {
	Containers        map[string]*Container
	StartedContainers []*Container
	Volumes           []string
	NetConfigs        []NetConfig
	NetInterfaces     map[string]*NetInterface
	Ip4AddrAllocator  *Ip4AddressAllocator
	TestIds           map[string]string
	CpuAllocator      *CpuAllocatorT
	CpuContexts       []*CpuContext
	CpuPerVpp         int
	Ppid              string
	ProcessIndex      string
	Logger            *log.Logger
	LogFile           *os.File
}

func getTestFilename() string {
	_, filename, _, _ := runtime.Caller(2)
	return filepath.Base(filename)
}

func (s *HstSuite) SetupSuite() {
	s.CreateLogger()
	s.Log("Suite Setup")
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
	s.CpuPerVpp = *NConfiguredCpus
}

func (s *HstSuite) AllocateCpus() []int {
	cpuCtx, err := s.CpuAllocator.Allocate(len(s.StartedContainers), s.CpuPerVpp)
	s.AssertNil(err)
	s.AddCpuContext(cpuCtx)
	return cpuCtx.cpus
}

func (s *HstSuite) AddCpuContext(cpuCtx *CpuContext) {
	s.CpuContexts = append(s.CpuContexts, cpuCtx)
}

func (s *HstSuite) TearDownSuite() {
	defer s.LogFile.Close()
	s.Log("Suite Teardown")
	s.UnconfigureNetworkTopology()
}

func (s *HstSuite) TearDownTest() {
	s.Log("Test Teardown")
	if *IsPersistent {
		return
	}
	s.ResetContainers()
	s.RemoveVolumes()
	s.Ip4AddrAllocator.DeleteIpAddresses()
}

func (s *HstSuite) SkipIfUnconfiguring() {
	if *IsUnconfiguring {
		s.Skip("skipping to unconfigure")
	}
}

func (s *HstSuite) SetupTest() {
	s.Log("Test Setup")
	s.StartedContainers = s.StartedContainers[:0]
	s.SkipIfUnconfiguring()
	s.SetupVolumes()
	s.SetupContainers()
}

func (s *HstSuite) SetupVolumes() {
	for _, volume := range s.Volumes {
		cmd := "docker volume create --name=" + volume
		s.Log(cmd)
		exechelper.Run(cmd)
	}
}

func (s *HstSuite) SetupContainers() {
	for _, container := range s.Containers {
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
			s.Log("The container might not be running - check logs in " + container.getLogDirPath())
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
	Expect(object).To(BeNil(), msgAndArgs...)
}

func (s *HstSuite) AssertNotNil(object interface{}, msgAndArgs ...interface{}) {
	Expect(object).ToNot(BeNil(), msgAndArgs...)
}

func (s *HstSuite) AssertEqual(expected, actual interface{}, msgAndArgs ...interface{}) {
	Expect(actual).To(Equal(expected), msgAndArgs...)
}

func (s *HstSuite) AssertNotEqual(expected, actual interface{}, msgAndArgs ...interface{}) {
	Expect(actual).ToNot(Equal(expected), msgAndArgs...)
}

func (s *HstSuite) AssertContains(testString, contains interface{}, msgAndArgs ...interface{}) {
	Expect(testString).To(ContainSubstring(fmt.Sprint(contains)), msgAndArgs...)
}

func (s *HstSuite) AssertNotContains(testString, contains interface{}, msgAndArgs ...interface{}) {
	Expect(testString).ToNot(ContainSubstring(fmt.Sprint(contains)), msgAndArgs...)
}

func (s *HstSuite) AssertNotEmpty(object interface{}, msgAndArgs ...interface{}) {
	Expect(object).ToNot(BeEmpty(), msgAndArgs...)
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
func (s *HstSuite) Log(arg any) {
	logs := strings.Split(fmt.Sprint(arg), "\n")
	for _, line := range logs {
		s.Logger.Println(line)
	}
	if *IsVerbose {
		GinkgoWriter.Println(arg)
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

func (s *HstSuite) SkipUnlessExtendedTestsBuilt() {
	imageName := "hs-test/nginx-http3"

	cmd := exec.Command("docker", "images", imageName)
	byteOutput, err := cmd.CombinedOutput()
	if err != nil {
		s.Log("error while searching for docker image")
		return
	}
	if !strings.Contains(string(byteOutput), imageName) {
		s.Skip("extended tests not built")
	}
}

func (s *HstSuite) ResetContainers() {
	for _, container := range s.StartedContainers {
		container.stop()
		exechelper.Run("docker rm " + container.Name)
	}
}

func (s *HstSuite) RemoveVolumes() {
	for _, volumeName := range s.Volumes {
		cmd := "docker volume rm " + volumeName
		exechelper.Run(cmd)
		os.RemoveAll(volumeName)
	}
}

func (s *HstSuite) GetNetNamespaceByName(name string) string {
	return s.ProcessIndex + name + s.Ppid
}

func (s *HstSuite) GetInterfaceByName(name string) *NetInterface {
	return s.NetInterfaces[s.ProcessIndex+name+s.Ppid]
}

func (s *HstSuite) GetContainerByName(name string) *Container {
	return s.Containers[s.ProcessIndex+name+s.Ppid]
}

/*
 * Create a copy and return its address, so that individial tests which call this
 * are not able to modify the original container and affect other tests by doing that
 */
func (s *HstSuite) GetTransientContainerByName(name string) *Container {
	containerCopy := *s.Containers[s.ProcessIndex+name+s.Ppid]
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

	s.Containers = make(map[string]*Container)
	for _, elem := range yamlTopo.Containers {
		newContainer, err := newContainer(s, elem)
		newContainer.Suite = s
		newContainer.Name = newContainer.Suite.ProcessIndex + newContainer.Name + newContainer.Suite.Ppid
		if err != nil {
			Fail("container config error: " + fmt.Sprint(err))
		}
		s.Containers[newContainer.Name] = newContainer
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
	if *IsPersistent {
		return
	}
	for _, nc := range s.NetConfigs {
		nc.unconfigure()
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

// Returns last 3 digits of PID + Ginkgo process index as the 4th digit
func (s *HstSuite) GetPortFromPpid() string {
	port := s.Ppid
	for len(port) < 3 {
		port += "0"
	}
	return port[len(port)-3:] + s.ProcessIndex
}

func (s *HstSuite) StartServerApp(c *Container, env map[string]string, running chan error, done chan struct{}) {
	for key, value := range env {
		c.AddEnvVar(key, value)
	}

	s.Log("starting server")
	c.ExecServer("iperf3 -4 -s -1 -p " + s.GetPortFromPpid())

	err := exechelper.Run("docker exec " + c.Name + " pidof iperf3")
	if err != nil {
		msg := fmt.Errorf("failed to start iperf server: %v", err)
		running <- msg
		return
	}
	running <- nil
	<-done
}

func (s *HstSuite) StartClientApp(c *Container, ipAddress string, env map[string]string, clnCh chan error, clnRes chan string) {
	defer func() {
		clnCh <- nil
	}()

	for key, value := range env {
		c.AddEnvVar(key, value)
	}

	s.Log("starting client")
	nTries := 0
	for {
		o, err := exechelper.CombinedOutput("docker exec " + c.getEnvVarsAsCliOption() + " " + c.Name + " iperf3 -c " + ipAddress + " -u -l 1460 -b 10g -p " + s.GetPortFromPpid())
		if err != nil {
			if nTries > 5 {
				clnCh <- fmt.Errorf("failed to start client app '%s'", err)
				return
			}
			time.Sleep(1 * time.Second)
			nTries++
			continue
		} else {
			s.Log("running iperf3:")
			clnRes <- fmt.Sprintf("Client output: %s", o)
		}
		break
	}
}

func (s *HstSuite) StartHttpServer(running chan struct{}, done chan struct{}, addressPort, netNs string) {
	cmd := newCommand([]string{"./http_server", addressPort, s.Ppid, s.ProcessIndex}, netNs)
	err := cmd.Start()
	s.Log(cmd)
	if err != nil {
		s.Log("Failed to start http server: " + fmt.Sprint(err))
		return
	}
	running <- struct{}{}
	<-done
	cmd.Process.Kill()
}

func (s *HstSuite) StartWget(finished chan error, server_ip, port, query, netNs string) {
	defer func() {
		finished <- errors.New("wget error")
	}()

	cmd := newCommand([]string{"wget", "--timeout=10", "--no-proxy", "--tries=5", "-O", "/dev/null", server_ip + ":" + port + "/" + query},
		netNs)
	s.Log(cmd)
	o, err := cmd.CombinedOutput()
	if err != nil {
		finished <- fmt.Errorf("wget error: '%v\n\n%s'", err, o)
		return
	} else if !strings.Contains(string(o), "200 OK") {
		finished <- fmt.Errorf("wget error: response not 200 OK")
		return
	}
	finished <- nil
}

/*
runBenchmark creates Gomega's experiment with the passed-in name and samples the passed-in callback repeatedly (samplesNum times),
passing in suite context, experiment and your data.

You can also instruct runBenchmark to run with multiple concurrent workers.
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
