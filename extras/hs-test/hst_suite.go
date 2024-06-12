package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"github.com/onsi/gomega/gmeasure"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/edwarnicke/exechelper"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gopkg.in/yaml.v3"
)

const (
	DEFAULT_NETWORK_NUM int = 1
)

var isPersistent = flag.Bool("persist", false, "persists topology config")
var isVerbose = flag.Bool("verbose", false, "verbose test output")
var isUnconfiguring = flag.Bool("unconfigure", false, "remove topology")
var isVppDebug = flag.Bool("debug", false, "attach gdb to vpp")
var nConfiguredCpus = flag.Int("cpus", 1, "number of CPUs assigned to vpp")
var vppSourceFileDir = flag.String("vppsrc", "", "vpp source file directory")

type HstSuite struct {
	containers        map[string]*Container
	startedContainers []*Container
	volumes           []string
	netConfigs        []NetConfig
	netInterfaces     map[string]*NetInterface
	ip4AddrAllocator  *Ip4AddressAllocator
	testIds           map[string]string
	cpuAllocator      *CpuAllocatorT
	cpuContexts       []*CpuContext
	cpuPerVpp         int
	ppid              string
	processIndex      string
	logger            *log.Logger
	logFile           *os.File
}

func (s *HstSuite) SetupSuite() {
	s.createLogger()
	s.log("Suite Setup")
	RegisterFailHandler(func(message string, callerSkip ...int) {
		s.hstFail()
		Fail(message, callerSkip...)
	})
	var err error
	s.ppid = fmt.Sprint(os.Getppid())
	// remove last number so we have space to prepend a process index (interfaces have a char limit)
	s.ppid = s.ppid[:len(s.ppid)-1]
	s.processIndex = fmt.Sprint(GinkgoParallelProcess())
	s.cpuAllocator, err = CpuAllocator()
	if err != nil {
		Fail("failed to init cpu allocator: " + fmt.Sprint(err))
	}
	s.cpuPerVpp = *nConfiguredCpus
}

func (s *HstSuite) AllocateCpus() []int {
	cpuCtx, err := s.cpuAllocator.Allocate(len(s.startedContainers), s.cpuPerVpp)
	s.assertNil(err)
	s.AddCpuContext(cpuCtx)
	return cpuCtx.cpus
}

func (s *HstSuite) AddCpuContext(cpuCtx *CpuContext) {
	s.cpuContexts = append(s.cpuContexts, cpuCtx)
}

func (s *HstSuite) TearDownSuite() {
	defer s.logFile.Close()
	s.log("Suite Teardown")
	s.unconfigureNetworkTopology()
}

func (s *HstSuite) TearDownTest() {
	s.log("Test Teardown")
	if *isPersistent {
		return
	}
	s.resetContainers()
	s.removeVolumes()
	s.ip4AddrAllocator.deleteIpAddresses()
}

func (s *HstSuite) skipIfUnconfiguring() {
	if *isUnconfiguring {
		s.skip("skipping to unconfigure")
	}
}

func (s *HstSuite) SetupTest() {
	s.log("Test Setup")
	s.startedContainers = s.startedContainers[:0]
	s.skipIfUnconfiguring()
	s.setupVolumes()
	s.setupContainers()
}

func (s *HstSuite) setupVolumes() {
	for _, volume := range s.volumes {
		cmd := "docker volume create --name=" + volume
		s.log(cmd)
		exechelper.Run(cmd)
	}
}

func (s *HstSuite) setupContainers() {
	for _, container := range s.containers {
		if !container.isOptional {
			container.run()
		}
	}
}

func (s *HstSuite) logVppInstance(container *Container, maxLines int) {
	if container.vppInstance == nil {
		return
	}

	logSource := container.getHostWorkDir() + defaultLogFilePath
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

	s.log("vvvvvvvvvvvvvvv " + container.name + " [VPP instance]:")
	for _, line := range lines {
		s.log(line)
	}
	s.log("^^^^^^^^^^^^^^^\n\n")
}

func (s *HstSuite) hstFail() {
	for _, container := range s.startedContainers {
		out, err := container.log(20)
		if err != nil {
			s.log("An error occured while obtaining '" + container.name + "' container logs: " + fmt.Sprint(err))
			s.log("The container might not be running - check logs in " + container.getLogDirPath())
			continue
		}
		s.log("\nvvvvvvvvvvvvvvv " +
			container.name + ":\n" +
			out +
			"^^^^^^^^^^^^^^^\n\n")
		s.logVppInstance(container, 20)
	}
}

func (s *HstSuite) assertNil(object interface{}, msgAndArgs ...interface{}) {
	Expect(object).To(BeNil(), msgAndArgs...)
}

func (s *HstSuite) assertNotNil(object interface{}, msgAndArgs ...interface{}) {
	Expect(object).ToNot(BeNil(), msgAndArgs...)
}

func (s *HstSuite) assertEqual(expected, actual interface{}, msgAndArgs ...interface{}) {
	Expect(actual).To(Equal(expected), msgAndArgs...)
}

func (s *HstSuite) assertNotEqual(expected, actual interface{}, msgAndArgs ...interface{}) {
	Expect(actual).ToNot(Equal(expected), msgAndArgs...)
}

func (s *HstSuite) assertContains(testString, contains interface{}, msgAndArgs ...interface{}) {
	Expect(testString).To(ContainSubstring(fmt.Sprint(contains)), msgAndArgs...)
}

func (s *HstSuite) assertNotContains(testString, contains interface{}, msgAndArgs ...interface{}) {
	Expect(testString).ToNot(ContainSubstring(fmt.Sprint(contains)), msgAndArgs...)
}

func (s *HstSuite) assertNotEmpty(object interface{}, msgAndArgs ...interface{}) {
	Expect(object).ToNot(BeEmpty(), msgAndArgs...)
}

func (s *HstSuite) createLogger() {
	suiteName := s.getCurrentSuiteName()
	var err error
	s.logFile, err = os.Create("summary/" + suiteName + ".log")
	if err != nil {
		Fail("Unable to create log file.")
	}
	s.logger = log.New(io.Writer(s.logFile), "", log.LstdFlags)
}

// Logs to files by default, logs to stdout when VERBOSE=true with GinkgoWriter
// to keep console tidy
func (s *HstSuite) log(arg any) {
	logs := strings.Split(fmt.Sprint(arg), "\n")
	for _, line := range logs {
		s.logger.Println(line)
	}
	if *isVerbose {
		GinkgoWriter.Println(arg)
	}
}

func (s *HstSuite) skip(args string) {
	Skip(args)
}

func (s *HstSuite) SkipIfMultiWorker(args ...any) {
	if *nConfiguredCpus > 1 {
		s.skip("test case not supported with multiple vpp workers")
	}
}

func (s *HstSuite) SkipUnlessExtendedTestsBuilt() {
	imageName := "hs-test/nginx-http3"

	cmd := exec.Command("docker", "images", imageName)
	byteOutput, err := cmd.CombinedOutput()
	if err != nil {
		s.log("error while searching for docker image")
		return
	}
	if !strings.Contains(string(byteOutput), imageName) {
		s.skip("extended tests not built")
	}
}

func (s *HstSuite) resetContainers() {
	for _, container := range s.startedContainers {
		container.stop()
		exechelper.Run("docker rm " + container.name)
	}
}

func (s *HstSuite) removeVolumes() {
	for _, volumeName := range s.volumes {
		cmd := "docker volume rm " + volumeName
		exechelper.Run(cmd)
		os.RemoveAll(volumeName)
	}
}

func (s *HstSuite) getNetNamespaceByName(name string) string {
	return s.processIndex + name + s.ppid
}

func (s *HstSuite) getInterfaceByName(name string) *NetInterface {
	return s.netInterfaces[s.processIndex+name+s.ppid]
}

func (s *HstSuite) getContainerByName(name string) *Container {
	return s.containers[s.processIndex+name+s.ppid]
}

/*
 * Create a copy and return its address, so that individial tests which call this
 * are not able to modify the original container and affect other tests by doing that
 */
func (s *HstSuite) getTransientContainerByName(name string) *Container {
	containerCopy := *s.containers[s.processIndex+name+s.ppid]
	return &containerCopy
}

func (s *HstSuite) loadContainerTopology(topologyName string) {
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
		workingVolumeDir := logDir + s.getCurrentTestName() + volumeDir
		volDirReplacer := strings.NewReplacer("$HST_VOLUME_DIR", workingVolumeDir)
		hostDir = volDirReplacer.Replace(hostDir)
		s.volumes = append(s.volumes, hostDir)
	}

	s.containers = make(map[string]*Container)
	for _, elem := range yamlTopo.Containers {
		newContainer, err := newContainer(s, elem)
		newContainer.suite = s
		newContainer.name = newContainer.suite.processIndex + newContainer.name + newContainer.suite.ppid
		if err != nil {
			Fail("container config error: " + fmt.Sprint(err))
		}
		s.containers[newContainer.name] = newContainer
	}
}

func (s *HstSuite) loadNetworkTopology(topologyName string) {
	data, err := os.ReadFile(networkTopologyDir + topologyName + ".yaml")
	if err != nil {
		Fail("read error: " + fmt.Sprint(err))
	}
	var yamlTopo YamlTopology
	err = yaml.Unmarshal(data, &yamlTopo)
	if err != nil {
		Fail("unmarshal error: " + fmt.Sprint(err))
	}

	s.ip4AddrAllocator = NewIp4AddressAllocator()
	s.netInterfaces = make(map[string]*NetInterface)

	for _, elem := range yamlTopo.Devices {
		if _, ok := elem["name"]; ok {
			elem["name"] = s.processIndex + elem["name"].(string) + s.ppid
		}

		if peer, ok := elem["peer"].(NetDevConfig); ok {
			if peer["name"].(string) != "" {
				peer["name"] = s.processIndex + peer["name"].(string) + s.ppid
			}
			if _, ok := peer["netns"]; ok {
				peer["netns"] = s.processIndex + peer["netns"].(string) + s.ppid
			}
		}

		if _, ok := elem["netns"]; ok {
			elem["netns"] = s.processIndex + elem["netns"].(string) + s.ppid
		}

		if _, ok := elem["interfaces"]; ok {
			interfaceCount := len(elem["interfaces"].([]interface{}))
			for i := 0; i < interfaceCount; i++ {
				elem["interfaces"].([]interface{})[i] = s.processIndex + elem["interfaces"].([]interface{})[i].(string) + s.ppid
			}
		}

		switch elem["type"].(string) {
		case NetNs:
			{
				if namespace, err := newNetNamespace(elem); err == nil {
					s.netConfigs = append(s.netConfigs, &namespace)
				} else {
					Fail("network config error: " + fmt.Sprint(err))
				}
			}
		case Veth, Tap:
			{
				if netIf, err := newNetworkInterface(elem, s.ip4AddrAllocator); err == nil {
					s.netConfigs = append(s.netConfigs, netIf)
					s.netInterfaces[netIf.Name()] = netIf
				} else {
					Fail("network config error: " + fmt.Sprint(err))
				}
			}
		case Bridge:
			{
				if bridge, err := newBridge(elem); err == nil {
					s.netConfigs = append(s.netConfigs, &bridge)
				} else {
					Fail("network config error: " + fmt.Sprint(err))
				}
			}
		}
	}
}

func (s *HstSuite) configureNetworkTopology(topologyName string) {
	s.loadNetworkTopology(topologyName)

	if *isUnconfiguring {
		return
	}

	for _, nc := range s.netConfigs {
		if err := nc.configure(); err != nil {
			Fail("Network config error: " + fmt.Sprint(err))
		}
	}
}

func (s *HstSuite) unconfigureNetworkTopology() {
	if *isPersistent {
		return
	}
	for _, nc := range s.netConfigs {
		nc.unconfigure()
	}
}

func (s *HstSuite) getTestId() string {
	testName := s.getCurrentTestName()

	if s.testIds == nil {
		s.testIds = map[string]string{}
	}

	if _, ok := s.testIds[testName]; !ok {
		s.testIds[testName] = time.Now().Format("2006-01-02_15-04-05")
	}

	return s.testIds[testName]
}

func (s *HstSuite) getCurrentTestName() string {
	return strings.Split(CurrentSpecReport().LeafNodeText, "/")[1]
}

func (s *HstSuite) getCurrentSuiteName() string {
	return CurrentSpecReport().ContainerHierarchyTexts[0]
}

// Returns last 3 digits of PID + Ginkgo process index as the 4th digit
func (s *HstSuite) getPortFromPpid() string {
	port := s.ppid
	for len(port) < 3 {
		port += "0"
	}
	return port[len(port)-3:] + s.processIndex
}

func (s *HstSuite) startServerApp(running chan error, done chan struct{}, env []string) {
	cmd := exec.Command("iperf3", "-4", "-s", "-p", s.getPortFromPpid())
	if env != nil {
		cmd.Env = env
	}
	s.log(cmd)
	err := cmd.Start()
	if err != nil {
		msg := fmt.Errorf("failed to start iperf server: %v", err)
		running <- msg
		return
	}
	running <- nil
	<-done
	cmd.Process.Kill()
}

func (s *HstSuite) startClientApp(ipAddress string, env []string, clnCh chan error, clnRes chan string) {
	defer func() {
		clnCh <- nil
	}()

	nTries := 0

	for {
		cmd := exec.Command("iperf3", "-c", ipAddress, "-u", "-l", "1460", "-b", "10g", "-p", s.getPortFromPpid())
		if env != nil {
			cmd.Env = env
		}
		s.log(cmd)
		o, err := cmd.CombinedOutput()
		if err != nil {
			if nTries > 5 {
				clnCh <- fmt.Errorf("failed to start client app '%s'.\n%s", err, o)
				return
			}
			time.Sleep(1 * time.Second)
			nTries++
			continue
		} else {
			clnRes <- fmt.Sprintf("Client output: %s", o)
		}
		break
	}
}

func (s *HstSuite) startHttpServer(running chan struct{}, done chan struct{}, addressPort, netNs string) {
	cmd := newCommand([]string{"./http_server", addressPort, s.ppid, s.processIndex}, netNs)
	err := cmd.Start()
	s.log(cmd)
	if err != nil {
		s.log("Failed to start http server: " + fmt.Sprint(err))
		return
	}
	running <- struct{}{}
	<-done
	cmd.Process.Kill()
}

func (s *HstSuite) startWget(finished chan error, server_ip, port, query, netNs string) {
	defer func() {
		finished <- errors.New("wget error")
	}()

	cmd := newCommand([]string{"wget", "--timeout=10", "--no-proxy", "--tries=5", "-O", "/dev/null", server_ip + ":" + port + "/" + query},
		netNs)
	s.log(cmd)
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
func (s *HstSuite) runBenchmark(name string, samplesNum, parallelNum int, callback func(s *HstSuite, e *gmeasure.Experiment, data interface{}), data interface{}) {
	experiment := gmeasure.NewExperiment(name)

	experiment.Sample(func(idx int) {
		defer GinkgoRecover()
		callback(s, experiment, data)
	}, gmeasure.SamplingConfig{N: samplesNum, NumParallel: parallelNum})
	AddReportEntry(experiment.Name, experiment)
}
