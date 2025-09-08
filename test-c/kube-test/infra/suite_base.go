package hst_kind

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var IsCoverage = flag.Bool("coverage", false, "use coverage run config")
var IsPersistent = flag.Bool("persist", false, "persists topology config")
var IsVerbose = flag.Bool("verbose", false, "verbose test output")
var WhoAmI = flag.String("whoami", "root", "what user ran kube-test")
var ParallelTotal = flag.Lookup("ginkgo.parallel.total")
var IsVppDebug = flag.Bool("debug", false, "attach gdb to vpp")
var DryRun = flag.Bool("dryrun", false, "set up containers but don't run tests")
var Timeout = flag.Int("timeout", 5, "test timeout override (in minutes)")
var PerfTesting = flag.Bool("perf", false, "perf test flag")
var NumaAwareCpuAlloc bool
var TestTimeout time.Duration
var RunningInCi bool

const (
	LogDir    string = "/tmp/kube-test/"
	VolumeDir string = "/vol"
)

type BaseSuite struct {
	Ppid         string
	ProcessIndex string
	Logger       *log.Logger
	LogFile      *os.File
}

func init() {
	cmd := exec.Command("mkdir", "-p", LogDir)
	if err := cmd.Run(); err != nil {
		panic(err)
	}
}

func (s *BaseSuite) Skip(args string) {
	Skip(args)
}

func (s *BaseSuite) SetupTest() {
	TestCounterFunc()
	s.Log("[* TEST SETUP]")
}

func (s *BaseSuite) SetupSuite() {
	s.CreateLogger()
	s.Log("[* SUITE SETUP]")
	s.Ppid = fmt.Sprint(os.Getppid())
	// remove last number so we have space to prepend a process index (interfaces have a char limit)
	s.Ppid = s.Ppid[:len(s.Ppid)-1]
	s.ProcessIndex = fmt.Sprint(GinkgoParallelProcess())
}

func (s *BaseSuite) TeardownTest() {
	if *IsPersistent || *DryRun {
		s.Skip("Skipping test teardown")
	}
	s.Log("[* TEST TEARDOWN]")
}

func (s *BaseSuite) TeardownSuite() {
	if *IsPersistent || *DryRun {
		s.Skip("Skipping suite teardown")
	}
	s.Log("[* SUITE TEARDOWN]")
}

func (s *BaseSuite) GetCurrentSuiteName() string {
	return CurrentSpecReport().ContainerHierarchyTexts[0]
}

func (s *BaseSuite) CreateLogger() {
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
func (s *BaseSuite) Log(log any, arg ...any) {
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

func (s *BaseSuite) AssertNil(object any, msgAndArgs ...any) {
	ExpectWithOffset(2, object).To(BeNil(), msgAndArgs...)
}

func (s *BaseSuite) AssertNotNil(object any, msgAndArgs ...any) {
	ExpectWithOffset(2, object).ToNot(BeNil(), msgAndArgs...)
}

func (s *BaseSuite) AssertEqual(expected, actual any, msgAndArgs ...any) {
	ExpectWithOffset(2, actual).To(Equal(expected), msgAndArgs...)
}

func (s *BaseSuite) AssertNotEqual(expected, actual any, msgAndArgs ...any) {
	ExpectWithOffset(2, actual).ToNot(Equal(expected), msgAndArgs...)
}

func (s *BaseSuite) AssertContains(testString, contains any, msgAndArgs ...any) {
	ExpectWithOffset(2, strings.ToLower(fmt.Sprint(testString))).To(ContainSubstring(strings.ToLower(fmt.Sprint(contains))), msgAndArgs...)
}

func (s *BaseSuite) AssertNotContains(testString, contains any, msgAndArgs ...any) {
	ExpectWithOffset(2, strings.ToLower(fmt.Sprint(testString))).ToNot(ContainSubstring(strings.ToLower(fmt.Sprint(contains))), msgAndArgs...)
}

func (s *BaseSuite) AssertEmpty(object any, msgAndArgs ...any) {
	ExpectWithOffset(2, object).To(BeEmpty(), msgAndArgs...)
}

func (s *BaseSuite) AssertNotEmpty(object any, msgAndArgs ...any) {
	ExpectWithOffset(2, object).ToNot(BeEmpty(), msgAndArgs...)
}

func (s *BaseSuite) AssertMatchError(actual, expected error, msgAndArgs ...any) {
	ExpectWithOffset(2, actual).To(MatchError(expected), msgAndArgs...)
}

func (s *BaseSuite) AssertGreaterEqual(actual, expected any, msgAndArgs ...any) {
	ExpectWithOffset(2, actual).Should(BeNumerically(">=", expected), msgAndArgs...)
}

func (s *BaseSuite) AssertGreaterThan(actual, expected any, msgAndArgs ...any) {
	ExpectWithOffset(2, actual).Should(BeNumerically(">", expected), msgAndArgs...)
}

func (s *BaseSuite) AssertLessEqual(actual, expected any, msgAndArgs ...any) {
	ExpectWithOffset(2, actual).Should(BeNumerically("<=", expected), msgAndArgs...)
}

func (s *BaseSuite) AssertLessThan(actual, expected any, msgAndArgs ...any) {
	ExpectWithOffset(2, actual).Should(BeNumerically("<", expected), msgAndArgs...)
}

func (s *BaseSuite) AssertEqualWithinThreshold(actual, expected, threshold any, msgAndArgs ...any) {
	ExpectWithOffset(2, actual).Should(BeNumerically("~", expected, threshold), msgAndArgs...)
}

func (s *BaseSuite) AssertTimeEqualWithinThreshold(actual, expected time.Time, threshold time.Duration, msgAndArgs ...any) {
	ExpectWithOffset(2, actual).Should(BeTemporally("~", expected, threshold), msgAndArgs...)
}

func (s *BaseSuite) AssertHttpStatus(resp *http.Response, expectedStatus int, msgAndArgs ...any) {
	ExpectWithOffset(2, resp).To(HaveHTTPStatus(expectedStatus), msgAndArgs...)
}

func (s *BaseSuite) AssertHttpHeaderWithValue(resp *http.Response, key string, value any, msgAndArgs ...any) {
	ExpectWithOffset(2, resp).To(HaveHTTPHeaderWithValue(key, value), msgAndArgs...)
}

func (s *BaseSuite) AssertHttpHeaderNotPresent(resp *http.Response, key string, msgAndArgs ...any) {
	ExpectWithOffset(2, resp.Header.Get(key)).To(BeEmpty(), msgAndArgs...)
}

func (s *BaseSuite) AssertHttpContentLength(resp *http.Response, expectedContentLen int64, msgAndArgs ...any) {
	ExpectWithOffset(2, resp).To(HaveHTTPHeaderWithValue("Content-Length", strconv.FormatInt(expectedContentLen, 10)), msgAndArgs...)
}

func (s *BaseSuite) AssertHttpBody(resp *http.Response, expectedBody string, msgAndArgs ...any) {
	ExpectWithOffset(2, resp).To(HaveHTTPBody(expectedBody), msgAndArgs...)
}

// Coverage builds take longer to finish -> assert timeout is set to 'TestTimeout - 30 seconds' to let the test finish properly
func (s *BaseSuite) AssertChannelClosed(timeout time.Duration, channel chan error) {
	if *IsCoverage && timeout > time.Second*30 {
		timeout = TestTimeout - time.Second*30
		s.Log("Coverage build, assert timeout is set to %s", timeout.String())
	}
	EventuallyWithOffset(2, channel).WithTimeout(timeout).Should(BeClosed())
}

// Pass the parsed result struct and the minimum amount of data transferred in MB.
// Won't do anything when testing a coverage build.
func (s *BaseSuite) AssertIperfMinTransfer(result IPerfResult, minTransferred int) {
	if *IsCoverage {
		s.Log("Coverage build; not asserting")
		return
	}
	if result.Start.Details.Protocol == "TCP" {
		s.AssertGreaterEqual(result.End.TcpReceived.MBytes, minTransferred)
	} else {
		s.AssertGreaterEqual(result.End.Udp.MBytes, minTransferred)
	}
}
