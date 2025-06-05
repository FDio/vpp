package hst_common

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var IsCoverage = flag.Bool("coverage", false, "use coverage run config")
var IsPersistent = flag.Bool("persist", false, "persists topology config")
var IsVerbose = flag.Bool("verbose", false, "verbose test output")
var SudoUser = flag.String("sudo_user", "root", "what user ran hs-test with sudo")
var ParallelTotal = flag.Lookup("ginkgo.parallel.total")
var IsVppDebug = flag.Bool("debug", false, "attach gdb to vpp")
var DryRun = flag.Bool("dryrun", false, "set up containers but don't run tests")
var Timeout = flag.Int("timeout", 5, "test timeout override (in minutes)")
var PerfTesting = flag.Bool("perf", false, "perf test flag")
var NumaAwareCpuAlloc bool
var TestTimeout time.Duration
var RunningInCi bool

const (
	LogDir    string = "/tmp/hs-test/"
	VolumeDir string = "/vol"
)

type HstCommon struct {
	Ppid         string
	ProcessIndex string
	Logger       *log.Logger
	LogFile      *os.File
}

func (s *HstCommon) Skip(args string) {
	Skip(args)
}

func (s *HstCommon) SetupTest() {
	TestCounterFunc()
	s.Log("[* TEST SETUP]")
}

func (s *HstCommon) SetupSuite() {
	s.CreateLogger()
	s.Log("[* SUITE SETUP]")
	s.Ppid = fmt.Sprint(os.Getppid())
	// remove last number so we have space to prepend a process index (interfaces have a char limit)
	s.Ppid = s.Ppid[:len(s.Ppid)-1]
	s.ProcessIndex = fmt.Sprint(GinkgoParallelProcess())
}

func (s *HstCommon) TeardownTest() {
	if *IsPersistent || *DryRun {
		s.Skip("Skipping test teardown")
	}
	s.Log("[* TEST TEARDOWN]")
}

func (s *HstCommon) TeardownSuite() {
	if *IsPersistent || *DryRun {
		s.Skip("Skipping suite teardown")
	}
	s.Log("[* SUITE TEARDOWN]")
}

func (s *HstCommon) GetCurrentSuiteName() string {
	return CurrentSpecReport().ContainerHierarchyTexts[0]
}

func (s *HstCommon) CreateLogger() {
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
func (s *HstCommon) Log(log any, arg ...any) {
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

func (s *HstCommon) AssertNil(object interface{}, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, object).To(BeNil(), msgAndArgs...)
}

func (s *HstCommon) AssertNotNil(object interface{}, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, object).ToNot(BeNil(), msgAndArgs...)
}

func (s *HstCommon) AssertEqual(expected, actual interface{}, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, actual).To(Equal(expected), msgAndArgs...)
}

func (s *HstCommon) AssertNotEqual(expected, actual interface{}, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, actual).ToNot(Equal(expected), msgAndArgs...)
}

func (s *HstCommon) AssertContains(testString, contains interface{}, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, strings.ToLower(fmt.Sprint(testString))).To(ContainSubstring(strings.ToLower(fmt.Sprint(contains))), msgAndArgs...)
}

func (s *HstCommon) AssertNotContains(testString, contains interface{}, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, strings.ToLower(fmt.Sprint(testString))).ToNot(ContainSubstring(strings.ToLower(fmt.Sprint(contains))), msgAndArgs...)
}

func (s *HstCommon) AssertEmpty(object interface{}, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, object).To(BeEmpty(), msgAndArgs...)
}

func (s *HstCommon) AssertNotEmpty(object interface{}, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, object).ToNot(BeEmpty(), msgAndArgs...)
}

func (s *HstCommon) AssertMatchError(actual, expected error, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, actual).To(MatchError(expected), msgAndArgs...)
}

func (s *HstCommon) AssertGreaterThan(actual, expected interface{}, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, actual).Should(BeNumerically(">=", expected), msgAndArgs...)
}

func (s *HstCommon) AssertEqualWithinThreshold(actual, expected, threshold interface{}, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, actual).Should(BeNumerically("~", expected, threshold), msgAndArgs...)
}

func (s *HstCommon) AssertTimeEqualWithinThreshold(actual, expected time.Time, threshold time.Duration, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, actual).Should(BeTemporally("~", expected, threshold), msgAndArgs...)
}

func (s *HstCommon) AssertHttpStatus(resp *http.Response, expectedStatus int, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, resp).To(HaveHTTPStatus(expectedStatus), msgAndArgs...)
}

func (s *HstCommon) AssertHttpHeaderWithValue(resp *http.Response, key string, value interface{}, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, resp).To(HaveHTTPHeaderWithValue(key, value), msgAndArgs...)
}

func (s *HstCommon) AssertHttpHeaderNotPresent(resp *http.Response, key string, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, resp.Header.Get(key)).To(BeEmpty(), msgAndArgs...)
}

func (s *HstCommon) AssertHttpContentLength(resp *http.Response, expectedContentLen int64, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, resp).To(HaveHTTPHeaderWithValue("Content-Length", strconv.FormatInt(expectedContentLen, 10)), msgAndArgs...)
}

func (s *HstCommon) AssertHttpBody(resp *http.Response, expectedBody string, msgAndArgs ...interface{}) {
	ExpectWithOffset(2, resp).To(HaveHTTPBody(expectedBody), msgAndArgs...)
}

// Coverage builds take longer to finish -> assert timeout is set to 'TestTimeout - 30 seconds' to let the test finish properly
func (s *HstCommon) AssertChannelClosed(timeout time.Duration, channel chan error) {
	if *IsCoverage && timeout > time.Second*30 {
		timeout = TestTimeout - time.Second*30
		s.Log("Coverage build, assert timeout is set to %s", timeout.String())
	}
	EventuallyWithOffset(2, channel).WithTimeout(timeout).Should(BeClosed())
}

// Pass the parsed result struct and the minimum amount of data transferred in MB.
// Won't do anything when testing a coverage build.
func (s *HstCommon) AssertIperfMinTransfer(result IPerfResult, minTransferred int) {
	if *IsCoverage {
		s.Log("Coverage build; not asserting")
		return
	}
	if result.Start.Details.Protocol == "TCP" {
		s.AssertGreaterThan(result.End.TcpReceived.MBytes, minTransferred)
	} else {
		s.AssertGreaterThan(result.End.Udp.MBytes, minTransferred)
	}
}
