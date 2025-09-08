package kube_test

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/gomega"
)

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