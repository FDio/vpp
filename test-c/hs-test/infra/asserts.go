package hst

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/gomega"
)

func (s *HstSuite) AssertNil(object any, msgAndArgs ...any) {
	ExpectWithOffset(2, object).To(BeNil(), msgAndArgs...)
}

func (s *HstSuite) AssertNotNil(object any, msgAndArgs ...any) {
	ExpectWithOffset(2, object).ToNot(BeNil(), msgAndArgs...)
}

func (s *HstSuite) AssertEqual(expected, actual any, msgAndArgs ...any) {
	ExpectWithOffset(2, actual).To(Equal(expected), msgAndArgs...)
}

func (s *HstSuite) AssertNotEqual(expected, actual any, msgAndArgs ...any) {
	ExpectWithOffset(2, actual).ToNot(Equal(expected), msgAndArgs...)
}

func (s *HstSuite) AssertContains(testString, contains any, msgAndArgs ...any) {
	ExpectWithOffset(2, strings.ToLower(fmt.Sprint(testString))).To(ContainSubstring(strings.ToLower(fmt.Sprint(contains))), msgAndArgs...)
}

func (s *HstSuite) AssertNotContains(testString, contains any, msgAndArgs ...any) {
	ExpectWithOffset(2, strings.ToLower(fmt.Sprint(testString))).ToNot(ContainSubstring(strings.ToLower(fmt.Sprint(contains))), msgAndArgs...)
}

func (s *HstSuite) AssertEmpty(object any, msgAndArgs ...any) {
	ExpectWithOffset(2, object).To(BeEmpty(), msgAndArgs...)
}

func (s *HstSuite) AssertNotEmpty(object any, msgAndArgs ...any) {
	ExpectWithOffset(2, object).ToNot(BeEmpty(), msgAndArgs...)
}

func (s *HstSuite) AssertMatchError(actual, expected error, msgAndArgs ...any) {
	ExpectWithOffset(2, actual).To(MatchError(expected), msgAndArgs...)
}

func (s *HstSuite) AssertGreaterEqual(actual, expected any, msgAndArgs ...any) {
	ExpectWithOffset(2, actual).Should(BeNumerically(">=", expected), msgAndArgs...)
}

func (s *HstSuite) AssertGreaterThan(actual, expected any, msgAndArgs ...any) {
	ExpectWithOffset(2, actual).Should(BeNumerically(">", expected), msgAndArgs...)
}

func (s *HstSuite) AssertLessEqual(actual, expected any, msgAndArgs ...any) {
	ExpectWithOffset(2, actual).Should(BeNumerically("<=", expected), msgAndArgs...)
}

func (s *HstSuite) AssertLessThan(actual, expected any, msgAndArgs ...any) {
	ExpectWithOffset(2, actual).Should(BeNumerically("<", expected), msgAndArgs...)
}

func (s *HstSuite) AssertEqualWithinThreshold(actual, expected, threshold any, msgAndArgs ...any) {
	ExpectWithOffset(2, actual).Should(BeNumerically("~", expected, threshold), msgAndArgs...)
}

func (s *HstSuite) AssertTimeEqualWithinThreshold(actual, expected time.Time, threshold time.Duration, msgAndArgs ...any) {
	ExpectWithOffset(2, actual).Should(BeTemporally("~", expected, threshold), msgAndArgs...)
}

func (s *HstSuite) AssertHttpStatus(resp *http.Response, expectedStatus int, msgAndArgs ...any) {
	ExpectWithOffset(2, resp).To(HaveHTTPStatus(expectedStatus), msgAndArgs...)
}

func (s *HstSuite) AssertHttpHeaderWithValue(resp *http.Response, key string, value any, msgAndArgs ...any) {
	ExpectWithOffset(2, resp).To(HaveHTTPHeaderWithValue(key, value), msgAndArgs...)
}

func (s *HstSuite) AssertHttpHeaderNotPresent(resp *http.Response, key string, msgAndArgs ...any) {
	ExpectWithOffset(2, resp.Header.Get(key)).To(BeEmpty(), msgAndArgs...)
}

func (s *HstSuite) AssertHttpContentLength(resp *http.Response, expectedContentLen int64, msgAndArgs ...any) {
	ExpectWithOffset(2, resp).To(HaveHTTPHeaderWithValue("Content-Length", strconv.FormatInt(expectedContentLen, 10)), msgAndArgs...)
}

func (s *HstSuite) AssertHttpBody(resp *http.Response, expectedBody string, msgAndArgs ...any) {
	ExpectWithOffset(2, resp).To(HaveHTTPBody(expectedBody), msgAndArgs...)
}

// Coverage builds take longer to finish -> assert timeout is set to 'TestTimeout - 30 seconds' to let the test finish properly
func (s *HstSuite) AssertChannelClosed(timeout time.Duration, channel chan error) {
	if *IsCoverage && timeout > time.Second*30 {
		timeout = TestTimeout - time.Second*30
		s.Log("Coverage build, assert timeout is set to %s", timeout.String())
	}
	EventuallyWithOffset(2, channel).WithTimeout(timeout).Should(BeClosed())
}
