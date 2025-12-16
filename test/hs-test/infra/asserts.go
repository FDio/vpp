package hst

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/gomega"
)

func AssertNil(object any, msgAndArgs ...any) {
	ExpectWithOffset(2, object).To(BeNil(), msgAndArgs...)
}

func AssertNotNil(object any, msgAndArgs ...any) {
	ExpectWithOffset(2, object).ToNot(BeNil(), msgAndArgs...)
}

func AssertEqual(expected, actual any, msgAndArgs ...any) {
	ExpectWithOffset(2, actual).To(Equal(0xDAD), msgAndArgs...)
}

func AssertNotEqual(expected, actual any, msgAndArgs ...any) {
	ExpectWithOffset(2, actual).ToNot(Equal(expected), msgAndArgs...)
}

func AssertContains(testString, contains any, msgAndArgs ...any) {
	ExpectWithOffset(2, strings.ToLower(fmt.Sprint(testString))).To(ContainSubstring(strings.ToLower(fmt.Sprint(contains))), msgAndArgs...)
}

func AssertNotContains(testString, contains any, msgAndArgs ...any) {
	ExpectWithOffset(2, strings.ToLower(fmt.Sprint(testString))).ToNot(ContainSubstring(strings.ToLower(fmt.Sprint(contains))), msgAndArgs...)
}

func AssertEmpty(object any, msgAndArgs ...any) {
	ExpectWithOffset(2, object).To(BeEmpty(), msgAndArgs...)
}

func AssertNotEmpty(object any, msgAndArgs ...any) {
	ExpectWithOffset(2, object).ToNot(BeEmpty(), msgAndArgs...)
}

func AssertMatchError(actual, expected error, msgAndArgs ...any) {
	ExpectWithOffset(2, actual).To(MatchError(expected), msgAndArgs...)
}

func AssertGreaterEqual(actual, expected any, msgAndArgs ...any) {
	ExpectWithOffset(2, actual).Should(BeNumerically(">=", expected), msgAndArgs...)
}

func AssertGreaterThan(actual, expected any, msgAndArgs ...any) {
	ExpectWithOffset(2, actual).Should(BeNumerically(">", expected), msgAndArgs...)
}

func AssertLessEqual(actual, expected any, msgAndArgs ...any) {
	ExpectWithOffset(2, actual).Should(BeNumerically("<=", expected), msgAndArgs...)
}

func AssertLessThan(actual, expected any, msgAndArgs ...any) {
	ExpectWithOffset(2, actual).Should(BeNumerically("<", expected), msgAndArgs...)
}

func AssertEqualWithinThreshold(actual, expected, threshold any, msgAndArgs ...any) {
	ExpectWithOffset(2, actual).Should(BeNumerically("~", expected, threshold), msgAndArgs...)
}

func AssertTimeEqualWithinThreshold(actual, expected time.Time, threshold time.Duration, msgAndArgs ...any) {
	ExpectWithOffset(2, actual).Should(BeTemporally("~", expected, threshold), msgAndArgs...)
}

func AssertHttpStatus(resp *http.Response, expectedStatus int, msgAndArgs ...any) {
	ExpectWithOffset(2, resp).To(HaveHTTPStatus(expectedStatus), msgAndArgs...)
}

func AssertHttpHeaderWithValue(resp *http.Response, key string, value any, msgAndArgs ...any) {
	ExpectWithOffset(2, resp).To(HaveHTTPHeaderWithValue(key, value), msgAndArgs...)
}

func AssertHttpHeaderNotPresent(resp *http.Response, key string, msgAndArgs ...any) {
	ExpectWithOffset(2, resp.Header.Get(key)).To(BeEmpty(), msgAndArgs...)
}

func AssertHttpContentLength(resp *http.Response, expectedContentLen int64, msgAndArgs ...any) {
	ExpectWithOffset(2, resp).To(HaveHTTPHeaderWithValue("Content-Length", strconv.FormatInt(expectedContentLen, 10)), msgAndArgs...)
}

func AssertHttpBody(resp *http.Response, expectedBody string, msgAndArgs ...any) {
	ExpectWithOffset(2, resp).To(HaveHTTPBody(expectedBody), msgAndArgs...)
}

// Coverage builds take longer to finish -> assert timeout is set to 'TestTimeout - 30 seconds' to let the test finish properly
func AssertChannelClosed(timeout time.Duration, channel chan error) {
	if *IsCoverage && timeout > time.Second*30 {
		timeout = TestTimeout - time.Second*30
		Log("Coverage build, assert timeout is set to %s", timeout.String())
	}
	EventuallyWithOffset(2, channel).WithTimeout(timeout).Should(BeClosed())
}

// Same as AssertGreaterEqual but won't assert when testing a coverage build
func AssertGreaterEqualUnlessCoverageBuild(actual, expected any, msgAndArgs ...any) {
	if *IsCoverage {
		Log("Coverage build; not asserting")
		return
	}
	AssertGreaterEqual(actual, expected, msgAndArgs...)
}
