package hst

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestPrintableHTTPContentType(t *testing.T) {
	tests := []struct {
		contentType string
		printable   bool
	}{
		{contentType: "text/plain; charset=utf-8", printable: true},
		{contentType: "text/html", printable: true},
		{contentType: "application/json", printable: true},
		{contentType: "application/problem+json", printable: true},
		{contentType: "application/xml", printable: true},
		{contentType: "application/soap+xml", printable: true},
		{contentType: "application/octet-stream", printable: false},
		{contentType: "image/jpeg", printable: false},
		{contentType: "", printable: false},
	}

	for _, test := range tests {
		t.Run(test.contentType, func(t *testing.T) {
			if actual := isPrintableHTTPContentType(test.contentType); actual != test.printable {
				t.Fatalf("isPrintableHTTPContentType(%q) = %t, expected %t",
					test.contentType, actual, test.printable)
			}
		})
	}
}

func TestDumpHttpRespSkipsBinaryBody(t *testing.T) {
	payload := "\x00binary payload\x00"
	resp := testHTTPResponse("application/octet-stream", payload)

	dump := DumpHttpResp(resp, true)
	if strings.Contains(dump, payload) {
		t.Fatal("binary response body was included in the dump")
	}
	if !strings.Contains(dump, "* binary response body, not printing!") {
		t.Fatal("binary response warning was not included in the dump")
	}
	assertResponseBody(t, resp, payload)
}

func TestDumpHttpRespIncludesTextBody(t *testing.T) {
	payload := "plain-text payload"
	resp := testHTTPResponse("text/plain; charset=utf-8", payload)

	dump := DumpHttpResp(resp, true)
	if !strings.Contains(dump, payload) {
		t.Fatal("text response body was not included in the dump")
	}
	assertResponseBody(t, resp, payload)
}

func TestDumpHttpRespWithoutBody(t *testing.T) {
	payload := "\x00binary payload\x00"
	resp := testHTTPResponse("application/octet-stream", payload)

	dump := DumpHttpResp(resp, false)
	if strings.Contains(dump, payload) || strings.Contains(dump, "binary response body") {
		t.Fatal("response body details were included when body dumping was disabled")
	}
	assertResponseBody(t, resp, payload)
}

func testHTTPResponse(contentType, payload string) *http.Response {
	return &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": []string{contentType}},
		Body:          io.NopCloser(strings.NewReader(payload)),
		ContentLength: int64(len(payload)),
	}
}

func assertResponseBody(t *testing.T, resp *http.Response, expected string) {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body failed: %v", err)
	}
	if string(body) != expected {
		t.Fatalf("response body = %q, expected %q", body, expected)
	}
}
