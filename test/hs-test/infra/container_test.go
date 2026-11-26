package hst

import (
	"archive/tar"
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"path"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/docker/docker/client"
	"github.com/docker/docker/errdefs"
	"github.com/docker/docker/pkg/stdcopy"
)

type dockerArchiveTransport func(*http.Request) (*http.Response, error)

func (transport dockerArchiveTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return transport(req)
}

func newArchiveTestContainer(t *testing.T, dest, content string, mode int64, status int, response string) *Container {
	t.Helper()
	requests := 0
	start := time.Now().Truncate(time.Second)
	transport := dockerArchiveTransport(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.Method != http.MethodPut || !strings.HasSuffix(req.URL.Path, "/containers/hst/archive") ||
			req.URL.Query().Get("path") != path.Dir(dest) {
			t.Fatalf("unexpected Docker request: %s %s", req.Method, req.URL)
		}
		defer req.Body.Close()
		reader := tar.NewReader(req.Body)
		header, err := reader.Next()
		if err != nil {
			t.Fatal(err)
		}
		if header.Name != path.Base(dest) || header.Mode != mode {
			t.Errorf("archive entry is %q with mode %#o, want %q with mode %#o", header.Name, header.Mode, path.Base(dest), mode)
		}
		if header.ModTime.Before(start) || header.ModTime.After(time.Now()) {
			t.Errorf("archive entry has unexpected modification time %v", header.ModTime)
		}
		data, err := io.ReadAll(reader)
		if err != nil || string(data) != content {
			t.Errorf("archive content is %q (%v), want %q", data, err, content)
		}
		if _, err := reader.Next(); err != io.EOF {
			t.Errorf("expected end of archive, got %v", err)
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(response))}, nil
	})
	docker, err := client.NewClientWithOpts(client.WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		docker.Close()
		if requests != 1 {
			t.Errorf("got %d Docker requests, want 1", requests)
		}
	})
	return &Container{Name: "hst", Suite: &HstSuite{Docker: docker}, ctx: t.Context()}
}

func TestContainerCreateFile(t *testing.T) {
	const dest, content = "/etc/vpp/config", "file contents\n"

	t.Run("copy", func(t *testing.T) {
		c := newArchiveTestContainer(t, dest, content, 0644, http.StatusOK, "")
		if err := c.CreateFile(dest, content); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("copy error", func(t *testing.T) {
		c := newArchiveTestContainer(t, dest, content, 0644, http.StatusNotFound, `{"message":"destination missing"}`)
		if err := c.CreateFile(dest, content); !errdefs.IsNotFound(err) || !strings.Contains(err.Error(), "destination missing") {
			t.Errorf("CreateFile returned %v, want Docker's missing destination error", err)
		}
	})
}

func TestContainerExecCancellation(t *testing.T) {
	const createPath = "/containers/hst/exec"
	const startPath = "/exec/test-id/start"

	for _, test := range []struct {
		name   string
		path   string
		output string
		err    error
	}{
		{name: "create", path: createPath, err: context.Canceled},
		{name: "attach upgrade", path: startPath, err: context.Canceled},
		{name: "cancel while reading output", path: startPath, output: "partial output\n"},
		{name: "deadline while reading output", path: startPath, output: "partial output\n", err: context.DeadlineExceeded},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(client.EnvOverrideCertPath, "")
			synctest.Test(t, func(t *testing.T) {
				requestReceived := make(chan struct{})
				connectionClosed := make(chan error, 1)
				dial := func(_ context.Context, _, _ string) (net.Conn, error) {
					conn, peer := net.Pipe()
					done := make(chan struct{})
					t.Cleanup(func() {
						peer.Close()
						<-done
					})
					go func() {
						defer close(done)
						defer peer.Close()
						reader := bufio.NewReader(peer)
						req, err := http.ReadRequest(reader)
						if err != nil {
							t.Error(err)
							return
						}
						if err := req.Body.Close(); err != nil {
							t.Error(err)
							return
						}
						switch {
						case strings.HasSuffix(req.URL.Path, test.path):
							if test.output != "" {
								const upgrade = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n"
								if _, err := io.WriteString(peer, upgrade); err != nil {
									t.Error(err)
									return
								}
								if _, err := io.WriteString(stdcopy.NewStdWriter(peer, stdcopy.Stdout), test.output); err != nil {
									t.Error(err)
									return
								}
							}
							close(requestReceived)
							_, err := reader.ReadByte()
							connectionClosed <- err
						case strings.HasSuffix(req.URL.Path, createPath):
							body := `{"Id":"test-id"}`
							response := http.Response{
								StatusCode:    http.StatusCreated,
								ProtoMajor:    1,
								ProtoMinor:    1,
								Close:         true,
								ContentLength: int64(len(body)),
								Body:          io.NopCloser(strings.NewReader(body)),
							}
							if err := response.Write(peer); err != nil {
								t.Error(err)
							}
						default:
							t.Errorf("unexpected Docker request: %s %s", req.Method, req.URL.Path)
						}
					}()
					return conn, nil
				}

				docker, err := client.NewClientWithOpts(client.WithDialContext(dial))
				if err != nil {
					t.Fatal(err)
				}
				defer docker.Close()
				container := Container{Name: "hst", Suite: &HstSuite{Docker: docker}}
				var ctx context.Context
				var cancel context.CancelFunc
				if test.err == context.DeadlineExceeded {
					ctx, cancel = context.WithTimeout(t.Context(), time.Second)
				} else {
					ctx, cancel = context.WithCancel(t.Context())
				}
				defer cancel()
				type execResult struct {
					output string
					err    error
				}
				result := make(chan execResult, 1)
				go func() {
					output, err := container.ExecContext(ctx, false, "true")
					result <- execResult{output, err}
				}()

				select {
				case <-requestReceived:
				case got := <-result:
					t.Fatalf("exec returned before reaching %s: %v", test.path, got.err)
				case <-time.After(5 * time.Second):
					t.Fatalf("Docker never received %s", test.path)
				}
				if test.err != context.DeadlineExceeded {
					cancel()
				}
				select {
				case got := <-result:
					if !errors.Is(got.err, test.err) || got.output != test.output {
						t.Errorf("exec returned (%q, %v), expected (%q, %v)", got.output, got.err, test.output, test.err)
					}
				case <-time.After(5 * time.Second):
					t.Error("exec did not return after cancellation")
				}
				select {
				case err := <-connectionClosed:
					if !errors.Is(err, io.EOF) {
						t.Errorf("Docker peer read returned %v, expected EOF", err)
					}
				case <-time.After(5 * time.Second):
					t.Error("Docker connection stayed open after cancellation")
				}
			})
		})
	}
}
