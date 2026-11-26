package hst

import (
	"archive/tar"
	"bufio"
	"context"
	"errors"
	"fmt"
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

type dockerTestTransport func(*http.Request) (*http.Response, error)

func (transport dockerTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return transport(req)
}

func newArchiveTestContainer(t *testing.T, dest, content string, mode int64, status int, response string) *Container {
	t.Helper()
	requests := 0
	start := time.Now().Truncate(time.Second)
	transport := dockerTestTransport(func(req *http.Request) (*http.Response, error) {
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

func TestContainerStart(t *testing.T) {
	const (
		apiVersion = "1.47"
		created    = `{"State":{"Status":"created"}}`
		restarting = `{"State":{"Status":"restarting","Running":true,"Restarting":true}}`
		running    = `{"State":{"Status":"running","Running":true}}`
		exited     = `{"State":{"Status":"exited","ExitCode":7}}`
	)
	for _, test := range []struct {
		name          string
		foreground    bool
		states        []string
		startStatus   int
		inspectStatus int
		blockInspect  bool
		pending       bool
		elapsed       time.Duration
		wantError     []string
	}{
		{name: "running immediately", states: []string{running}},
		{name: "pending then running", states: []string{created, restarting, running}, elapsed: 2 * containerStartupPoll},
		{name: "early exit", states: []string{exited}, wantError: []string{`state="exited"`, "exit code=7"}},
		{name: "foreground exit", foreground: true, states: []string{exited}},
		{name: "Docker state error", states: []string{`{"State":{"Status":"created","ExitCode":128,"Error":"runtime failure"}}`},
			wantError: []string{`state="created"`, "exit code=128", `Docker error="runtime failure"`}},
		{name: "startup timeout", states: []string{created}, pending: true, elapsed: containerStartupTimeout,
			wantError: []string{`state="created"`, "context deadline exceeded"}},
		{name: "blocked inspection", blockInspect: true, elapsed: containerStartupTimeout,
			wantError: []string{"Docker inspect failed", "context deadline exceeded", "state unavailable"}},
		{name: "missing container", inspectStatus: http.StatusNotFound, wantError: []string{"Docker inspect failed", "No such container", "state unavailable"}},
		{name: "inspect error", inspectStatus: http.StatusInternalServerError, wantError: []string{"Docker inspect failed", "daemon unavailable"}},
		{name: "missing state", states: []string{`{}`}, wantError: []string{"Docker inspect response has no container state"}},
		{name: "start error", startStatus: http.StatusInternalServerError, states: []string{created},
			wantError: []string{"Docker start failed", "failed to start process", `state="created"`}},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var starts, inspects, logRequests int
				transport := dockerTestTransport(func(req *http.Request) (*http.Response, error) {
					var status int
					var body strings.Builder
					requestPath := strings.TrimPrefix(req.URL.Path, "/v"+apiVersion)
					switch req.Method + " " + requestPath {
					case "POST /containers/test-id/start":
						starts++
						status = http.StatusNoContent
						if test.startStatus != 0 {
							status = test.startStatus
							body.WriteString(`{"message":"failed to start process"}`)
						}
					case "GET /containers/test-id/json":
						inspects++
						if starts != 1 {
							t.Fatalf("inspected container after %d start requests", starts)
						}
						if test.blockInspect {
							<-req.Context().Done()
							return nil, req.Context().Err()
						}
						status = http.StatusOK
						switch test.inspectStatus {
						case http.StatusNotFound:
							status = test.inspectStatus
							body.WriteString(`{"message":"No such container: test-id"}`)
						case http.StatusInternalServerError:
							status = test.inspectStatus
							body.WriteString(`{"message":"daemon unavailable"}`)
						default:
							body.WriteString(test.states[min(inspects, len(test.states))-1])
						}
					case "GET /containers/test-id/logs":
						logRequests++
						query := req.URL.Query()
						if query.Get("tail") != "20" || query.Has("follow") {
							t.Errorf("unexpected log query: %s", query.Encode())
						}
						status = http.StatusOK
						fmt.Fprintln(stdcopy.NewStdWriter(&body, stdcopy.Stderr), "container diagnostic")
					default:
						t.Fatalf("unexpected Docker request: %s %s", req.Method, req.URL)
					}
					return &http.Response{
						StatusCode: status,
						Header:     http.Header{"Content-Type": {"application/json"}},
						Body:       io.NopCloser(strings.NewReader(body.String())),
					}, nil
				})
				docker, err := client.NewClientWithOpts(client.WithVersion(apiVersion), client.WithHTTPClient(&http.Client{Transport: transport}))
				if err != nil {
					t.Fatal(err)
				}
				defer docker.Close()
				c := &Container{Name: "hst", ID: "test-id", RunDetached: !test.foreground, Suite: &HstSuite{Docker: docker}, ctx: t.Context()}
				started := time.Now()
				err = c.Start()
				if elapsed := time.Since(started); elapsed != test.elapsed {
					t.Errorf("Start took %s, want %s", elapsed, test.elapsed)
				}
				if starts != 1 {
					t.Errorf("got %d start requests, want 1", starts)
				}
				if test.pending {
					if inspects < 2 {
						t.Errorf("got %d inspect requests, want repeated inspection while startup is pending", inspects)
					}
				} else if want := max(1, len(test.states)); inspects != want {
					t.Errorf("got %d inspect requests, want %d", inspects, want)
				}
				if len(test.wantError) == 0 {
					if err != nil || logRequests != 0 {
						t.Errorf("Start returned %v and requested logs %d times", err, logRequests)
					}
					return
				}
				if err == nil {
					t.Fatal("Start succeeded, want an error")
				}
				for _, part := range append(test.wantError, "hst (test-id)", "container diagnostic") {
					if !strings.Contains(err.Error(), part) {
						t.Errorf("Start error %q is missing %q", err, part)
					}
				}
				if logRequests != 1 {
					t.Errorf("got %d log requests, want 1", logRequests)
				}
				if test.inspectStatus == http.StatusNotFound && !errdefs.IsNotFound(err) {
					t.Errorf("Start error %v lost Docker's not-found classification", err)
				}
				if test.elapsed == containerStartupTimeout && !errors.Is(err, context.DeadlineExceeded) {
					t.Errorf("Start error %v lost the deadline-exceeded cause", err)
				}
			})
		})
	}
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
