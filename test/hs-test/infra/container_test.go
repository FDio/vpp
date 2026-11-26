package hst

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

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
