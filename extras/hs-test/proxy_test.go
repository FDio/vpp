package main

import (
	"context"
	"fmt"
	"os"

	"github.com/edwarnicke/exechelper"
)

func testProxyHttpTcp(s *NsSuite, dockerInstance, action string, proxySetup func() error) error {
	const outputFile = "test.data"
	const srcFile = "10M"
	stopServer := make(chan struct{}, 1)
	serverRunning := make(chan struct{}, 1)

	volumeArgs := fmt.Sprintf("-v shared-vol:/tmp/%s", dockerInstance)
	s.assertNil(dockerRun(dockerInstance, volumeArgs), "failed to start container")
	defer func() { exechelper.Run("docker stop " + dockerInstance) }()

	// start & configure vpp in the container
	_, err := hstExec(action, dockerInstance)
	s.assertNil(err)

	fmt.Println("VPP running and configured...")

	s.assertNil(proxySetup(), "failed to setup proxy")
	fmt.Println("Proxy configured...")

	// create test file
	err = exechelper.Run(fmt.Sprintf("ip netns exec server truncate -s %s %s", srcFile, srcFile))
	s.assertNil(err, "failed to run truncate command")
	defer func() { os.Remove(srcFile) }()

	fmt.Println("Test file created...")

	go startHttpServer(serverRunning, stopServer, ":666", "server")
	// TODO better error handling and recovery
	<-serverRunning

	defer func(chan struct{}) {
		stopServer <- struct{}{}
	}(stopServer)

	fmt.Println("http server started...")

	c := fmt.Sprintf("ip netns exec client wget --retry-connrefused --retry-on-http-error=503 --tries=10 -O %s 10.0.0.2:555/%s", outputFile, srcFile)
	_, err = exechelper.CombinedOutput(c)
	s.assertNil(err, "failed to run wget")
	stopServer <- struct{}{}

	defer func() { os.Remove(outputFile) }()

	s.assertNil(assertFileSize(outputFile, srcFile))
	return nil
}

func setupEnvoy(ctx context.Context, dockerInstance string) error {
	errCh := startEnvoy(ctx, dockerInstance)
	select {
	case err := <-errCh:
		return err
	default:
	}

	go func(ctx context.Context, errCh <-chan error) {
		for {
			select {
			// handle cancel() call from outside to gracefully stop the routine
			case <-ctx.Done():
				return
			default:
				select {
				case err := <-errCh:
					fmt.Printf("error while running envoy: %v", err)
				default:
				}
			}
		}
	}(ctx, errCh)
	return nil
}

func (s *NsSuite) TestVppProxyHttpTcp() {
	dockerInstance := "vpp-proxy"
	err := testProxyHttpTcp(s, dockerInstance, "ConfigureVppProxy", configureVppProxy)
	s.assertNil(err)
}

func (s *NsSuite) TestEnvoyProxyHttpTcp() {
	exechelper.Run("docker volume create --name=shared-vol")
	defer func() {
		exechelper.Run("docker stop envoy")
	}()

	ctx, cancel := context.WithCancel(context.Background())

	dockerInstance := "vpp-envoy"
	err := testProxyHttpTcp(s, dockerInstance, "ConfigureEnvoyProxy", func() error {
		return setupEnvoy(ctx, dockerInstance)
	})
	s.assertNil(err)
	cancel()
}
