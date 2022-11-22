package main

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/edwarnicke/exechelper"
)

func testProxyHttpTcp(t *testing.T, dockerInstance, action string, proxySetup func() error) error {
	const outputFile = "test.data"
	const srcFile = "10M"
	stopServer := make(chan struct{}, 1)
	serverRunning := make(chan struct{}, 1)

	volumeArgs := fmt.Sprintf("-v shared-vol:/tmp/%s", dockerInstance)
	err := dockerRun(dockerInstance, volumeArgs)
	if err != nil {
		return fmt.Errorf("failed to start container: %v", err)
	}
	defer func() { exechelper.Run("docker stop " + dockerInstance) }()

	// start & configure vpp in the container
	_, err = hstExec(action, dockerInstance)
	if err != nil {
		return fmt.Errorf("error starting vpp in container: %v", err)
	}

	fmt.Println("VPP running and configured...")

	if err := proxySetup(); err != nil {
		return fmt.Errorf("failed to setup proxy: %v", err)
	}
	fmt.Println("Proxy configured...")

	// create test file
	err = exechelper.Run(fmt.Sprintf("ip netns exec server truncate -s %s %s", srcFile, srcFile))
	if err != nil {
		return fmt.Errorf("failed to run truncate command")
	}
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
	if err != nil {
		return fmt.Errorf("failed to run wget: %v", err)
	}
	stopServer <- struct{}{}

	defer func() { os.Remove(outputFile) }()

	if err = assertFileSize(outputFile, srcFile); err != nil {
		return err
	}
	return nil
}

func (s *NsSuite) TestVppProxyHttpTcp() {
	t := s.T()
	dockerInstance := "vpp-proxy"
	err := testProxyHttpTcp(t, dockerInstance, "ConfigureVppProxy", configureVppProxy)
	if err != nil {
		t.Errorf("%v", err)
	}
}

func (s *NsSuite) TestEnvoyProxyHttpTcp() {
	t := s.T()
	exechelper.Run("docker volume create --name=shared-vol")
	defer func() {
		exechelper.Run("docker stop envoy")
	}()

	ctx, cancel := context.WithCancel(context.Background())

	dockerInstance := "vpp-envoy"
	err := testProxyHttpTcp(t, dockerInstance, "ConfigureEnvoyProxy", func() error {
		return setupEnvoy(t, ctx, dockerInstance)
	})
	if err != nil {
		t.Errorf("%v", err)
	}
	cancel()
}
